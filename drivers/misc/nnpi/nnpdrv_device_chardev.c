/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include "nnpdrv_device_chardev.h"
#include <uapi/misc/intel_nnpi.h>
#include "nnp_log.h"
#include "nnpdrv_cmd_chan.h"
#include "idr_allocator.h"
#include "inf_proc.h"
#include "nnpdrv_device_sysfs.h"
#include "utils.h"

static dev_t       s_devnum;
static struct cdev s_cdev;
static struct class *s_class;

#define NNPDRV_DEVICE_DEV_NAME "nnpi"

static inline int is_nnp_device_file(struct file *f);

static int nnpdrv_device_open(struct inode *inode, struct file *f)
{
	struct device_client_info *client;
	int ret;

	if (unlikely(!is_nnp_device_file(f)))
		return -EINVAL;

	client = kzalloc(sizeof(*client), GFP_KERNEL);
	if (unlikely(client == NULL))
		return -ENOMEM;

	ret = nnpdrv_device_list_get(iminor(inode), &client->nnpdev);
	if (unlikely(ret)) {
		kfree(client);
		return ret;
	}

	f->private_data = client;

	return 0;
}

static int nnpdrv_device_release(struct inode *inode, struct file *f)
{
	struct device_client_info *client = (struct device_client_info *)f->private_data;

	if (unlikely(!is_nnp_device_file(f)))
		return -EINVAL;

	kfree(client);
	f->private_data = NULL;

	return 0;
}

long create_channel(struct device_client_info *cinfo, void __user *arg)
{
	struct nnp_device *nnpdev = cinfo->nnpdev;
	struct ioctl_nnpi_create_channel req;
	struct nnpdrv_cmd_chan *chan;
	union h2c_channel_op msg;
	long ret;

	ret = copy_from_user(&req, arg, sizeof(req));
	if (unlikely(ret != 0))
		return -EIO;

	req.o_errno = 0;

	if (req.i_max_id < req.i_min_id)
		return -EINVAL;

	if (unlikely((req.i_max_id < 256 && !nnpdrv_device_active(nnpdev)) ||
	    !nnpdrv_device_driver_ready(nnpdev))) {
		req.o_errno = NNPER_DEVICE_NOT_READY;
		goto done;
	}

	if (NNP_VERSION_MAJOR(req.i_protocol_version) != NNP_VERSION_MAJOR(nnpdev->chan_protocol_version) ||
	    NNP_VERSION_MINOR(req.i_protocol_version) != NNP_VERSION_MINOR(nnpdev->chan_protocol_version)) {
		nnp_log_err(CREATE_COMMAND_LOG, "Error: Protocol version mismatch between UMD and card payload\n");
		nnp_log_err(CREATE_COMMAND_LOG, "UMD protocol version %d.%d.%d\n",
			    NNP_VERSION_MAJOR(req.i_protocol_version),
			    NNP_VERSION_MINOR(req.i_protocol_version),
			    NNP_VERSION_DOT(req.i_protocol_version));
		nnp_log_err(CREATE_COMMAND_LOG, "Card protocol version %d.%d.%d\n",
			    NNP_VERSION_MAJOR(nnpdev->chan_protocol_version),
			    NNP_VERSION_MINOR(nnpdev->chan_protocol_version),
			    NNP_VERSION_DOT(nnpdev->chan_protocol_version));
		req.o_errno = NNPER_VERSIONS_MISMATCH;
		goto done;
	}

	ret = nnpdrv_cmd_chan_create(nnpdev,
				     req.i_host_fd,
				     req.i_weight,
				     req.i_min_id,
				     req.i_max_id,
				     req.i_get_device_events,
				     &chan);
	if (unlikely(ret < 0))
		goto done;

	/*
	 * send the create request to card
	 */
	msg.value = 0;
	msg.opcode = NNP_IPC_H2C_OP_CHANNEL_OP;
	msg.protocol_id = chan->protocol_id;
	msg.uid = current_euid().val;
	msg.privileged = capable(CAP_SYS_ADMIN) ? 1 : 0;

	ret = nnpdrv_msg_scheduler_queue_add_msg(nnpdev->public_cmdq,
						 &msg.value,
						 1);

	if (unlikely(ret < 0)) {
		if (atomic_xchg(&chan->destroyed, 1) == 0)
			nnpdrv_cmd_chan_put(chan);
		goto done;
	}

	wait_event(nnpdev->waitq,
		   chan->event_msg.value != 0 ||
		   is_card_fatal_drv_event(chan->card_critical_error.event_code));
	if (unlikely(chan->event_msg.value == 0)) {
		req.o_errno = NNPER_DEVICE_ERROR;
		ret = 0;
		if (atomic_xchg(&chan->destroyed, 1) == 0)
			nnpdrv_cmd_chan_put(chan);
		goto done;
	} else if (chan->event_msg.event_code == NNP_IPC_CREATE_CHANNEL_FAILED) {
		req.o_errno = event_valToNNPErrno(chan->event_msg.event_val);
		ret = 0;
		if (atomic_xchg(&chan->destroyed, 1) == 0)
			nnpdrv_cmd_chan_put(chan);
		goto done;
	}

	req.o_channel_id = chan->protocol_id;

	/*
	 * Attach file descriptor to the channel object - if created
	 * successfully
	 */
	req.o_fd = nnpdrv_cmd_chan_create_file(chan);

	/* remove channel object if failed */
	if (req.o_fd < 0) {
		ret = req.o_fd;
		nnpdrv_cmd_chan_send_destroy(chan);
	}

done:
	if (unlikely(ret != 0))
		return ret;

	if (unlikely(copy_to_user(arg, &req, sizeof(req)) != 0))
		return -EIO;

	return ret;
}

long create_channel_data_ringbuf(struct device_client_info *cinfo, void __user *arg)
{
	struct nnp_device *nnpdev = cinfo->nnpdev;
	struct ioctl_nnpi_create_channel_data_ringbuf req;
	struct nnpdrv_cmd_chan *chan = NULL;
	struct inf_hostres *hostres_entry = NULL;
	struct nnpdrv_host_resource *hostres;
	union h2c_channel_data_ringbuf_op msg;
	struct inf_process_info *proc_info = NULL;
	dma_addr_t page_list;
	uint32_t total_chunks;
	int ret;

	ret = copy_from_user(&req, arg, sizeof(req));
	if (unlikely(ret != 0))
		return -EIO;

	req.o_errno = 0;

	chan = nnpdrv_device_find_channel(nnpdev, req.i_channel_id);
	if (unlikely(chan == NULL)) {
		nnp_log_err(CREATE_COMMAND_LOG, "channel not found\n");
		req.o_errno = NNPER_NO_SUCH_CHANNEL;
		goto Exit;
	}

	NNP_ASSERT(req.i_hostres_handle < INT_MAX);
	proc_info = chan->proc_info;
	hostres_entry = nnp_idr_get_object(&proc_info->objects_idr,
					   (int)req.i_hostres_handle,
					   inf_hostres_check_and_get);
	if (unlikely(hostres_entry == NULL)) {
		nnp_log_err(CREATE_COMMAND_LOG, "host resource not found\n");
		req.o_errno = NNPER_NO_SUCH_RESOURCE;
		goto Exit;
	}

	hostres = hostres_entry->hostres;

	if (!req.i_h2c) {
		// check host resource is output resource
		if (unlikely(!nnpdrv_hostres_is_output(hostres))) {
			nnp_log_err(CREATE_COMMAND_LOG, "Wrong direction\n");
			req.o_errno = NNPER_INCOMPATIBLE_RESOURCES;
			goto Exit;
		}
	} else {
		// check host resource is input resource
		if (unlikely(!nnpdrv_hostres_is_input(hostres))) {
			nnp_log_err(CREATE_COMMAND_LOG, "Wrong direction\n");
			req.o_errno = NNPER_INCOMPATIBLE_RESOURCES;
			goto Exit;
		}
	}

	ret = nnpdrv_hostres_map_device(hostres,
					nnpdev,
					false,
					&page_list,
					&total_chunks);
	if (unlikely(ret != 0)) {
		nnp_log_err(CREATE_COMMAND_LOG, "hostresource map failed with ret:%d\n", ret);
		ret = -EFAULT;
		goto Exit;
	}

	msg.opcode = NNP_IPC_H2C_OP_CHANNEL_RB_OP;
	msg.chan_id = chan->protocol_id;
	msg.h2c = req.i_h2c ? 1 : 0;
	msg.rb_id = req.i_id;
	msg.destroy = 0;
	msg.host_ptr = NNP_IPC_DMA_ADDR_TO_PFN(page_list);

	chan->event_msg.value = 0;

	ret = -EPIPE;
	if (likely(!is_card_fatal_drv_event(chan->card_critical_error.event_code)))
		ret = nnpdrv_msg_scheduler_queue_add_msg(nnpdev->public_cmdq,
							 &msg.value,
							 1);
	if (unlikely(ret < 0))
		goto Fail;

	wait_event(nnpdev->waitq,
		   chan->event_msg.value != 0 ||
		   is_card_fatal_drv_event(chan->card_critical_error.event_code));
	if (unlikely(chan->event_msg.value == 0)) {
		req.o_errno = NNPER_DEVICE_ERROR;
		ret = 0;
	} else if (unlikely(chan->event_msg.event_code == NNP_IPC_CHANNEL_SET_RB_FAILED)) {
		req.o_errno = event_valToNNPErrno(chan->event_msg.event_val);
		ret = 0;
	}

	if (likely(ret == 0 && req.o_errno == 0)) {
		ret = nnpdrv_cmd_chan_set_ringbuf(chan,
						  req.i_h2c,
						  req.i_id,
						  hostres);
	}

	if (likely(ret == 0 && req.o_errno == 0))
		goto Exit;

Fail:
	nnpdrv_hostres_unmap_device(hostres, chan->nnpdev);

Exit:
	if (hostres_entry)
		inf_hostres_put(hostres_entry);
	if (chan)
		nnpdrv_cmd_chan_put(chan);

	if (unlikely(ret != 0))
		return ret;

	if (unlikely(copy_to_user(arg, &req, sizeof(req)) != 0))
		return -EIO;

	return ret;
}

long destroy_channel_data_ringbuf(struct device_client_info *cinfo, void __user *arg)
{
	struct nnp_device *nnpdev = cinfo->nnpdev;
	struct ioctl_nnpi_destroy_channel_data_ringbuf req;
	struct nnpdrv_cmd_chan *chan;
	union h2c_channel_data_ringbuf_op msg;
	int ret;

	ret = copy_from_user(&req, arg, sizeof(req));
	if (unlikely(ret != 0))
		return -EIO;

	req.o_errno = 0;

	chan = nnpdrv_device_find_channel(nnpdev, req.i_channel_id);
	if (unlikely(chan == NULL)) {
		nnp_log_err(CREATE_COMMAND_LOG, "channel not found\n");
		req.o_errno = NNPER_NO_SUCH_CHANNEL;
		goto done;
	}

	msg.opcode = NNP_IPC_H2C_OP_CHANNEL_RB_OP;
	msg.chan_id = chan->protocol_id;
	msg.h2c = req.i_h2c ? 1 : 0;
	msg.rb_id = req.i_id;
	msg.destroy = 1;
	msg.host_ptr = 0;

	chan->event_msg.value = 0;

	ret = -EPIPE;
	if (likely(!is_card_fatal_drv_event(chan->card_critical_error.event_code)))
		ret = nnpdrv_msg_scheduler_queue_add_msg(nnpdev->public_cmdq,
							 &msg.value,
							 1);
	if (unlikely(ret < 0))
		goto put_chan;

	wait_event(nnpdev->waitq,
		   chan->event_msg.value != 0 ||
		   is_card_fatal_drv_event(chan->card_critical_error.event_code));
	if (unlikely(chan->event_msg.value == 0)) {
		req.o_errno = NNPER_DEVICE_ERROR;
		ret = 0;
	} else if (unlikely(chan->event_msg.event_code == NNP_IPC_CHANNEL_SET_RB_FAILED)) {
		req.o_errno = event_valToNNPErrno(chan->event_msg.event_val);
		ret = 0;
	}

	if (likely(ret == 0 && req.o_errno == 0)) {
		ret = nnpdrv_cmd_chan_set_ringbuf(chan,
						  req.i_h2c,
						  req.i_id,
						  NULL);
	}

put_chan:
	nnpdrv_cmd_chan_put(chan);
done:
	if (unlikely(ret != 0))
		return ret;

	if (unlikely(copy_to_user(arg, &req, sizeof(req)) != 0))
		return -EIO;

	return ret;
}

static long map_hostres(struct device_client_info *cinfo, void __user *arg)
{
	struct nnp_device *nnpdev = cinfo->nnpdev;
	struct ioctl_nnpi_channel_map_hostres req;
	struct nnpdrv_cmd_chan *chan = NULL;
	struct inf_hostres *hostres_entry = NULL;
	struct nnpdrv_host_resource *hostres;
	union h2c_channel_hostres_op msg;
	struct inf_process_info *proc_info = NULL;
	struct chan_hostres_map *hostres_map = NULL;
	dma_addr_t page_list;
	uint32_t total_chunks;
	int map_protocol_id;
	long ret;

	ret = copy_from_user(&req, arg, sizeof(req));
	if (unlikely(ret != 0))
		return -EIO;

	req.o_errno = 0;

	chan = nnpdrv_device_find_channel(nnpdev, req.i_channel_id);
	if (unlikely(chan == NULL)) {
		nnp_log_err(CREATE_COMMAND_LOG, "channel not found\n");
		req.o_errno = NNPER_NO_SUCH_CHANNEL;
		goto Exit;
	}

	hostres_map = kzalloc(sizeof(*hostres_map), GFP_KERNEL);
	if (unlikely(hostres_map == NULL)) {
		nnp_log_err(CREATE_COMMAND_LOG, "no memory for hostres_map\n");
		ret = -ENOMEM;
		goto Exit;
	}

	map_protocol_id = -1;
	ret = ida_simple_get(&chan->hostres_map_ida,
			     0,
			     0xffff,
			     GFP_KERNEL);
	if (unlikely(ret < 0)) {
		ret = -ENOMEM;
		goto Fail;
	}
	map_protocol_id = (int)ret;

	NNP_ASSERT(req.i_hostres_handle < INT_MAX);
	proc_info = chan->proc_info;
	hostres_entry = nnp_idr_get_object(&proc_info->objects_idr,
					   (int)req.i_hostres_handle,
					   inf_hostres_check_and_get);
	if (unlikely(hostres_entry == NULL)) {
		nnp_log_err(CREATE_COMMAND_LOG, "host resource not found\n");
		req.o_errno = NNPER_NO_SUCH_RESOURCE;
		ret = 0;
		goto Fail;
	}

	hostres = hostres_entry->hostres;

	ret = nnpdrv_hostres_map_device(hostres,
					nnpdev,
					false,
					&page_list,
					&total_chunks);
	if (unlikely(ret != 0)) {
		nnp_log_err(CREATE_COMMAND_LOG, "hostresource map failed with ret:%ld\n", ret);
		ret = -EFAULT;
		goto Fail;
	}

	msg.opcode = NNP_IPC_H2C_OP_CHANNEL_HOSTRES_OP;
	msg.chan_id = chan->protocol_id;
	msg.hostres_id = (uint16_t) map_protocol_id;
	msg.unmap = 0;
	msg.host_ptr = NNP_IPC_DMA_ADDR_TO_PFN(page_list);

	hostres_map->event_msg.value = 0;
	hostres_map->protocol_id = (uint16_t) map_protocol_id;
	hostres_map->hostres = hostres;

	spin_lock(&chan->lock);
	hash_add(chan->hostres_hash,
		 &hostres_map->hash_node,
		 hostres_map->protocol_id);
	spin_unlock(&chan->lock);

	ret = -EPIPE;
	if (likely(!is_card_fatal_drv_event(chan->card_critical_error.event_code)))
		ret = msg_scheduler_queue_add_msg(chan->cmdq,
						  msg.value,
						  2);
	if (unlikely(ret < 0)) {
		req.o_errno = NNPER_DEVICE_ERROR;
		ret = 0;
	} else {
		wait_event(nnpdev->waitq,
			   hostres_map->event_msg.value != 0 ||
			   is_card_fatal_drv_event(chan->card_critical_error.event_code));
		if (unlikely(hostres_map->event_msg.value == 0)) {
			req.o_errno = NNPER_DEVICE_ERROR;
			ret = 0;
		} else if (unlikely(hostres_map->event_msg.event_code == NNP_IPC_CHANNEL_MAP_HOSTRES_FAILED)) {
			req.o_errno = event_valToNNPErrno(hostres_map->event_msg.event_val);
			ret = 0;
		}
	}

	inf_hostres_put(hostres_entry);

	if (likely(ret == 0 && req.o_errno == 0)) {
		const struct dma_map_ops *ops = get_dma_ops(nnpdev->hw_device_info->hw_device);

		if (dma_is_direct(ops))
			req.o_sync_needed = !dev_is_dma_coherent(nnpdev->hw_device_info->hw_device);
		else
			req.o_sync_needed = (ops->sync_sg_for_cpu != NULL);

		req.o_map_id = (uint16_t)map_protocol_id;
	} else {
		nnpdrv_chan_unmap_hostres(chan, (uint16_t)map_protocol_id);
	}

	goto Exit;

Fail:
	if (hostres_entry)
		inf_hostres_put(hostres_entry);
	if (-1 != map_protocol_id)
		ida_simple_remove(&chan->hostres_map_ida, map_protocol_id);
	kfree(hostres_map);

Exit:
	if (chan)
		nnpdrv_cmd_chan_put(chan);

	if (unlikely(ret != 0))
		return ret;

	ret = copy_to_user(arg, &req, sizeof(req));
	if (ret != 0)
		ret = -EIO;

	return ret;
}

static long unmap_hostres(struct device_client_info *cinfo, void __user *arg)
{
	struct nnp_device *nnpdev = cinfo->nnpdev;
	struct ioctl_nnpi_channel_unmap_hostres req;
	struct nnpdrv_cmd_chan *chan = NULL;
	struct chan_hostres_map *hostres_map;
	union h2c_channel_hostres_op msg;
	long ret;

	ret = copy_from_user(&req, arg, sizeof(req));
	if (unlikely(ret != 0))
		return -EIO;

	req.o_errno = 0;

	chan = nnpdrv_device_find_channel(nnpdev, req.i_channel_id);
	if (unlikely(chan == NULL)) {
		nnp_log_err(CREATE_COMMAND_LOG, "channel not found\n");
		req.o_errno = NNPER_NO_SUCH_CHANNEL;
		goto done;
	}

	hostres_map = nnpdrv_cmd_chan_find_hostres(chan, req.i_map_id);
	if (unlikely(hostres_map == NULL)) {
		nnp_log_err(CREATE_COMMAND_LOG, "host resource mapping not found\n");
		req.o_errno = NNPER_NO_SUCH_HOSTRES_MAP;
		goto done;
	}

	msg.opcode = NNP_IPC_H2C_OP_CHANNEL_HOSTRES_OP;
	msg.chan_id = chan->protocol_id;
	msg.hostres_id = req.i_map_id;
	msg.unmap = 1;

	ret = -EPIPE;
	if (likely(!is_card_fatal_drv_event(chan->card_critical_error.event_code)))
		ret = msg_scheduler_queue_add_msg(chan->cmdq,
						  msg.value,
						  2);

done:
	if (chan)
		nnpdrv_cmd_chan_put(chan);

	if (unlikely(ret != 0))
		return ret;

	if (unlikely(copy_to_user(arg, &req, sizeof(req)) != 0))
		return -EIO;

	return ret;
}

static long nnpdrv_device_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct device_client_info *client = (struct device_client_info *)f->private_data;

	if (!is_nnp_device_file(f))
		return -EINVAL;

	switch (cmd) {
	case IOCTL_NNPI_DEVICE_CREATE_CHANNEL:
		return create_channel(client, (void __user *)arg);
	case IOCTL_NNPI_DEVICE_CREATE_CHANNEL_RB:
		return create_channel_data_ringbuf(client, (void __user *)arg);
	case IOCTL_NNPI_DEVICE_DESTROY_CHANNEL_RB:
		return destroy_channel_data_ringbuf(client, (void __user *)arg);
	case IOCTL_NNPI_DEVICE_CHANNEL_MAP_HOSTRES:
		return map_hostres(client, (void __user *)arg);
	case IOCTL_NNPI_DEVICE_CHANNEL_UNMAP_HOSTRES:
		return unmap_hostres(client, (void __user *)arg);
	default:
		nnp_log_err(GENERAL_LOG, "Unsupported device IOCTL 0x%x\n", cmd);
	}

	return -EINVAL;
}

static const struct file_operations nnpdrv_device_fops = {
	.owner = THIS_MODULE,
	.open = nnpdrv_device_open,
	.release = nnpdrv_device_release,
	.unlocked_ioctl = nnpdrv_device_ioctl,
	.compat_ioctl = nnpdrv_device_ioctl
};

static inline int is_nnp_device_file(struct file *f)
{
	return (f->f_op == &nnpdrv_device_fops);
}

int nnpdev_device_chardev_create(struct nnp_device *nnpdev)
{
	int ret;

	if (unlikely(nnpdev == NULL))
		return -EINVAL;

	nnpdev->cdev = device_create(s_class,
				     NULL,
				     MKDEV(MAJOR(s_devnum), nnpdev->id),
				     nnpdev,
				     NNPI_DEVICE_DEV_FMT,
				     nnpdev->id);
	if (IS_ERR(nnpdev->cdev))
		return PTR_ERR(nnpdev->cdev);

	ret = nnpdrv_device_sysfs_init(nnpdev);
	if (ret) {
		device_destroy(s_class, MKDEV(MAJOR(s_devnum), nnpdev->id));
		return ret;
	}

	return 0;
}

void nnpdev_device_chardev_destroy(struct nnp_device *nnpdev)
{
	if (nnpdev) {
		nnpdrv_device_sysfs_fini(nnpdev);
		device_destroy(s_class, MKDEV(MAJOR(s_devnum), nnpdev->id));
	}
}

int nnpdev_device_chardev_init(void)
{
	int ret;

	ret = alloc_chrdev_region(&s_devnum, 0, NNP_MAX_DEVS, NNPDRV_DEVICE_DEV_NAME);
	if (ret < 0) {
		nnp_log_err(START_UP_LOG, "failed to allocate devnum %d\n", ret);
		return ret;
	}

	cdev_init(&s_cdev, &nnpdrv_device_fops);
	s_cdev.owner = THIS_MODULE;

	ret = cdev_add(&s_cdev, s_devnum, NNP_MAX_DEVS);
	if (ret < 0) {
		nnp_log_err(START_UP_LOG, "failed to add cdev %d\n", ret);
		unregister_chrdev_region(s_devnum, NNP_MAX_DEVS);
		return ret;
	}

	s_class = class_create(THIS_MODULE, NNPDRV_DEVICE_DEV_NAME);
	if (IS_ERR(s_class)) {
		ret = PTR_ERR(s_class);
		nnp_log_err(START_UP_LOG, "failed to register class %d\n", ret);
		cdev_del(&s_cdev);
		unregister_chrdev_region(s_devnum, NNP_MAX_DEVS);
		return ret;
	}

	return 0;
}

int nnpdev_device_chardev_cleanup(void)
{
	class_destroy(s_class);
	cdev_del(&s_cdev);
	unregister_chrdev_region(s_devnum, NNP_MAX_DEVS);
	return 0;
}

