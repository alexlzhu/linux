/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include <linux/module.h>
#include <linux/pci.h>
#include "nnpdrv_pcie.h"
#include "nnp_log.h"
#include "nnp_local.h"
#include "nnp_time.h"
#include "nnp_boot_defs.h"

struct hw_sim_descriptor {
	struct device *dev;
	struct nnp_hw_device_info device_info;
	int (*send_message_p)(enum QUEUE_TYPE queue, u64 data);
	void (*set_callback_p)(enum QUEUE_TYPE queue, int (*cb)(u64 data));
	void (*remove_callback_p)(enum QUEUE_TYPE queue);
	struct device* (*get_ep_device_p)(void);
	void (*set_doorbell_callback_p)(enum DOORBELL_TYPE db,
					void (*cb)(u32 value));
	u32 (*get_doorbell_value_p)(enum DOORBELL_TYPE db);
	void (*set_doorbell_value_p)(enum DOORBELL_TYPE db, u32 val);

	struct nnp_device *nnpdev;
} hw_sim_descriptor;

static struct nnpdrv_device_hw_callbacks *s_callbacks;

static int hw_sim_write_mesg(void *hw_handle, u64 *msg, u32 size, u64 *timed_wait)
{
	u32 i;
	u64 start = 0;

	if (timed_wait)
		start = nnp_time_us();

	for (i = 0; i < size; i++)
		hw_sim_descriptor.send_message_p(QUEUE_H2C, msg[i]);

	if (timed_wait)
		*timed_wait = nnp_time_us() - start;

	return 0;
}

static int hw_sim_cmdq_flush(void *hw_handle)
{
	return 0;
}

static u32 hw_sim_get_card_doorbell_value(void *hw_handle)
{
	return hw_sim_descriptor.get_doorbell_value_p(HOST_PCI);
}

static int hw_sim_set_host_doorbell_value(void *hw_handle, u32 value)
{
	hw_sim_descriptor.set_doorbell_value_p(PCI_HOST, value);
	return 0;
}

static int hw_sim_reset(void *hw_handle)
{
	return 0;
}


static struct nnpdrv_device_hw_ops s_hw_sim_ops = {
	.write_mesg = hw_sim_write_mesg,
	.flush_command_fifo = hw_sim_cmdq_flush,
	.get_card_doorbell_value = hw_sim_get_card_doorbell_value,
	.set_host_doorbell_value = hw_sim_set_host_doorbell_value,
	.reset = hw_sim_reset
};

static int c2h_cb(u64 data)
{
	s_callbacks->process_messages(hw_sim_descriptor.nnpdev, &data, 1);
	return 0;
};

static void doorbell_cb(u32 value)
{
	s_callbacks->card_doorbell_value_changed(hw_sim_descriptor.nnpdev,
						 value);
}

static ssize_t remove_store(struct device *dev, struct device_attribute *attr,
			    const char *buf, size_t count)
{
	unsigned long val;

	if (kstrtoul(buf, 0, &val) < 0)
		return -EINVAL;

	if (val && hw_sim_descriptor.nnpdev) {
		s_callbacks->destroy_nnp_device(hw_sim_descriptor.nnpdev, false);
		hw_sim_descriptor.nnpdev = NULL;
	}

	return count;
}

static struct device_attribute remove_attr = __ATTR(remove,
						    (S_IWUSR|S_IWGRP),
						    NULL, remove_store);

static ssize_t rescan_store(struct device *dev, struct device_attribute *attr,
			    const char *buf, size_t count)
{
	unsigned long val;

	if (kstrtoul(buf, 0, &val) < 0)
		return -EINVAL;

	if (val && !hw_sim_descriptor.nnpdev) {
		s_callbacks->create_nnp_device(&hw_sim_descriptor,
					       &hw_sim_descriptor.device_info,
					       &s_hw_sim_ops,
					       &hw_sim_descriptor.nnpdev);
	}

	return count;
}

static struct device_attribute rescan_attr = __ATTR(rescan,
						    (S_IWUSR|S_IWGRP),
						    NULL, rescan_store);

int nnpdrv_pci_init(struct nnpdrv_device_hw_callbacks *callbacks)
{
	int rc;

	hw_sim_descriptor.send_message_p = symbol_request(send_message);
	hw_sim_descriptor.set_callback_p = symbol_request(set_callback);
	hw_sim_descriptor.remove_callback_p = symbol_request(remove_callback);
	hw_sim_descriptor.get_ep_device_p = symbol_request(get_ep_device);
	hw_sim_descriptor.dev = hw_sim_descriptor.get_ep_device_p();
	hw_sim_descriptor.set_doorbell_callback_p = symbol_request(set_doorbell_callback);
	hw_sim_descriptor.get_doorbell_value_p = symbol_request(get_doorbell_value);
	hw_sim_descriptor.set_doorbell_value_p = symbol_request(set_doorbell_value);

	hw_sim_descriptor.set_doorbell_callback_p(HOST_PCI, doorbell_cb);

	s_callbacks = callbacks;

	hw_sim_descriptor.device_info.hw_device = hw_sim_descriptor.dev;
	hw_sim_descriptor.device_info.pci_bus = 0;
	hw_sim_descriptor.device_info.pci_slot = 0;
	hw_sim_descriptor.device_info.name = "local_pci_Dev";

	s_callbacks->create_nnp_device(&hw_sim_descriptor,
			&hw_sim_descriptor.device_info,
			&s_hw_sim_ops,
			&hw_sim_descriptor.nnpdev);

	hw_sim_descriptor.set_callback_p(QUEUE_C2H, c2h_cb);

	/* update host doorbell value as "host driver ready" */
	hw_sim_descriptor.set_doorbell_value_p(PCI_HOST,
					       NNP_HOST_BOOT_STATE_DRV_READY << NNP_HOST_BOOT_STATE_SHIFT);

	/* update sph device with current card doorbell value */
	s_callbacks->card_doorbell_value_changed(hw_sim_descriptor.nnpdev,
						 hw_sim_descriptor.get_doorbell_value_p(HOST_PCI));

	rc = sysfs_create_file(&THIS_MODULE->mkobj.kobj, &remove_attr.attr);
	if (rc)
		nnp_log_info(GENERAL_LOG, "Failed to create hw_sim remove sysfs entry\n");

	rc = sysfs_create_file(&THIS_MODULE->mkobj.kobj, &rescan_attr.attr);
	if (rc)
		nnp_log_info(GENERAL_LOG, "Failed to create hw_sim rescan sysfs entry\n");

	return 0;
}

void nnpdrv_hw_cleanup(void)
{
	hw_sim_descriptor.remove_callback_p(QUEUE_C2H);
	hw_sim_descriptor.set_doorbell_callback_p(HOST_PCI, NULL);

	if (hw_sim_descriptor.nnpdev)
		s_callbacks->destroy_nnp_device(hw_sim_descriptor.nnpdev, false);

	symbol_put(send_message);
	symbol_put(set_callback);
	symbol_put(remove_callback);
	symbol_put(get_ep_device);
	symbol_put(set_doorbell_callback);
	symbol_put(get_doorbell_value);
	symbol_put(set_doorbell_value);
}
