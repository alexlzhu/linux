/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _NNPDRV_DEVICE_H
#define _NNPDRV_DEVICE_H

#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/debugfs.h>
#include <linux/kref.h>
#include <linux/completion.h>
#include <linux/idr.h>
#include <linux/hashtable.h>
#include "nnpdrv_pcie.h"
#include "msg_scheduler.h"
#include "nnp_inbound_mem.h"
#include "ipc_protocol.h"

#define NNP_MAX_DEVS		32
#define DEVICE_NAME_LEN 32
#define NNP_DEVICE_MAX_BOOT_IMAGE_PATH_SIZE 256

#define NNP_FIRMWARE_NAME "intel/nnpi/disk.img"

NNP_STATIC_ASSERT(NNP_MAX_DEVS <= U8_MAX, "Setting NNP_MAX_DEVS to more than U8_MAX is not supported");

/* device state bits */
#define NNP_DEVICE_BOOT_BIOS_READY        BIT(1)
#define NNP_DEVICE_BOOT_RECOVERY_BIOS_READY BIT(2)
#define NNP_DEVICE_BOOT_SYSINFO_READY     BIT(3)
#define NNP_DEVICE_BOOT_STARTED           BIT(4)
#define NNP_DEVICE_BIOS_UPDATE_READY      BIT(5)
#define NNP_DEVICE_BIOS_UPDATE_STARTED    BIT(6)
#define NNP_DEVICE_BIOS_UPDATE_DONE       BIT(7)
#define NNP_DEVICE_CARD_DRIVER_READY      BIT(8)
#define NNP_DEVICE_CARD_READY             BIT(9)
#define NNP_DEVICE_CARD_ENABLED           BIT(10)

#define NNP_DEVICE_CARD_BOOT_STATE_MASK   GENMASK(9, 1)

#define NNP_DEVICE_ACTIVE_MASK       (NNP_DEVICE_CARD_READY | \
				      NNP_DEVICE_CARD_ENABLED)

#define NNP_DEVICE_FAILED_VERSION    BIT(16)
#define NNP_DEVICE_BOOT_FAILED       BIT(17)
#define NNP_DEVICE_HOST_DRIVER_ERROR BIT(18)
#define NNP_DEVICE_FATAL_DMA_ERROR   BIT(19)
#define NNP_DEVICE_KERNEL_CRASH	     BIT(20)
#define NNP_DEVICE_PCI_ERROR         BIT(21)
#define NNP_DEVICE_CARD_IN_RESET     BIT(22)
#define NNP_DEVICE_FATAL_MCE_ERROR   BIT(23)
#define NNP_DEVICE_FATAL_DRAM_ECC_ERROR   BIT(24)
#define NNP_DEVICE_FATAL_ICE_ERROR   BIT(25)
#define NNP_DEVICE_HANG              BIT(26)
#define NNP_DEVICE_PROTOCOL_ERROR    BIT(27)
#define NNP_DEVICE_CAPSULE_EXPECTED  BIT(28)
#define NNP_DEVICE_CAPSULE_FAILED    BIT(29)
#define NNP_DEVICE_CURRUPTED_BOOT_IMAGE BIT(30)
#define NNP_DEVICE_ERROR_MASK        GENMASK(31, 16)

struct host_crash_dump {
	void *vaddr;
	dma_addr_t dma_addr;
	uint32_t dump_size;
};

struct nnp_device_counters {
	struct {
		int enable;
		u64 commands_wait_time;  /* total time spend waiting for free slots in h/w command queue */
		u64 commands_sent_count; /* number of commands sent on the h/w command queue */
		u64 commands_sched_count; /* Number of commands scheduled to be sent to h/w queue */
		u64 responses_consume_time; /* Total time spent reading responses from h/w queue */
		u64 responses_count;  /* Total number of responses received from device */
	} ipc;

	struct {
		u64 os_crashed;  /* Number of times device needed to be reset due to device fatal error */
		u64 ecc_nonfatal;  /* Number of times a non-fatal uncorrectable ECC error happend on device */
		u64 ecc_fatal; /* Number of times a fatal, uncorrectable ECC error happened on device */
		u64 dram_ecc_nonfatal;  /* Number of times a non-fatal uncorrectable ECC error happend on device DRAM */
		u64 dram_ecc_fatal; /* Number of times a fatal, uncorrectable ECC error happened on device DRAM */
		u64 mce_nonfatal;  /* Number of times a non-fatal uncorrectable MCE error happend on device */
		u64 mce_fatal; /* Number of times a fatal, uncorrectable MCE error happened on device */
		u64 dma_hang_nonfatal; /* Number of times DMA engine on device has hanged and rewquired reset */
		u64 dma_hang_fatal; /* Number of times DMA engine on device has hanged and failed to be reset */
	} uncorr;

	struct {
		u64 ecc; /* Number of times a correctable ECC error happened on device */
		u64 dram_ecc; /* Number of times a correctable ECC error happened on device DRAM */
	} corr;
};

struct nnp_device {
	struct kref    ref;
	void          *hw_handle;
	const struct nnp_hw_device_info   *hw_device_info;
	const struct nnpdrv_device_hw_ops *hw_ops;
	struct workqueue_struct *wq;
	spinlock_t     lock;
	struct completion *release_completion;
	struct work_struct free_work;

	struct device *cdev;
	struct host_crash_dump host_crash_dump;
	struct msg_scheduler       *cmdq_sched;
	struct msg_scheduler_queue *public_cmdq;
	union c2h_event_report critical_error;
	union nnp_inbound_mem  *inbound_mem;

	uint32_t        id;
	char           name[DEVICE_NAME_LEN];
	bool           is_recovery_bios;
	u32            boot_image_loaded;
	char           reset_boot_image_path[NNP_DEVICE_MAX_BOOT_IMAGE_PATH_SIZE];

	u64            response_buf[32];
	u32            response_num_msgs;

	struct ida cmd_chan_ida;
	DECLARE_HASHTABLE(cmd_chan_hash, 6);
	wait_queue_head_t waitq;

	dma_addr_t                  bios_system_info_dma_addr;
	struct nnp_c2h_system_info *bios_system_info;
	bool                        bios_system_info_valid;
	size_t                      card_sys_info_num_page;
	dma_addr_t                  card_sys_info_dma_addr;
	struct nnp_sys_info        *card_sys_info;
	bool                        card_sys_info_valid;

	u32            num_ice_devices;
	u32            state;
	u32            curr_boot_state;
	u16            protocol_version;
	u16            chan_protocol_version;
	u32            num_active_contexts;
	u32            card_doorbell_val;
	u32            pci_error;

	struct workqueue_struct *restore_wq;
	uint32_t correctable_ecc_threshold;
	uint32_t correctable_ecc_counter;
	uint32_t uncorrectable_ecc_threshold;
	uint32_t uncorrectable_ecc_counter;
	uint32_t correctable_dram_ecc_threshold;
	uint32_t correctable_dram_ecc_counter;
	uint32_t uncorrectable_dram_ecc_threshold;
	uint32_t uncorrectable_dram_ecc_counter;

	struct dentry *debugfs_dir;

	bool ipc_h2c_en[IPC_OP_MAX];
	bool ipc_c2h_en[IPC_OP_MAX];
	u8   ipc_chan_resp_op_size[32];
	u8   ipc_chan_cmd_op_size[32];

	struct nnp_device_counters counters;
};

typedef int (*nnpdrv_response_handler)(struct nnp_device *nnpdev, u64 *msg, u32 size);

int nnpdrv_device_create(void                              *hw_handle,
			 const struct nnp_hw_device_info   *hw_device_info,
			 const struct nnpdrv_device_hw_ops *hw_ops,
			 struct nnp_device                **out_nnpdev);

void nnpdrv_device_get(struct nnp_device *nnpdev);
int nnpdrv_device_put(struct nnp_device *nnpdev);

void nnpdrv_card_doorbell_value_changed(struct nnp_device *nnpdev,
					u32                doorbell_val);

int nnpdrv_device_destroy(struct nnp_device *nnpdev, bool prepare_only);

int nnpdrv_device_process_messages(struct nnp_device *nnpdev,
				   u64               *msg,
				   u32                size);

int nnpdrv_device_pci_error_detected(struct nnp_device *nnpdev,
				     u32                error_type);

int nnpdrv_device_active(struct nnp_device *nnpdev);
int nnpdrv_device_ready(struct nnp_device *nnpdev);
int nnpdrv_device_driver_ready(struct nnp_device *nnpdev);

struct msg_scheduler_queue *nnpdrv_create_cmd_queue(struct nnp_device *nnpdev,
						    u32                weight);

int nnpdrv_destroy_cmd_queue(struct nnp_device          *nnpdev,
			     struct msg_scheduler_queue *q);

static inline int nnpdrv_msg_scheduler_queue_add_msg(struct msg_scheduler_queue *queue, u64 *msg, int size)
{
	struct nnp_device *nnpdev = (struct nnp_device *)queue->device_hw_data;

	if (nnpdev->counters.ipc.enable)
		nnpdev->counters.ipc.commands_sched_count++;

	return msg_scheduler_queue_add_msg(queue, msg, size);
}

int nnpdrv_device_list_get(uint32_t nnpDevNum, struct nnp_device **outNNPDev);
bool nnpdrv_device_has_critical_error(struct nnp_device *nnpdev);
void nnpdrv_device_disable(struct nnp_device *nnpdev);
void nnpdrv_device_enable(struct nnp_device *nnpdev);
int nnpdrv_device_force_reset(struct nnp_device *nnpdev);
void nnpdrv_device_reset_prepare(struct nnp_device *nnpdev, bool is_hang);
void nnpdrv_device_reset_done(struct nnp_device *nnpdev);
void nnpdrv_device_state_set(struct nnp_device *nnpdev, u32 mask);

struct nnpdrv_cmd_chan *nnpdrv_device_find_channel(struct nnp_device *nnpdev, uint16_t protocol_id);

void nnpdrv_submit_device_event_to_channels(struct nnp_device *nnpdev,
					    union c2h_event_report *event_msg,
					    bool                   force);

extern struct ida g_nnp_dev_ida;
extern struct dentry *g_debugfs_dir;

#ifdef ULT
int inject_pci_err_event_on_device(struct nnp_device *nnpdev);
#endif

#endif
