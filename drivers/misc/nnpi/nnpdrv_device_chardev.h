/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _NNPDRV_DEVICE_CHARDEV_H
#define _NNPDRV_DEVICE_CHARDEV_H

#include "nnpdrv_device.h"
#include <linux/list.h>
#include <linux/fs.h>

struct events_report_client_info {
	struct list_head events_list_head;
	struct list_head node;
};

struct inf_process_info;

struct device_client_info {
	struct nnp_device *nnpdev;
	struct file *host_file;
	bool is_inf_client;
};

int nnpdev_device_chardev_create(struct nnp_device *nnpdev);
void nnpdev_device_chardev_destroy(struct nnp_device *nnpdev);
int nnpdev_device_chardev_init(void);
int nnpdev_device_chardev_cleanup(void);

extern int event_valToNNPErrno(enum event_val event_val);
#endif
