/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "nnpdrv_device.h"

void nnpdrv_device_sysfs_get_state_strings(struct nnp_device *nnpdev,
					   const char **state,
					   const char **boot_state,
					   const char **fail_reason);

int nnpdrv_device_sysfs_init(struct nnp_device *nnpdev);
void nnpdrv_device_sysfs_fini(struct nnp_device *nnpdev);
