/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef SRC_DRIVER_HOST_NNPDRV_MAINTENANCE_H_
#define SRC_DRIVER_HOST_NNPDRV_MAINTENANCE_H_

#include "nnpdrv_hostres.h"

struct nnp_device;

int nnpdrv_bootimage_init(void);
void nnpdrv_bootimage_fini(void);

int nnpdrv_bootimage_load_boot_image(struct nnp_device *nnpdev, const char *boot_image_name);
int nnpdrv_bootimage_unload_boot_image(struct nnp_device *nnpdev, const char *boot_image_name);

bool nnpdrv_bootimage_image_list_empty(void);

#endif /* SRC_DRIVER_HOST_NNPDRV_MAINTENANCE_H_ */
