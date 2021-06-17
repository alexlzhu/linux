/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _NNPDRV_INFERENCE_H
#define _NNPDRV_INFERENCE_H

#include "ipc_protocol.h"
#include "nnpdrv_hostres.h"

struct nnp_device;

int init_host_interface(void);
void release_host_interface(void);

struct file *nnpdrv_host_file_get(int host_fd);

#endif
