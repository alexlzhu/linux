/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _NNPDRV_CRASHLOG_DEBUGFS_H
#define _NNPDRV_CRASHLOG_DEBUGFS_H

#include "nnpdrv_device.h"

void init_crashlog_debugfs(struct nnp_device *nnpdev,
			   struct dentry     *parent);

#endif
