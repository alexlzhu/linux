/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _NNP_TIME_H
#define _NNP_TIME_H

#include <linux/kernel.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/timekeeping.h>

static inline u64 nnp_time_us(void)
{
	struct timespec64 t;

	ktime_get_real_ts64(&t);
	return ((u64)(t.tv_sec * 1000000) + (t.tv_nsec / 1000));
};

#endif


