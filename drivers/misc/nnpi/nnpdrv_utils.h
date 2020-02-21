/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include <linux/sched.h>
#include <linux/jiffies.h>
#include <linux/version.h>

#define __NNP_USECS_TO_JIFFIES(x) ((x) != U32_MAX ? usecs_to_jiffies((x)) : MAX_SCHEDULE_TIMEOUT)

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)) /* SPH_IGNORE_STYLE_CHECK */
#define _NNP_USECS_TO_JIFFIES(x) ((x) != 0 ? __NNP_USECS_TO_JIFFIES((x)) : 1)
#else
#define _NNP_USECS_TO_JIFFIES(x) __NNP_USECS_TO_JIFFIES((x))
#endif

#ifdef ULT
extern int nnp_sim;

#define NNP_USECS_TO_JIFFIES(x) (nnp_sim == 0 || (x) == 0 ? _NNP_USECS_TO_JIFFIES((x)) : MAX_SCHEDULE_TIMEOUT)
#else
#define NNP_USECS_TO_JIFFIES(x) _NNP_USECS_TO_JIFFIES((x))
#endif

#define GET_WAIT_EVENT_ERR(ret)					\
	((ret) > 0 ?						\
		(0) /* wait completed before timeout elapsed */	\
	:							\
		((ret) == 0 ?					\
			(-ETIME) /* timed out */		\
		:						\
			/* ERESTARTSYS should not be returned to user. Convert it to EINTR. */\
			((ret) == -ERESTARTSYS ?		\
				(-EINTR)			\
			:					\
				(ret)				\
			)					\
		)						\
	)
