/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _NNP_TRACE_FORMAT_H
#define _NNP_TRACE_FORMAT_H

#define NNP_TRACE_IPC			nnpi_host_ipc
#define NNP_TRACE_MMIO			host_pep_mmio
#define NNP_TRACE_CLOCK_STAMP		nnpi_host_clock_stamp

#define NNP_TRACE_START		's'	// state - s: operation has began
#define NNP_TRACE_COMPLETE	'c'	// state - c: operation has completed



#endif /* _NNP_TRACE_FORMAT_H */
