


/*******************************************************************************
 * INTEL CORPORATION CONFIDENTIAL Copyright(c) 2017-2021 Intel Corporation. All Rights Reserved.
 *
 * The source code contained or described herein and all documents related to the
 * source code ("Material") are owned by Intel Corporation or its suppliers or
 * licensors. Title to the Material remains with Intel Corporation or its suppliers
 * and licensors. The Material contains trade secrets and proprietary and
 * confidential information of Intel or its suppliers and licensors. The Material
 * is protected by worldwide copyright and trade secret laws and treaty provisions.
 * No part of the Material may be used, copied, reproduced, modified, published,
 * uploaded, posted, transmitted, distributed, or disclosed in any way without
 * Intel's prior express written permission.
 *
 * No license under any patent, copyright, trade secret or other intellectual
 * property right is granted to or conferred upon you by disclosure or delivery of
 * the Materials, either expressly, by implication, inducement, estoppel or
 * otherwise. Any license under such intellectual property rights must be express
 * and approved by Intel in writing.
 ********************************************************************************/
#include <syslog.h>
#include "log_category_defs.h"

#define SPH_LOG_DEFAULT GENERAL_LOG

#define sph_log_info(category, msg, ...) \
	syslog(LOG_LOCAL0 | LOG_INFO, category " , INFO, " msg "\n", ##__VA_ARGS__)

#define sph_log_err(category, msg, ...) \
	syslog(LOG_LOCAL0 | LOG_ERR, category " , ERROR, " msg "\n", ##__VA_ARGS__)

#define sph_log_warn(category, msg, ...) \
	syslog(LOG_LOCAL0 | LOG_WARNING, category " , WARNING, " msg "\n", ##__VA_ARGS__)

#if defined (_DEBUG) || defined(DEBUG)
#define sph_log_debug(category, msg, ...) \
	syslog(LOG_LOCAL0 | LOG_DEBUG, category " , DEBUG, " msg "\n", ##__VA_ARGS__)
#else
#define sph_log_debug(category, msg, ...)
#endif

#ifdef SPH_INTERNAL_LOG
#define sph_log_internal(SPH_LOG_RT, msg, ...) \
	syslog(LOG_LOCAL0 | LOG_DEBUG, category " , INTERNAL, " msg "\n", ##__VA_ARGS__)
#endif

#define sph_start_log() \
	openlog(NULL, LOG_PID, LOG_LOCAL0)

#define sph_end_log() \
	closelog()
