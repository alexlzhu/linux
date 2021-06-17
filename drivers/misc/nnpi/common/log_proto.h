



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

#pragma once

#include <stdint.h>

#pragma pack(push, 1)

#define LOG_PROTO_MAX_PACKET_SIZE   4096

enum log_proto_request_type {
	LOG_MSG_SET_LEVEL       = 1,
	LOG_MSG_SET_LEVEL_REPLY = 2,
	LOG_MSG_GET_LEVEL       = 3,
	LOG_MSG_GET_LEVEL_REPLY = 4,
	LOG_MSG_GET_HISTORY	= 5,
	LOG_MSG_GET_HISTORY_REPLY = 6,
	LOG_MSG_SET_LEVEL_NO_PERM = 7,
	LOG_MSG_GET_MRC           = 8,
	LOG_MSG_GET_MRC_REPLY     = 9,
	LOG_MSG_NOT_PERMITTED      = 10,
	LOG_MSG_INVALID_ARGUMENT   = 11,
	LOG_MSG_GET_OS_MEASUREMENT = 12,
	LOG_MSG_GET_OS_MEASUREMENT_REPLY = 13,
};

struct log_proto_get_level {
	uint32_t msg_type	: 8;
	uint32_t i_category	: 8;
	uint32_t o_level	: 8;
	uint32_t unused		: 8;
};

struct log_proto_set_level {
	uint32_t msg_type	: 8;
	uint32_t i_category	: 8;
	uint32_t io_level	: 8;
	uint32_t unused		: 8;
};

struct log_proto_get_history {
	uint32_t msg_type	: 8;
	uint32_t o_ret		: 8;
	uint32_t syslog		: 1;
	uint32_t unused		: 15;
	int32_t i_seconds;
};

struct log_proto_get_mrc {
	uint8_t msg_type;
	uint8_t o_ret;
	uint8_t ppv;
};

struct log_proto_get_os_measurement {
	uint8_t msg_type;
	uint8_t o_ret;
};

#pragma pack(pop)
