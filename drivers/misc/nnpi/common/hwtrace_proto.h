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
#include <vector>
#include <map>

#include "sph_hwtrace_types.h"


#pragma pack(push, 1)

#define HWTRACE_PROTO_MAX_PACKET_SIZE   4096
#define HWTRACE_PROTO_MAX_PAYLOAD_SIZE  (HWTRACE_PROTO_MAX_PACKET_SIZE - sizeof(hwtrace_proto_header))
#define HWTRACE_SERVICE_NAME "hwtraces"

enum hwtrace_proto_request_type {
	HWTRACED_MSG_NPK_INIT,
	HWTRACED_MSG_NPK_INIT_REPLY,
	HWTRACED_MSG_DEINIT,
	HWTRACED_MSG_DEINIT_REPLY,
	HWTRACED_MSG_SET_TRACE_STATE,
	HWTRACED_MSG_SET_TRACE_STATE_REPLY,
	HWTRACED_MSG_CNC_CONFIG,
	HWTRACED_MSG_CNC_CONFIG_REPLY,
	HWTRACED_MSG_GET_PMONS,
	HWTRACED_MSG_GET_PMONS_REPLY,
	HWTRACED_MSG_SET_PMONS,
	HWTRACED_MSG_SET_PMONS_REPLY,
	HWTRACED_MSG_GET_STATUS,
	HWTRACED_MSG_GET_STATUS_REPLY,
	HWTRACED_MSG_GET_XML_DATA_SIZE,
	HWTRACED_MSG_GET_XML_DATA_SIZE_REPLY,
	HWTRACED_MSG_GET_XML_DATA,
	HWTRACED_MSG_GET_XML_DATA_REPLY,
	HWTRACED_MSG_ULT_SW_TRACES,
	HWTRACED_MSG_ULT_SW_TRACES_REPLY,
	HWTRACED_MSG_WA_DISABLE_CPKG,
	HWTRACED_MSG_WA_DISABLE_CPKG_REPLY,
	HWTRACED_MSG_USE_LOGICAL_ICE_NUMBERS,
	HWTRACED_MSG_USE_LOGICAL_ICE_NUMBERS_REPLY,
	HWTRACED_MSG_SET_LOGICAL_NODE,
	HWTRACED_MSG_SET_LOGICAL_NODE_REPLY
};

struct hwtrace_proto_header {
	uint32_t msg_type	:  8;
	uint32_t packet_size	: 16;
	uint32_t is_last	:  1;
	uint32_t success	:  1;
	uint32_t retCode	:  6;
};

struct hwtrace_npk_init {
	struct hwtrace_proto_header header;
	size_t resource_count;
	size_t resource_size;
	pid_t pid;
};

struct hwtrace_npk_trace_state {
	struct hwtrace_proto_header header;
	bool enable;
	pid_t pid;
};

struct hwtrace_logical_config {
	struct hwtrace_proto_header header;
	uint32_t node_count;
};

struct hwtrace_logical_node {
	struct hwtrace_proto_header header;
	uint32_t node_num;
	ice_mask mask;
	ice_cnc_filter filter;
	bool	ctx_id_valid;
	uint32_t ctx_id;
	bool	infer_num_valid;
	uint32_t infer_num;
	bool	net_id_valid;
	uint32_t net_id;
};

struct hwtrace_cnc_configure {
	struct hwtrace_proto_header header;
	ice_mask mask;
	ice_cnc_filter filter;
};

struct hwtrace_pmons_list {
	struct hwtrace_proto_header header;
	size_t count;
};

struct hwtrace_xml_data {
	struct hwtrace_proto_header header;
	size_t size;
};

struct hwtrace_pmons_configure {
	struct hwtrace_proto_header header;
	ice_mask mask;
	size_t count;
};

#ifdef ULT

struct ult_hwtrace_sw_trace {
	struct hwtrace_proto_header header;
	size_t count;
	size_t start;
};

#endif //ULT

struct hwtrace_header {
	struct hwtrace_proto_header header;
};

struct hwtrace_status_reply {
	struct hwtrace_proto_header header;
	sphHwTraceStatus status;
	bool             start_permission;
};

typedef struct hwtrace_header  hwtrace_disable_trace;
typedef struct hwtrace_header  hwtrace_get_status;


#pragma pack(pop)
