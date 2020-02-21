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
	//
// INTEL CORPORATION CONFIDENTIAL Copyright(c) 2018-2021 Intel Corporation. All Rights Reserved.
//

#pragma once

#include <stdint.h>
#include <vector>
#include <map>


#pragma pack(push, 1)

#define TRACE_PROTO_MAX_PACKET_SIZE   4096
#define TRACE_PROTO_MAX_PAYLOAD_SIZE  (TRACE_PROTO_MAX_PACKET_SIZE - sizeof(trace_proto_header))
#define TRACE_SERVICE_NAME "traces"

typedef std::vector < std::string > event_names_vec;
typedef std::map < std::string, std::string >  str2str_map;

enum trace_proto_request_type {
	TRACED_MSG_LIST_EVENTS       = 1,
	TRACED_MSG_LIST_EVENTS_REPLY,
	TRACED_MSG_ENABLE,
	TRACED_MSG_ENABLE_REPLY,
	TRACED_MSG_DISABLE,
	TRACED_MSG_DISABLE_REPLY,
	TRACED_MSG_DESTROY,
	TRACED_MSG_DESTROY_REPLY,
	TRACED_MSG_READ,
	TRACED_MSG_READ_REPLY,
	TRACED_MSG_NOT_PRIVILEGED_REPLY
};

enum TraceError {
	TRACE_SUCCESS = 0,
	TRACE_NOT_ENOUGH_MEMORY,
	TRACE_EVENT_NOT_EXIST,
	TRACE_UNKNOWN_ERROR
};

struct trace_proto_connect_reply {
	uint8_t  is_busy;
	uint8_t  is_started;
	uint8_t  is_stopped;
};

struct trace_proto_header {
	uint32_t msg_type      :  8;
	uint32_t packet_size   : 16;
	uint32_t is_last       :  1;
	uint32_t success       :  1;
	uint32_t reserved      :  6;
};

struct trace_list_events {
	uint32_t num_events;
};

struct trace_list_events_reply {
	TraceError status;
};

struct trace_enable {
	struct trace_proto_header header;
	uint32_t                  max_bytes;
	bool                      enable_overwrite;
};

struct trace_disable_reply {
	uint32_t bytes;
	uint32_t discard_events;
	bool success;
};

struct trace_read_file {
	struct trace_proto_header header;
	uint32_t                  read_offset;
	uint32_t                  req_read_size;
};

struct trace_read_file_reply {
	uint32_t actual_read;
	char     buf[];
};

#pragma pack(pop)
