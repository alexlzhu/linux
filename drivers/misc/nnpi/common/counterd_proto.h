



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

#define COUNTERD_PROTO_MAX_PACKET_SIZE   4096
#define COUNTERD_PROTO_MAX_PAYLOAD_SIZE  (COUNTERD_PROTO_MAX_PACKET_SIZE - sizeof(counterd_proto_header))
#define COUNTERD_PROTO_NUM_ICEBOS  6

enum counterd_proto_request_type {
	COUNTERD_MSG_LIST_COUNTERS       = 1,
	COUNTERD_MSG_LIST_COUNTERS_REPLY,
	COUNTERD_MSG_CREATE_REPORT,
	COUNTERD_MSG_CREATE_REPORT_REPLY,
	COUNTERD_MSG_DESTROY_REPORT,
	COUNTERD_MSG_REFRESH_REPORT,
	COUNTERD_MSG_REFRESH_REPORT_REPLY,
	COUNTERD_MSG_SAMPLE_REPORT,
	COUNTERD_MSG_SAMPLE_REPORT_REPLY,
	COUNTERD_PMON_CONFIG,
	COUNTERD_PMON_CONFIG_REPLY
};

struct counterd_proto_header {
	uint32_t msg_type      :  8;
	uint32_t packet_size   : 16;
	uint32_t is_last       :  1;
	uint32_t reserved      :  7;
};

struct counterd_list_counters_reply {
	uint32_t num_counters;
};

struct counterd_create_report_reply {
	uint64_t handle;
	uint32_t num_entries;
	uint32_t can_auto_refresh;
};

struct counterd_destroy_report {
	struct counterd_proto_header header;
	uint64_t                     handle;
};

struct counterd_sample_report {
	struct counterd_proto_header header;
	uint64_t                     handle;
	uint32_t                     set_auto_refresh;
};

struct counterd_sample_report_reply {
	struct counterd_proto_header header;
	uint64_t                     handle;
	uint32_t                     num_values;
	uint64_t                     timestamp;
};

struct counterd_refresh_report {
	struct counterd_proto_header header;
	uint64_t                     handle;
};

struct counterd_refresh_report_reply {
	struct counterd_proto_header header;
	uint64_t                     handle;
	uint32_t                     num_entries;
	uint32_t                     refreshed;
};

enum icebo_pmon_config {
	PMON_HITS_PER_ICE = 1,
	PMON_MISS_PER_ICE,
	PMON_ACCESSES_PER_ICE,
	PMON_HITS_MISS_ICEBO,
	PMON_TRANSACTION_WAIT_AVG,
	PMON_READ_WRITE,
	PMON_SHARED_READ_ANALYSIS1,
	PMON_INVALID_CONFIG /* must be last */
};

enum icebo_pmon_config2 {
	PMON_BOTTLENECK_ANALYSIS = 1,
	PMON_IDLE_ANALYSIS,
	PMON_ICE0_RW_BACKPRESSURE,
	PMON_ICE1_RW_BACKPRESSURE,
	PMON_SHARED_READ_ANALYSIS2,
	PMON_BW_FIFO_TRENDS,
	PMON_BW_CREDIT_TRENDS,
	PMON_INVALID_CONFIG2 /* must be last */
};

enum counterd_pmon_config_status {
	PMON_CONFIG_SUCCESS = 0,
	PMON_CONFIG_NOPERM,
	PMON_CONFIG_FAILED
};

struct counterd_pmon_config {
	struct counterd_proto_header header;
	icebo_pmon_config            config[COUNTERD_PROTO_NUM_ICEBOS];
	icebo_pmon_config2           config2[COUNTERD_PROTO_NUM_ICEBOS];
};

struct counterd_pmon_config_reply {
	counterd_pmon_config_status status;
};
#pragma pack(pop)
