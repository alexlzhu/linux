



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
#include <limits.h>

#pragma pack(push, 1)

enum maintenance_request_type {
	MAIN_FW_UPDATE,
	MAIN_FW_UPDATE_STATUS,       /* Not supported - leave for protocol backward compatibility */
	MAIN_POWER_SET_TIME_WINDOW,
	MAIN_POWER_GET_TIME_WINDOW,
	MAIN_POWER_LIMIT_RANGE_GET,
	MAIN_POWER_LIMIT_GET,
	MAIN_POWER_LIMIT_SET,
	MAIN_THERMAL_POINT_SET,
	MAIN_THERMAL_POINT_GET,
	MAIN_MCE_INJECT,
	MAIN_FW_FLASH_OUTPUT,
	MAIN_FREQ_GET,
	MAIN_FREQ_SET,
	MAIN_POWER_SET_POWER_SAVING_MODE,
	MAIN_POWER_GET_POWER_SAVING_MODE,
	MAIN_SET_TIME,
	MAIN_GET_TIME,
	MAIN_IBECC_INJECT,
	MAIN_ICE_DUMP_SET_LEVEL,
	MAIN_ICE_DUMP_LIST,
	MAIN_ICE_DUMP_PULL,
	MAIN_GET_VERSIONS,
	MAIN_POWER_SET_ICE_IDLE_TIME,
	MAIN_POWER_GET_ICE_IDLE_TIME,
	MAIN_SET_DMA_HANG_PERIODIC_TIME,
	MAIN_GET_DMA_HANG_PERIODIC_TIME,
	MAIN_SET_DMA_RECOVERY_MODE,
	MAIN_GET_DMA_RECOVERY_MODE,
};

struct maintenance_fw_update_request_header {
	size_t image_size;
	char image_name[NAME_MAX];
	uint32_t image_name_len;
	uint32_t crc;
	char term[64];

};

struct maintenance_thermal_threshold {
	uint32_t event;
	uint32_t throttle_thresh;
	uint32_t time_ms;
};

struct maintenance_power_capabilities {
	uint32_t minimum;
	uint32_t maximum;
	uint32_t time_window;
};

struct maintenance_rapl {
	uint32_t power_limit1_uW;
	uint32_t power_limit2_uW;
	uint32_t time_window1_ms;
	uint32_t time_window2_ms;
};

enum maintenance_mce_inject_type {
	MAIN_MCE_TYPE_CORR_ECC = 0,
	MAIN_MCE_TYPE_UNCORR,
	MAIN_MCE_TYPE_UNCORR_ECC,
	MAIN_MCE_TYPE_UNCORR_FATAL,
	MAIN_MCE_TYPE_UNCORR_FATAL_ECC,
	MAIN_MCE_TYPE_CATERR
};

struct maintenance_mce_inject {
	uint32_t mce_inject_type;
	uint32_t delay_ms;
};

enum maintenance_freq_device_type {
	MAIN_FREQ_DEVICE_IA = 0,
	MAIN_FREQ_DEVICE_RING,
	MAIN_FREQ_DEVICE_ICE,
	MAIN_FREQ_DEVICE_LAST
};

enum maintenance_freq_range_type {
	MAIN_FREQ_RANGE_LIMITS = 0,
	MAIN_FREQ_RANGE_CURR_LIMITS,
	MAIN_FREQ_RANGE_TYPE_LAST
};

struct maintenance_freq_get {
	maintenance_freq_device_type dev;
	maintenance_freq_range_type  range_type;
	uint32_t                     dev_num;
};

struct maintenance_freq_set {
	maintenance_freq_device_type dev;
	uint32_t                     dev_num;
	uint32_t                     min;
	uint32_t                     max;
};

struct maintenance_time {
	uint64_t seconds;
	uint64_t useconds;
};

enum maintenance_ibecc_error_type {
	MAIN_IBECC_TYPE_COR,
	MAIN_IBECC_TYPE_UNCOR,
};

enum maintenance_ibecc_error_scope {
	MAIN_IBECC_SCOPE_OS,
	MAIN_IBECC_SCOPE_CTXT,
};

enum maintenance_ibecc_error_uc_severity {
	MAIN_IBECC_SEVERITY_CTXT,
	MAIN_IBECC_SEVERITY_CARD,
	MAIN_IBECC_SEVERITY_NA
};

struct maintenance_ibecc_inject_request {
	enum maintenance_ibecc_error_scope error_scope;
	enum maintenance_ibecc_error_type error_type;
	enum maintenance_ibecc_error_uc_severity error_uc_severity;
	uint32_t delay_ms;
};

struct maintenance_ice_dumps_request {
	uint32_t level;
	char folder_name[NAME_MAX];
	uint32_t num_of_entries;
};

enum dma_recovery_mode {
	MAIN_DMA_NO_RECOVERY = 0,
	MAIN_DMA_NORMAL_RECOVERY,
	MAIN_DMA_FATAL_RECOVERY,
	MAIN_DMA_SILENT_RECOVERY,
};

struct maintenance_request_header {
	uint32_t request_type;
	union {
		struct maintenance_fw_update_request_header fw_update_request_header;
		struct maintenance_thermal_threshold thermal_thresh;
		struct maintenance_rapl rapl;
		struct maintenance_mce_inject mce_inject;
		struct maintenance_freq_get freq_get;
		struct maintenance_freq_set freq_set;
		struct maintenance_time time_value;
		struct maintenance_ibecc_inject_request ibecc_inject_request;
		struct maintenance_ice_dumps_request ice_dumps_request;
		uint32_t power_status_refresh_rate;
		uint32_t power_save_mode;
		uint32_t ice_idle_time_ms;
		enum dma_recovery_mode recovery_mode;
	};
};

enum maintenance_reply_type {
	MAIN_REQ_COMPLETED,
	MAIN_REQ_BUSY,
	MAIN_REQ_INVALID,
	MAIN_REQ_NO_PERM,
	MAIN_REQ_PERM,
	MAIN_REQ_ERROR,
	MAIN_REQ_CRC_ERROR,
	MAIN_INACTIVE_ICE,
	MAIN_ICE_DUMP
};

struct maintenance_fw_update_status_reply {
	char image_name[NAME_MAX];
	uint32_t image_name_len;
};

struct maintenance_freq_reply {
	maintenance_freq_device_type dev;
	maintenance_freq_range_type  range_type;
	uint32_t                     dev_num;
	uint32_t                     min;
	uint32_t                     max;
	uint32_t                     step;
};

enum maintenance_ice_dumps_type {
	MAIN_ICE_DUMPS_NAME,
	MAIN_ICE_DUMPS_FILE_CONTENT
};

struct maintenance_ice_dumps_reply {
	enum maintenance_ice_dumps_type msg_type;
	uint32_t size;
	bool is_last;
};

struct maintenance_reply {
	uint32_t reply_type;
	union {
		struct maintenance_fw_update_status_reply fw_update_status_reply;
		struct maintenance_thermal_threshold thermal_point;
		struct maintenance_power_capabilities power_cap;
		struct maintenance_rapl power_limit;
		struct maintenance_freq_reply freq;
		struct maintenance_time time_value;
		struct maintenance_ice_dumps_reply ice_dumps;
		uint32_t power_time_window;
		uint32_t power_save_mode;
		uint32_t versions_len;
		uint32_t ice_idle_time_ms;
		enum dma_recovery_mode recovery_mode;
	};
};

typedef struct {
	char folder_name[NAME_MAX+1];
	int64_t tv_sec;
} ice_dump_info;

#pragma pack(pop)
