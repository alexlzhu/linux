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

/**
 * @file sph_hwtrace_types.h
 *
 * @brief Header file defining sph hwtrace types
 *
 * This header file defines common types used in the sph hwtrace interface library.
 *
 */

#pragma once

#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t hwtrace_t;

#define CNC_PACKET_MAX_SIZE 4 /* (64Bits * 4)  */

typedef enum {
	NNP_HWTRACE_STATUS_INIT			= 0, /**< Session was initialized and ready to program filter and pmons */
	NNP_HWTRACE_STATUS_READY		= 1, /**< trace filters were set and ready to start collect trace */
	NNP_HWTRACE_STATUS_ACTIVE		= 2, /**< Trace session is running - collecting trace */
	NNP_HWTRACE_STATUS_DISABLED		= 3, /**< Trace session is disabled */
	NNP_HWTRACE_STATUS_ERR			= 4, /**< Error in trace collection - please close session */
	NNP_HWTRACE_STATUS_UKNOWN		= 999, /**<Unknown hwtrace state - in case session was not initialize*/
} sphHwTraceStatus;

//CnC Filters used for enabling ICE Traces
typedef struct {
	uint32_t dtf_encoder_config;
	uint32_t cfg_dtf_src_config;
	uint32_t cfg_ptype_filter_ch0;
	uint32_t filter_match_low_ch0;
	uint32_t filter_match_high_ch0;
	uint32_t filter_mask_low_ch0;
	uint32_t filter_mask_high_ch0;
	uint32_t filter_inv_ch0;
	uint32_t cfg_ptype_filter_ch1;
	uint32_t filter_match_low_ch1;
	uint32_t filter_match_high_ch1;
	uint32_t filter_mask_low_ch1;
	uint32_t filter_mask_high_ch1;
	uint32_t filter_inv_ch1;
} ice_cnc_filter;

//Performance monitor object, defines attributes for a single performance monitor item
typedef struct {
	uint32_t id;
	char *offset;
	char *name;
	char *group;
	char *description;
} pmon_info;

//Performance monitor object, input structure - for each perfmormance counter,
//id - index for requester pmon
//frequency - index from 0 - 15 - sample frequency is 256*2^frequency
typedef struct {
	int32_t id;
	uint32_t frequency;
} pmon_enable;


typedef struct {
	union {
		uint64_t value;
		struct {
			uint32_t cbo0_ice0		:1;
			uint32_t cbo0_ice1		:1;
			uint32_t cbo1_ice0		:1;
			uint32_t cbo1_ice1		:1;
			uint32_t cbo2_ice0		:1;
			uint32_t cbo2_ice1		:1;
			uint32_t cbo3_ice0		:1;
			uint32_t cbo3_ice1		:1;
			uint32_t cbo4_ice0		:1;
			uint32_t cbo4_ice1		:1;
			uint32_t cbo5_ice0		:1;
			uint32_t cbo5_ice1		:1;
			uint32_t reserved		:20;
		};
	};
} ice_mask;


/**
 * @brief return status from all sph hwtrace function calls
 */
typedef enum {
	SPH_HWTRACE_NO_ERR				= 0,
	SPH_HWTRACE_DAEMON_NA				= 1,  /**< Can't connect to card trace service */
	SPH_HWTRACE_DRIVER_NA				= 2,  /**< Can't connect to driver trace driver */
	SPH_HWTRACE_INVALID_ARGUMENT			= 3,  /**< bad input */
	SPH_HWTRACE_BAD_PMON_DATA			= 4,  /**< incorrect pmon values were set */
	SPH_HWTRACE_BAD_OPERATION			= 5,  /**< invalid operation */
	SPH_HWTRACE_NO_MEMORY				= 6,  /**< out of memory */
	SPH_HWTRACE_NOT_SUPPORTED			= 7,  /**< request is not supported */
	SPH_HWTRACE_IO_ERROR				= 8,  /**< internal IO problem */
	SPH_HWTRACE_NO_PERMISSION			= 9,  /**< no permission to start hwtrace */
	SPH_HWTRACE_NO_SUCH_RESOURCE			= 10, /**< resource don't exist */
	SPH_HWTRACE_NOT_INITIALIZED			= 11, /**< hwtrace failed to initialized */
	SPH_HWTRACE_FAILED_DEINIT			= 12, /**< hwtrace failed to de initialization */
	SPH_HWTRACE_RESOURCE_CLEANUP_FAIL		= 13, /**< failed to clean resources */
	SPH_HWTRACE_ADD_RESOURCE_FAIL			= 14, /**< failed to add resource */
	SPH_HWTRACE_CONTEXT_BROKEN			= 15, /**< context broken */
	SPH_HWTRACE_FAILED_TO_MAP_HOST_RES		= 16, /**< failed to map host resource */
	SPH_HWTRACE_NO_AVAILABLE_RESOURCE		= 17, /**< failed to retrieve resource */
	SPH_HWTRACE_FAIL_TO_GET_MEM_POOL_INFO		= 18, /**< fail to get max resource allocation info*/
	SPH_HWTRACE_NO_HWTRACE_CLIENT			= 19, /**< client not exist for device */
	SPH_HWTRACE_FAIL_TO_GET_STATE			= 20, /**< fail to get hwtrace state */
	SPH_HWTRACE_FAIL_TO_SET_MSR			= 21, /**< fail to set msr in rdmsr_wrmsr class */
	SPH_HWTRACE_NPK_ERR				= 22, /**< npk interrupts vector is missing */
	SPH_HWTRACE_BAD_INPUT_DATA			= 23, /**< input/content is/are invalid */
	SPH_HWTRACE_UNSUPPORTED_ICE_NUM			= 24, /**< ice number is out of range */
	SPH_HWTRACE_UNSUPPORTED_PMON_ID			= 25, /**< pmon id is out of range */
	SPH_HWTRACE_UNSUPPORTED_PMON_FREQUENCY		= 26, /**< pmon frequency unsupported */
	SPH_HWTRACE_UNSUPPORTED_CONFIG_FILE_FORMAT	= 27, /**< config file format unsupported */
	SPH_HWTRACE_CARD_FATAL_ERROR			= 28, /**< card fatal error */
	SPH_HWTRACE_NO_BLOB_XML_DATA			= 29, /**< no blob xml data */
	SPH_HWTRACE_UNKNOWN_ERROR			= 99  /**< Unexpected error occurred */
} SphHwTraceError;

typedef enum {
	SPHDRV_HWTRACE_NOT_SUPPORTED	= 0, /**< trace engine is not supported */
	SPHDRV_HWTRACE_REGISTERED	= 1, /**< trace engine registers to trace hub device */
	SPHDRV_HWTRACE_INITIALIZED	= 2, /**< trace session was initialized*/
	SPHDRV_HWTRACE_ASIGNED		= 3, /**< trace hub is now working with driver */
	SPHDRV_HWTRACE_ACTIVATED	= 4, /**< trace session is active */
	SPHDRV_HWTRACE_DEACTIVATED	= 5, /**< trace session was deactivated */
	SPHDRV_HWTRACE_ERR		= 6, /**< error in trace session */
	SPHDRV_HWTRACE_UNKNOWN		= 99 /**< unkmonwn trace state */
} SphHwTraceDeviceStatus;



typedef enum {
	SPH_HWTRACE_CNC_TIME_RAW	= 0,
	SPH_HWTRACE_CNC_TIME_MS		= 1,
	SPH_HWTRACE_CNC_TIME_US		= 2,
	SPH_HWTRACE_CNC_TIME_NS		= 3,
	SPH_HWTRACE_CNC_TIME_PS		= 4
} SphHwTraceCncTime;


typedef enum {
	CNC_EVENT_LAYER_START	= 0,
	CNC_EVENT_LAYER_END		= 1,
	CNC_EVENT_CMD			= 2,
	CNC_EVENT_MFW_START		= 3,
	CNC_EVENT_MFW_STOP		= 4,
	CNC_EVENT_CBB_START		= 5,
	CNC_EVENT_CBB_STOP		= 6,
	CNC_PMON_DATA			= 7,
	CNC_FTRACE_MARK_START		= 8,
	CNC_FTRACE_MARK_END		= 9,
	CNC_EVENT_JOB_INFO		= 10,
	CNC_DUMMY_EVENT			= 11,
} SphIceCnCEventType;



typedef struct {
	uint32_t ice_num;
	uint64_t timestamp;
	uint64_t time_unit;
	uint64_t packet_data[CNC_PACKET_MAX_SIZE];
	uint32_t size;
	SphHwTraceCncTime timeFormat;
	bool overflow;
	bool block_wrap;
	bool window_wrap;
} ice_cnc_packet;


typedef struct {
	SphIceCnCEventType type;
	uint64_t timestamp;
	uint64_t time_unit;
	uint64_t ftrace_timestamp;
	uint64_t ftrace_ctxId;
	uint64_t ftrace_netId;
	uint64_t ftrace_infrId;
	uint32_t ice;
	uint32_t core;
	uint32_t network_id;
	uint32_t section;
	uint32_t class_id;
	uint32_t src;
	uint32_t dst;
	uint32_t isPosted;
	uint32_t isSpoofed;
	uint32_t isReply;
	uint32_t exec_state;
	uint32_t exec_isLast;
	uint32_t exec_credits;
	uint32_t exec_isInput;
	uint32_t exec_bid;
	uint32_t exec_paramNum;
	uint32_t exec_consumerNum;
	uint32_t dtf_event;
	uint32_t dtf_debugInfo;
	uint32_t dtf_dsPayloadWords0;
	uint32_t dtf_dsPayloadWords1;
	uint32_t pmon_id;
	uint32_t pmon_group_id;
	uint32_t pmon_payload0;
	uint32_t pmon_payload1;
	bool job_info_start;
	bool job_info_end;
	char *kernel_name;
	char *opcode_name;
} ice_cnc_event;

#ifdef __cplusplus
} // of extern "C"
#endif
