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
#include <string>
#include <memory>
#include <map>
#include <semaphore.h>

/**
 * structure to define sw counter group info
 */
struct um_sw_counter_group_info {
	const char *name;            /**< group name */
};

/**
 * structure to define sw counter info
 */
struct um_sw_counter_info {
	uint32_t    group_idx;       /**< index in group_info_array of the counter group */
	const char *name;            /**< counter name */
	const char *description;     /**< counter description string */
};

/**
 * structure to define a counter set
 */
struct um_sw_counters_set {
	const char                            *name;                   /**< counter set name */
	bool                                   perID;                  /**< false if includes one set of values (global) */
	const struct um_sw_counter_group_info *group_info_array;       /**< group info array */
	uint32_t                               group_info_array_size;  /**< group info array size */
	const struct um_sw_counter_info       *info_array;             /**< counter info array */
	uint32_t                               info_array_size;        /**< counter info array size */
	const struct um_sw_counters_set      **children_array;         /**< children counter set array */
	uint32_t                               children_array_size;    /**< children counter set array size */
};

/**
 * @brief Registers counter set in the system
 *
 * This registers the counter set and all its children sets in the
 * system with the nnpiml counter query API.
 * This function should be called only once after the OS is initialized,
 * the counter set will persist in the system until a reset or reboot.
 * Calling this function more than one time will re-create the counter info
 * and will generate new set of counter values.
 * NOTE: the counter set is identified in the system by its name, so the name
 * property of the set must be unique in the system.
 *
 * @param[in]  root_set  counter set to be registered
 * @return zero on success, -1 on error, errno is set appropiatly.
 */
int register_um_sw_counters(const struct um_sw_counters_set *root_set);

/**
 * @brief Unregister counter set in the system
 *
 * That function unregisters the counter set from the system and will no longer
 * be visible by nnpiml counter query API.
 * Any attempt to create counter values object for that set will fail until it
 * will be re-registered again.
 */
int unregister_um_sw_counters(const struct um_sw_counters_set *root_set);

/**
 * Opaque structure used by the implementation.
 */
struct internal_values_handle;
typedef std::shared_ptr<internal_values_handle>  internal_values_handle_ptr;

/**
 * @brief class to hold counter values of a single counter set instance
 */
class um_sw_counter_values {
public:
	/**
	 * @brief static function to construct a um_sw_counter_values object.
	 *
	 * The function creates an object pointing to exactly N counter values
	 * where N is the value of set->info_array_size.
	 * If the provided counter set is a child of another counter set, a
	 * counter_values object of the parent must have been already created
	 * and must be passed in the parent argument.
	 *
	 * If the provided counter set is a root set (no parent), then the
	 * values object persist in the system until the next reboot, if the
	 * values object of such a set already exist, the function will attach
	 * to the existing counter values object instead of creating a new one.
	 *
	 * If the perID property of the counter set is non-zero then it can hold
	 * multiple values objects, then node_id argument specify the object id
	 * of the currently created values object.
	 *
	 * @param[in]  set      Counter set describing the values to create
	 * @param[in]  parent   Counter values object of the parent object.
	 * @param[in]  node_id  object ID of the values object (ignored for non-perID sets)
	 *
	 * @return counter values object pointer on success or nullptr on failure.
	 */
	static um_sw_counter_values *create(const struct um_sw_counters_set *set,      /* SPH_IGNORE_STYLE_CHECK */
					    um_sw_counter_values            *parent,   /* SPH_IGNORE_STYLE_CHECK */
					    int32_t                          node_id); /* SPH_IGNORE_STYLE_CHECK */

	/**
	 * @brief destruct a values object from the system
	 */
	~um_sw_counter_values();

	void unlink(void);

	/**
	 * @brief check if the given group index is enabled.
	 *
	 * The given group index must be within the range defined for the
	 * counter set (set->group_info_array_size).
	 * The behaviour if out of bound is undefined!
	 */
	inline bool is_enabled(uint32_t group_idx)
	{
		return m_groups[group_idx] || m_global_groups[group_idx];
	}

	/**
	 * @brief return a reference to counter value by its index.
	 *
	 * The given index must be within the range defined for the
	 * counter set (set->info_array_size).
	 * The behaviour if out of bound is undefined!
	 */
	inline uint64_t &value(uint32_t counter_idx)  /* SPH_IGNORE_STYLE_CHECK */
	{
		return m_values[counter_idx];
	}

	/**
	 * @brief Locks the values object
	 *
	 * Used to serialize a counter value when updates from multiple
	 * threads or processes. Do not held the lock for long duration!
	 */
	inline void lock(void)
	{
		sem_wait(m_lock);
	}

	/**
	 * @brief Unlock the values object
	 */
	inline void unlock(void)
	{
		sem_post(m_lock);
	}

private:
	um_sw_counter_values() :
		m_node_id(-1),
		m_values(nullptr),
		m_groups(nullptr),
		m_global_groups(nullptr),
		m_file_idx(-1),
		m_lock(nullptr),
		m_internal_block_off(0),
		m_child_shm_name(nullptr)
	{
	}

private:
	int32_t   m_node_id;
	uint64_t *m_values;
	uint32_t *m_groups;
	uint32_t *m_global_groups;
	internal_values_handle_ptr m_handle;
	uint32_t  m_file_idx;
	sem_t    *m_lock;
	uintptr_t m_internal_block_off;
	char     *m_child_shm_name;
};
