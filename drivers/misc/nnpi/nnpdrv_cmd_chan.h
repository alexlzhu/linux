/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef NNPDRV_CMD_CHAN_H
#define NNPDRV_CMD_CHAN_H

#include <linux/kref.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/atomic.h>
#include <linux/fs.h>
#include "nnpdrv_device.h"
#include "nnpdrv_hostres.h"
#include "inf_proc.h"
#include "ipc_chan_protocol.h"

struct respq_elem;

struct chan_hostres_map {
	uint16_t protocol_id;
	struct hlist_node hash_node;
	struct nnpdrv_host_resource *hostres;
	union c2h_event_report event_msg;
};

struct nnpdrv_cmd_chan {
	void             *magic;
	struct kref       ref;
	struct nnp_device *nnpdev;
	uint16_t          protocol_id;
	struct hlist_node hash_node;
	atomic_t          destroyed;
	union c2h_event_report event_msg;
	union c2h_event_report card_critical_error;
	bool              get_device_events;

	int fd;
	struct msg_scheduler_queue *cmdq;
	struct file *host_file;
	struct inf_process_info *proc_info;
	int    closing;

	spinlock_t        lock;
	struct ida        hostres_map_ida;
	DECLARE_HASHTABLE(hostres_hash, 6);

	spinlock_t        resp_lock_bh;
	wait_queue_head_t resp_waitq;
	struct list_head  respq_list;
	struct respq_elem *curr_respq;

	struct nnpdrv_host_resource *h2c_rb_hostres[NNP_IPC_MAX_CHANNEL_RINGBUFS];
	struct nnpdrv_host_resource *c2h_rb_hostres[NNP_IPC_MAX_CHANNEL_RINGBUFS];
};

int nnpdrv_cmd_chan_create(struct nnp_device       *nnpdev,
			   int                      host_fd,
			   uint32_t                 weight,
			   unsigned int             min_id,
			   unsigned int             max_id,
			   bool                     get_device_events,
			   struct nnpdrv_cmd_chan **out_cmd_chan);

int is_cmd_chan_ptr(void *ptr);

bool nnpdrv_cmd_chan_get(struct nnpdrv_cmd_chan *cmd_chan);
int nnpdrv_cmd_chan_put(struct nnpdrv_cmd_chan *cmd_chan);
void nnpdrv_cmd_chan_set_closing(struct nnpdrv_cmd_chan *cmd_chan);

int nnpdrv_cmd_chan_create_file(struct nnpdrv_cmd_chan *cmd_chan);
int nnpdrv_cmd_chan_send_destroy(struct nnpdrv_cmd_chan *chan);

int nnpdrv_cmd_chan_add_response(struct nnpdrv_cmd_chan *cmd_chan,
				 u64                    *hw_msg,
				 u32                     byte_size);

int nnpdrv_cmd_chan_set_ringbuf(struct nnpdrv_cmd_chan *chan,
				bool                    h2c,
				uint8_t                 id,
				struct nnpdrv_host_resource *hostres);

struct chan_hostres_map *nnpdrv_cmd_chan_find_hostres(struct nnpdrv_cmd_chan *chan, uint16_t protocol_id);
int nnpdrv_chan_unmap_hostres(struct nnpdrv_cmd_chan *chan, uint16_t protocol_id);
void nnpdrv_chan_unmap_hostres_all(struct nnpdrv_cmd_chan *chan);

#endif
