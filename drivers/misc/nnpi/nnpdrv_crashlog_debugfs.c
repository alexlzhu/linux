/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "nnpdrv_crashlog_debugfs.h"
#include <linux/seq_file.h>

static int debug_crashlog_show(struct seq_file *m, void *v)
{
	struct nnp_device *nnpdev = m->private;
	union nnp_inbound_mem *inbound_mem;

	if (unlikely(nnpdev == NULL))
		return -EINVAL;

	inbound_mem = nnpdev->inbound_mem;
	if (!inbound_mem) {
		seq_puts(m, "Inbound memory region is not present\n");
		return 0;
	}

	seq_printf(m, "Inbound memory magic: 0x%x\n", inbound_mem->magic);
	if (inbound_mem->magic != NNP_INBOUND_MEM_MAGIC) {
		seq_printf(m, "Inbound magic is wrong, should be 0x%x\n", NNP_INBOUND_MEM_MAGIC);
		return 0;
	}

	seq_printf(m, "Crash dump size: %u\n", inbound_mem->crash_dump_size);
	if (inbound_mem->crash_dump_size > 0)
		seq_write(m, inbound_mem->crash_dump, inbound_mem->crash_dump_size);

	return 0;
}

static int debug_crashlog_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, debug_crashlog_show, inode->i_private);
}

static const struct file_operations debug_crashlog_fops = {
	.open		= debug_crashlog_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

void init_crashlog_debugfs(struct nnp_device *nnpdev,
			   struct dentry     *parent)
{
	struct dentry *crashlog;

	if (!parent)
		return;

	crashlog = debugfs_create_file("crashlog",
				       0444,
				       parent,
				       (void *)nnpdev,
				       &debug_crashlog_fops);
}
