/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/idr.h>
#include <linux/mutex.h>
#include <linux/stringify.h>
#include <linux/debugfs.h>
#include "nnpdrv_pcie.h"
#include "nnpdrv_host.h"
#include "nnp_log.h"
#include "nnpdrv_device_chardev.h"
#include "nnpdrv_pcie.h"
#include "nnpdrv_bootimage.h"

struct ida g_nnp_dev_ida;
struct dentry *g_debugfs_dir;

static struct nnpdrv_device_hw_callbacks nnp_dev_callbacks = {

	.create_nnp_device = nnpdrv_device_create,
	.card_doorbell_value_changed = nnpdrv_card_doorbell_value_changed,
	.destroy_nnp_device = nnpdrv_device_destroy,
	.process_messages = nnpdrv_device_process_messages,
	.pci_error_detected = nnpdrv_device_pci_error_detected,
	.reset_prepare = nnpdrv_device_reset_prepare,
	.reset_done = nnpdrv_device_reset_done
};

static int nnpdrv_init_module(void)
{
	int ret = 0;

	nnp_log_debug(START_UP_LOG, "init module\n");

	ida_init(&g_nnp_dev_ida);

	g_debugfs_dir = debugfs_create_dir("sphdrv", NULL);
	if (IS_ERR_OR_NULL(g_debugfs_dir)) {
		nnp_log_info(START_UP_LOG, "Failed to initialize debugfs dir\n");
		g_debugfs_dir = NULL;
	}

	ret = nnpdev_device_chardev_init();
	if (ret) {
		nnp_log_err(START_UP_LOG, "Failed to init device chardev\n");
		goto err_return;
	}

	/* Initlize host interface character device */
	ret = init_host_interface();
	if (ret) {
		nnp_log_err(START_UP_LOG, "Failed to init host chardev interface\n");
		ret = -ENODEV;
		goto nnpdrv_chardev_cleanup;
	}

	ret = nnpdrv_pci_init(&nnp_dev_callbacks);
	if (ret) {
		nnp_log_err(START_UP_LOG, "Failed to init pcie\n");
		ret = -ENODEV;
		goto host_cleanup;
	}

	nnp_log_info(START_UP_LOG, "SPH host driver is up\n");

	return 0;

host_cleanup:
	release_host_interface();
nnpdrv_chardev_cleanup:
	nnpdev_device_chardev_cleanup();
err_return:
	debugfs_remove_recursive(g_debugfs_dir);
	return ret;
}

void nnpdrv_cleanup(void)
{
	nnp_log_debug(START_UP_LOG, "Cleaning Up the Module\n");

	nnpdrv_hw_cleanup();

	nnpdrv_bootimage_fini();
	release_host_interface();

	nnpdev_device_chardev_cleanup();
	ida_destroy(&g_nnp_dev_ida);
	debugfs_remove_recursive(g_debugfs_dir);
}

module_init(nnpdrv_init_module);
module_exit(nnpdrv_cleanup);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SpringHill Host Driver");
MODULE_AUTHOR("Intel Corporation");
#ifdef NNP_VERSION
MODULE_VERSION(__stringify(NNP_VERSION));
#endif
#if defined(DEBUG) && defined(GIT_HASH)
MODULE_INFO(git_hash, __stringify(gh.GIT_HASH));
#endif
MODULE_FIRMWARE(NNP_FIRMWARE_NAME);
