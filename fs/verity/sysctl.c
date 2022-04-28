// SPDX-License-Identifier: GPL-2.0

#include "fsverity_private.h"

#include <linux/sysctl.h>

/*
 * /proc/sys/fs/verity/require_signatures
 * If 1, all verity files must have a valid builtin signature.
 */
int fsverity_require_signatures;
/*
 * /proc/sys/fs/verity/mode
 * If "disable": disable verity, don't verify, fail all ioctls.
 * If "audit": allow ioctls, and run verification logic, but only log on verification failure.
 * If "enforce": fully enforce, verification failure returns errors.
 * default: "enforce"
 */
#define FSVERITY_MODE_LEN 10
static const char * const fsverity_modes[] = {
	"disable",
	"audit",
	"enforce",
	NULL
};
static char fsverity_mode[FSVERITY_MODE_LEN] = "audit";

#ifdef CONFIG_SYSCTL
static struct ctl_table_header *fsverity_sysctl_header;

static const struct ctl_path fsverity_sysctl_path[] = {
	{ .procname = "fs", },
	{ .procname = "verity", },
	{ }
};

static int proc_do_fsverity_mode(struct ctl_table *table, int write,
				 void *buffer, size_t *lenp, loff_t *ppos)
{
	char tmp_mode[FSVERITY_MODE_LEN];
	const char *const *mode = fsverity_modes;
	struct ctl_table tmp = {
		.data = tmp_mode,
		.maxlen = FSVERITY_MODE_LEN,
		.mode = table->mode,
	};
	int ret;

	strncpy(tmp_mode, fsverity_mode, FSVERITY_MODE_LEN);
	ret = proc_dostring(&tmp, write, buffer, lenp, ppos);
	if (write) {
		while (*mode) {
			if (!strcmp(*mode, tmp_mode))
				break;
			++mode;
		}
		if (!*mode)
			ret = -EINVAL;
		else
			strncpy(fsverity_mode, *mode, FSVERITY_MODE_LEN);
	}
	return ret;
}

static struct ctl_table fsverity_sysctl_table[] = {
	{
		.procname       = "require_signatures",
		.data           = &fsverity_require_signatures,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
	{
		.procname       = "mode",
		.data           = fsverity_mode,
		.maxlen         = FSVERITY_MODE_LEN,
		.mode           = 0644,
		.proc_handler   = proc_do_fsverity_mode,
	},
	{ }
};

int __init fsverity_sysctl_init(void)
{
	fsverity_sysctl_header = register_sysctl_paths(fsverity_sysctl_path,
						       fsverity_sysctl_table);
	if (!fsverity_sysctl_header) {
		pr_err("sysctl registration failed!\n");
		return -ENOMEM;
	}
	return 0;
}

void __init fsverity_exit_sysctl(void)
{
	unregister_sysctl_table(fsverity_sysctl_header);
	fsverity_sysctl_header = NULL;
}

bool fsverity_disabled(void)
{
	return !strcmp(fsverity_mode, "disable");
}
bool fsverity_enforced(void)
{
	return !strcmp(fsverity_mode, "enforce");
}
#endif /* !CONFIG_SYSCTL */
