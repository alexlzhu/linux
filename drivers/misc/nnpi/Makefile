#
# Copyright (C) 2019 Intel Corporation
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

obj-$(CONFIG_SPH) := sphdrv.o

sphdrv-$(CONFIG_SPH) := \
    nnpdrv_main.o \
    nnpdrv_device_chardev.o \
    nnpdrv_device_sysfs.o \
    nnpdrv_device.o \
    nnpdrv_host.o \
    nnpdrv_hostres.o \
    inf_proc.o \
    nnpdrv_bootimage.o \
    nnpdrv_trace.o \
    nnpdrv_crashlog_debugfs.o \
    ipc_c2h_events.o \
    msg_scheduler.o \
    nnpdrv_cmd_chan.o

sphdrv-$(CONFIG_SPH_HW_LAYER_SPH) += nnpdrv_pcie.o
sphdrv-$(CONFIG_SPH_HW_LAYER_LOCAL) += nnpdrv_hw_sim.o

ccflags-y += \
    -I$(srctree)/drivers/misc/nnpi/uapi \
    -I$(srctree)/drivers/misc/nnpi/host_interface \
    -I$(srctree)/drivers/misc/nnpi/common \
    -I$(srctree)/drivers/misc/nnpi \
    -DTRACE \
    -DHW_LAYER_SPH \
    -Wall -Werror \
    $(SPH_EXTRA_MODULE_COMPILE_FLAGS)

ifneq ($(SPH_VERSION),)
ccflags-y += -DNNP_VERSION=$(SPH_VERSION)
endif
