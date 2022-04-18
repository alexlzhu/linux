/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates
 */
#ifndef _LINUX_NETLINK_DEBUG
#define _LINUX_NETLINK_DEBUG

struct sock;
struct nlmsghdr;
struct ifreq;

void record_msg(const struct sock *sk, const struct nlmsghdr *msg_header);
void record_ifr(unsigned int cmd, const struct ifreq *ifr);

#endif /* _LINUX_NETLINK_DEBUG */
