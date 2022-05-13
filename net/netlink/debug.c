// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */
#include <net/netlink_debug.h>

#ifdef CONFIG_NETLINK_DEBUG_RINGBUFFER_SIZE
#include <linux/ktime.h>
#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>
#include <net/sock.h>
#include <uapi/linux/if.h>
#include <uapi/linux/netlink.h>

// ring buffer for recording incoming messages
static unsigned char ring_buffer[CONFIG_NETLINK_DEBUG_RINGBUFFER_SIZE];
static const size_t ring_buffer_len = sizeof(ring_buffer) / sizeof(unsigned char);
static size_t ring_buffer_index;
static int ring_buffer_wrap_count;
static DEFINE_SPINLOCK(ring_buffer_lock);

// copies src_len bytes starting at src pointer into ring buffer
static void netlink_ring_buffer_write(const void *src, size_t src_len)
{
	// bytes to write each loop iteration
	size_t nbytes = 0;

	// loop until src length is depleted, i.e. all src bytes are copied to buffer
	while (src_len > 0) {
		// decide on how many bytes to copy this loop iteration -
		// the lesser of source length or the remaining buffer space
		nbytes = min(src_len, ring_buffer_len - ring_buffer_index);

		// copy into buffer
		memcpy(&ring_buffer[ring_buffer_index], src, nbytes);

		// subtract bytes written from src length
		src_len -= nbytes;
		// move buffer index foward the amount of bytes written
		ring_buffer_index += nbytes;

		// when index reaches the end of buffer, reset the index
		if (ring_buffer_index >= ring_buffer_len) {
			// index should not exceed the buffer length
			WARN_ON(ring_buffer_index > ring_buffer_len);

			ring_buffer_index = 0;
			ring_buffer_wrap_count++;
		}
	}
}

/* record_msg() copies into ring buffer and uses layout and sizes below (not to scale):
 * | msg_header | msg_payload | msg_payload_len | sk_protocol | timestamp |
 * |  nlmsghdr  |    varies   |      int        |    u16      |    s64    |
 *
 * the msg_payload byte count varies in size. the actual value is stored in msg_payload_len.
 * if msg_payload_len is -1, it means the msg_payload size would have caused the total size of all
 * fields to exceed the available buffer size. in these cases, the msg_payload is not recorded
 * but all other fields are.
 * all fields besides msg_payload are fixed size. to read from the buffer, start at
 * ring_buffer_index and moving backward, read the fields above right to left.
 */
void record_msg(const struct sock *sk, const struct nlmsghdr *msg_header)
{
	const ktime_t timestamp = ktime_get_coarse_boottime();
	const void *msg_payload = NLMSG_DATA(msg_header);
	const int msg_header_len = NLMSG_HDRLEN;
	int msg_payload_len = msg_header->nlmsg_len;
	size_t min_record_len = 0;
	size_t max_record_len = 0;

	// min record length is everything with a zero length payload
	min_record_len = msg_header_len + sizeof(msg_payload_len) + sizeof(sk->sk_protocol)
		+ sizeof(timestamp);

	// cannot record when minimum space is not available
	if (min_record_len > ring_buffer_len) {
		pr_warn_once("[netlink] insufficient ring buffer size %zu when at least %zu needed\n",
			     ring_buffer_len, min_record_len);

		return;
	}

	// max record length is everything including the actual payload length
	max_record_len = min_record_len + msg_payload_len;

	spin_lock(&ring_buffer_lock);

	netlink_ring_buffer_write(msg_header, msg_header_len);

	// cannot include payload when maximum space is larger than buffer
	if (max_record_len <= ring_buffer_len)
		netlink_ring_buffer_write(msg_payload, msg_payload_len);
	else
		msg_payload_len = -1;

	netlink_ring_buffer_write(&msg_payload_len, sizeof(msg_payload_len));
	netlink_ring_buffer_write(&sk->sk_protocol, sizeof(sk->sk_protocol));
	netlink_ring_buffer_write(&timestamp, sizeof(timestamp));

	spin_unlock(&ring_buffer_lock);
}

/* record_ifr() writes into ring buffer using layout and sizes below (not to scale):
 * |     cmd      |     ifr      | sk_protocol | timestamp |
 * | unsigned int | struct ifreq |    u16      |    s64    |
 *
 * starting at the ring_buffer_index, reading can be done from right to left.
 * the sk_protocol field is always set to NETLINK_UNUSED to indicate the data should
 * not be treated like a normal netlink message but a command and ifreq struct instead.
 */
void record_ifr(unsigned int cmd, const struct ifreq *ifr)
{
	const u16 sk_protocol = NETLINK_UNUSED;
	const size_t min_record_len = sizeof(cmd) + sizeof(*ifr) + sizeof(sk_protocol)
		+ sizeof(ktime_t);
	const ktime_t timestamp = ktime_get_coarse_boottime();

	// cannot record when minimum space is not available
	if (min_record_len > ring_buffer_len) {
		pr_warn_once("[netdevice] insufficient ring buffer size %zu when at least %zu needed\n",
			     ring_buffer_len, min_record_len);

		return;
	}

	spin_lock(&ring_buffer_lock);

	netlink_ring_buffer_write(&cmd, sizeof(cmd));
	netlink_ring_buffer_write(ifr, sizeof(*ifr));
	netlink_ring_buffer_write(&sk_protocol, sizeof(sk_protocol));
	netlink_ring_buffer_write(&timestamp, sizeof(timestamp));

	spin_unlock(&ring_buffer_lock);
}
#else
void record_msg(const struct sock *sk, const struct nlmsghdr *msg_header)
{
}

void record_ifr(unsigned int cmd, const struct ifreq *ifr)
{
}
#endif
