/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ALPHA_CHECKSUM_H
#define _ALPHA_CHECKSUM_H

#define _HAVE_ARCH_CSUM_TCPUDP_MAGIC
#define _HAVE_ARCH_COPY_AND_CSUM_FROM_USER
#define _HAVE_ARCH_CSUM_AND_COPY
__wsum_fault csum_and_copy_from_user(const void __user *src, void *dst, int len);

__wsum csum_partial_copy_nocheck(const void *src, void *dst, int len);

#define _HAVE_IP_COMPUTE_CSUM
#define _HAVE_ARCH_IPV6_CSUM

struct in6_addr;
extern __sum16 csum_ipv6_magic(const struct in6_addr *saddr,
			       const struct in6_addr *daddr,
			       __u32 len, __u8 proto, __wsum sum);

#include <asm-generic/checksum.h>

#endif
