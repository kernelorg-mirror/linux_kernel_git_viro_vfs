/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FILENAME_H
#define _LINUX_FILENAME_H

#include <linux/build_bug.h>
#include <linux/compiler_types.h>

struct audit_names;
struct filename {
	const char		*name;	/* pointer to actual string */
	const __user char	*uptr;	/* original userland pointer */
	atomic_t		refcnt;
	struct audit_names	*aname;
	const char		iname[];
};
static_assert(offsetof(struct filename, iname) % sizeof(long) == 0);

#endif /* _LINUX_FILENAME_H */
