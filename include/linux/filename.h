/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FILENAME_H
#define _LINUX_FILENAME_H

#include <linux/build_bug.h>
#include <linux/compiler_types.h>

struct audit_names;
struct filename {
	const char		*name;	/* pointer to actual string */
};

struct __filename {
	struct filename		public;
	const __user char	*uptr;	/* original userland pointer */
	atomic_t		refcnt;
	struct audit_names	*aname;
	const char		iname[];
};
static_assert(offsetof(struct __filename, iname) % sizeof(long) == 0);

static inline struct __filename *__filename_full(struct filename *name)
{
	return container_of(name, struct __filename, public);
}

#endif /* _LINUX_FILENAME_H */
