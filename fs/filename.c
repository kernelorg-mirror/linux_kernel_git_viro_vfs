// SPDX-License-Identifier: GPL-2.0
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/filename.h>
#include <linux/namei.h>
#include <linux/uaccess.h>
#include <linux/audit.h>

/* In order to reduce some races, while at the same time doing additional
 * checking and hopefully speeding things up, we copy filenames to the
 * kernel data space before using them..
 *
 * POSIX.1 2.4: an empty pathname is invalid (ENOENT).
 * PATH_MAX includes the nul terminator --RR.
 */

#define EMBEDDED_NAME_MAX	(PATH_MAX - offsetof(struct __filename, iname))

struct filename *
getname_flags(const char __user *filename, int flags)
{
	struct __filename *full;
	struct filename *result;
	char *kname;
	int len;

	result = audit_reusename(filename);
	if (result)
		return result;

	full = __getname();
	if (unlikely(!full))
		return ERR_PTR(-ENOMEM);

	result = &full->public;
	/*
	 * First, try to embed the struct filename inside the names_cache
	 * allocation
	 */
	kname = (char *)full->iname;
	result->name = kname;

	len = strncpy_from_user(kname, filename, EMBEDDED_NAME_MAX);
	/*
	 * Handle both empty path and copy failure in one go.
	 */
	if (unlikely(len <= 0)) {
		if (unlikely(len < 0)) {
			__putname(full);
			return ERR_PTR(len);
		}

		/* The empty path is special. */
		if (!(flags & LOOKUP_EMPTY)) {
			__putname(full);
			return ERR_PTR(-ENOENT);
		}
	}

	/*
	 * Uh-oh. We have a name that's approaching PATH_MAX. Allocate a
	 * separate struct filename so we can dedicate the entire
	 * names_cache allocation for the pathname, and re-do the copy from
	 * userland.
	 */
	if (unlikely(len == EMBEDDED_NAME_MAX)) {
		const size_t size = offsetof(struct __filename, iname[1]);
		kname = (char *)full;

		/*
		 * size is chosen that way we to guarantee that
		 * result->iname[0] is within the same object and that
		 * kname can't be equal to result->iname, no matter what.
		 */
		full = kzalloc(size, GFP_KERNEL);
		if (unlikely(!full)) {
			__putname(kname);
			return ERR_PTR(-ENOMEM);
		}
		result = &full->public;
		result->name = kname;
		len = strncpy_from_user(kname, filename, PATH_MAX);
		if (unlikely(len < 0)) {
			__putname(kname);
			kfree(full);
			return ERR_PTR(len);
		}
		/* The empty path is special. */
		if (unlikely(!len) && !(flags & LOOKUP_EMPTY)) {
			__putname(kname);
			kfree(full);
			return ERR_PTR(-ENOENT);
		}
		if (unlikely(len == PATH_MAX)) {
			__putname(kname);
			kfree(full);
			return ERR_PTR(-ENAMETOOLONG);
		}
	}

	atomic_set(&full->refcnt, 1);
	full->uptr = filename;
	full->aname = NULL;
	audit_getname(result);
	return result;
}

struct filename *getname_uflags(const char __user *filename, int uflags)
{
	int flags = (uflags & AT_EMPTY_PATH) ? LOOKUP_EMPTY : 0;

	return getname_flags(filename, flags);
}

struct filename *getname(const char __user * filename)
{
	return getname_flags(filename, 0);
}

struct filename *__getname_maybe_null(const char __user *pathname)
{
	struct filename *name;
	char c;

	/* try to save on allocations; loss on um, though */
	if (get_user(c, pathname))
		return ERR_PTR(-EFAULT);
	if (!c)
		return NULL;

	name = getname_flags(pathname, LOOKUP_EMPTY);
	if (!IS_ERR(name) && !(name->name[0])) {
		putname(name);
		name = NULL;
	}
	return name;
}

struct filename *getname_kernel(const char * filename)
{
	struct __filename *full;
	struct filename *result;
	int len = strlen(filename) + 1;

	full = __getname();
	if (unlikely(!full))
		return ERR_PTR(-ENOMEM);

	result = &full->public;
	if (len <= EMBEDDED_NAME_MAX) {
		result->name = (char *)full->iname;
	} else if (len <= PATH_MAX) {
		const size_t size = offsetof(struct __filename, iname[1]);
		struct __filename *tmp;

		tmp = kmalloc(size, GFP_KERNEL);
		if (unlikely(!tmp)) {
			__putname(full);
			return ERR_PTR(-ENOMEM);
		}
		tmp->public.name = (char *)full;
		full = tmp;
		result = &full->public;
	} else {
		__putname(full);
		return ERR_PTR(-ENAMETOOLONG);
	}
	memcpy((char *)result->name, filename, len);
	full->uptr = NULL;
	full->aname = NULL;
	atomic_set(&full->refcnt, 1);
	audit_getname(result);

	return result;
}
EXPORT_SYMBOL(getname_kernel);

void putname(struct filename *name)
{
	struct __filename *full;

	if (IS_ERR_OR_NULL(name))
		return;

	full = __filename_full(name);
	if (WARN_ON_ONCE(!atomic_read(&full->refcnt)))
		return;

	if (!atomic_dec_and_test(&full->refcnt))
		return;

	if (name->name != full->iname) {
		__putname(name->name);
		kfree(full);
	} else
		__putname(full);
}
EXPORT_SYMBOL(putname);
