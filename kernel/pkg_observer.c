// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/fsnotify_backend.h>
#include <linux/slab.h>
#include <linux/rculist.h>
#include <linux/version.h>
#include "klog.h" // IWYU pragma: keep
#include "throne_tracker.h"

#define MASK_SYSTEM (FS_CREATE | FS_MOVE | FS_EVENT_ON_CHILD)

struct watch_dir {
	const char *path;
	u32 mask;
	struct path kpath;
	struct inode *inode;
	struct fsnotify_mark *mark;
};

static struct fsnotify_group *g;

static int ksu_handle_inode_event(struct fsnotify_mark *mark, u32 mask,
                                  struct inode *inode, struct inode *dir,
                                  const struct qstr *file_name, u32 cookie)
{
    if (!file_name)
        return 0;
    if (mask & FS_ISDIR)
        return 0;
    if (file_name->len == 13 && !memcmp(file_name->name, "packages.list", 13)) {
        pr_info("packages.list detected: %d\n", mask);
        track_throne(false);
    }
    return 0;
}

static const struct fsnotify_ops ksu_ops = {
	.handle_inode_event = ksu_handle_inode_event,
};

static int add_mark_on_inode(struct inode *inode, u32 mask,
                             struct fsnotify_mark **out)
{
	struct fsnotify_mark *m;

	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return -ENOMEM;

	fsnotify_init_mark(m, g);
	m->mask = mask;

	if (fsnotify_add_inode_mark(m, inode, 0)) {
		fsnotify_put_mark(m);
		return -EINVAL;
	}
	*out = m;
	return 0;
}

static int watch_one_dir(struct watch_dir *wd)
{
	int ret = kern_path(wd->path, LOOKUP_FOLLOW, &wd->kpath);
	if (ret) {
		pr_info("path not ready: %s (%d)\n", wd->path, ret);
		return ret;
	}
	wd->inode = d_inode(wd->kpath.dentry);
	ihold(wd->inode);

	ret = add_mark_on_inode(wd->inode, wd->mask, &wd->mark);
	if (ret) {
		pr_err("Add mark failed for %s (%d)\n", wd->path, ret);
		path_put(&wd->kpath);
		iput(wd->inode);
		wd->inode = NULL;
		return ret;
	}
	pr_info("watching %s\n", wd->path);
	return 0;
}

static void unwatch_one_dir(struct watch_dir *wd)
{
	if (wd->mark) {
		fsnotify_destroy_mark(wd->mark, g);
		fsnotify_put_mark(wd->mark);
		wd->mark = NULL;
	}
	if (wd->inode) {
		iput(wd->inode);
		wd->inode = NULL;
	}
	if (wd->kpath.dentry) {
		path_put(&wd->kpath);
		memset(&wd->kpath, 0, sizeof(wd->kpath));
	}
}

static struct watch_dir g_watch = { .path = "/data/system",
                                    .mask = MASK_SYSTEM };

int ksu_observer_init(void)
{
	int ret = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	g = fsnotify_alloc_group(&ksu_ops, 0);
#else
	g = fsnotify_alloc_group(&ksu_ops);
#endif
	if (IS_ERR(g))
		return PTR_ERR(g);

	ret = watch_one_dir(&g_watch);
	pr_info("observer init done\n");
	return 0;
}

void ksu_observer_exit(void)
{
	if (!g || IS_ERR(g))
		return;

	/*
	 * Do NOT destroy the fsnotify group or marks.  On this platform,
	 * fsnotify_destroy_group() lacks fsnotify_wait_marks_destroyed():
	 * destroying marks queues fsnotify_mark_destroy_workfn as a delayed
	 * work that accesses group fields (mark_mutex, ops, etc.) AFTER
	 * fsnotify_put_group() has already freed the group struct.
	 *
	 * Every combination of flush_workqueue / reorder / sleep failed
	 * because flush_workqueue cannot flush delayed works whose timer
	 * hasn't expired, and we have no access to the internal reaper_work
	 * struct needed for flush_delayed_work.
	 *
	 * Instead, disable event delivery and intentionally leak:
	 *  - Zero the mark mask so events skip our mark
	 *  - Set group->shutdown so fsnotify_handle_event returns early
	 *    (checked BEFORE group->ops is dereferenced)
	 *  - Leak the group, mark, inode ref, and path ref (~1 KB total)
	 *
	 * Since no mark refcount reaches zero, the delayed reaper is never
	 * triggered for our mark, eliminating the race entirely.
	 * Leaked memory is reclaimed on reboot.
	 */
	if (g_watch.mark)
		WRITE_ONCE(g_watch.mark->mask, 0);

	spin_lock(&g->notification_lock);
	g->shutdown = true;
	spin_unlock(&g->notification_lock);

	g = NULL;
	g_watch.mark = NULL;
	g_watch.inode = NULL;
	memset(&g_watch.kpath, 0, sizeof(g_watch.kpath));
	pr_info("observer exit done\n");
}
