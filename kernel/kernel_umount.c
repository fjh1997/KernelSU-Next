#include <linux/sched.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

#include "kernel_umount.h"
#include "klog.h" // IWYU pragma: keep
#include "allowlist.h"
#include "selinux/selinux.h"
#include "feature.h"
#include "ksud.h"
#include "ksu.h"

static bool ksu_kernel_umount_enabled = true;

static int kernel_umount_feature_get(u64 *value)
{
	*value = ksu_kernel_umount_enabled ? 1 : 0;
	return 0;
}

static int kernel_umount_feature_set(u64 value)
{
	bool enable = value != 0;
	ksu_kernel_umount_enabled = enable;
	pr_info("kernel_umount: set to %d\n", enable);
	return 0;
}

static const struct ksu_feature_handler kernel_umount_handler = {
	.feature_id = KSU_FEATURE_KERNEL_UMOUNT,
	.name = "kernel_umount",
	.get_handler = kernel_umount_feature_get,
	.set_handler = kernel_umount_feature_set,
};

extern int path_umount(struct path *path, int flags);

static void ksu_umount_mnt(struct path *path, int flags)
{
	int err = path_umount(path, flags);
	if (err) {
		pr_info("umount %s failed: %d\n", path->dentry->d_iname, err);
	}
}

static void try_umount(const char *mnt, int flags)
{
	struct path path;
	int err = kern_path(mnt, 0, &path);
	if (err) {
		return;
	}

	if (path.dentry != path.mnt->mnt_root) {
		// it is not root mountpoint, maybe umounted by others already.
		path_put(&path);
		return;
	}

    ksu_umount_mnt(&path, flags);
}

struct umount_tw {
	struct callback_head cb;
};

static void umount_tw_func(struct callback_head *cb)
{
	struct umount_tw *tw = container_of(cb, struct umount_tw, cb);
	const struct cred *saved = override_creds(ksu_cred);

    struct mount_entry *entry;
    down_read(&mount_list_lock);
    list_for_each_entry (entry, &mount_list, list) {
        pr_info("%s: unmounting: %s flags 0x%x\n", __func__, entry->umountable,
                entry->flags);
        try_umount(entry->umountable, entry->flags);
    }
    up_read(&mount_list_lock);

	revert_creds(saved);

	kfree(tw);
	module_put(THIS_MODULE); /* Release module ref taken before task_work_add */
}

int ksu_handle_umount(uid_t old_uid, uid_t new_uid)
{
	struct umount_tw *tw;

	// if there isn't any module mounted, just ignore it!
	if (!ksu_module_mounted) {
		return 0;
	}

	if (!ksu_kernel_umount_enabled) {
		return 0;
	}

	if (!ksu_cred) {
		return 0;
	}

    // There are 5 scenarios:
    // 1. Normal app: zygote -> appuid
    // 2. Isolated process forked from zygote: zygote -> isolated_process
    // 3. App zygote forked from zygote: zygote -> appuid
    // 4. Isolated process froked from app zygote: appuid -> isolated_process (already handled by 3)
    // 5. Isolated process froked from webview zygote (no need to handle, app cannot run custom code)
    if (!is_appuid(new_uid) && !is_isolated_process(new_uid)) {
        return 0;
    }

	if (!ksu_uid_should_umount(new_uid) && !is_isolated_process(new_uid)) {
		return 0;
	}

	// check old process's selinux context, if it is not zygote, ignore it!
	// because some su apps may setuid to untrusted_app but they are in global mount namespace
	// when we umount for such process, that is a disaster!
	// also handle case 4 and 5
	bool is_zygote_child = is_zygote(get_current_cred());
	if (!is_zygote_child) {
		pr_info("handle umount ignore non zygote child: %d\n", current->pid);
		return 0;
	}
	// umount the target mnt
	pr_info("handle umount for uid: %d, pid: %d\n", new_uid, current->pid);

	tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
	if (!tw)
		return 0;

	/* Pin module so umount callback code isn't freed before it runs */
	if (!try_module_get(THIS_MODULE)) {
		kfree(tw);
		return 0;
	}

	tw->cb.func = umount_tw_func;

	int err = task_work_add(current, &tw->cb, TWA_RESUME);
	if (err) {
		module_put(THIS_MODULE);
		kfree(tw);
		pr_warn("unmount add task_work failed\n");
	}

	return 0;
}

#define MOUNTINFO_PATH "/proc/1/mountinfo"
#define MOUNTINFO_BUF_SIZE (256 * 1024)
#define MODULE_MOUNT_ROOT "/adb/"
#define UMOUNT_SCAN_RETRIES 10

/*
 * Scan /proc/1/mountinfo for bind mounts whose root path contains
 * "/adb/modules/" and unmount them via MNT_DETACH.
 * Returns true if any module mounts were found (and unmount attempted).
 */
static bool umount_module_mounts_scan(void)
{
	struct file *fp;
	char *buf;
	loff_t pos = 0;
	ssize_t len;
	bool found = false;

	fp = filp_open(MOUNTINFO_PATH, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		pr_warn("ksu_umount_all: cannot open %s: %ld\n",
			MOUNTINFO_PATH, PTR_ERR(fp));
		return false;
	}

	buf = vmalloc(MOUNTINFO_BUF_SIZE);
	if (!buf) {
		filp_close(fp, NULL);
		return false;
	}

	len = kernel_read(fp, buf, MOUNTINFO_BUF_SIZE - 1, &pos);
	filp_close(fp, NULL);

	if (len <= 0) {
		vfree(buf);
		return false;
	}
	buf[len] = '\0';

	/* Parse each line of mountinfo */
	char *line = buf;
	while (line && *line) {
		char *next_line = strchr(line, '\n');
		if (next_line)
			*next_line++ = '\0';

		/*
		 * mountinfo fields (space-separated):
		 *  [0] mount_id
		 *  [1] parent_id
		 *  [2] major:minor
		 *  [3] root         -- path within the source filesystem
		 *  [4] mount_point  -- where it appears in the VFS
		 *  ...
		 */
		char *p = line;
		char *root = NULL;
		char *mount_point = NULL;
		int i;

		for (i = 0; i < 5 && *p; i++) {
			while (*p == ' ')
				p++;
			if (!*p)
				break;

			char *start = p;
			while (*p && *p != ' ')
				p++;
			if (*p)
				*p++ = '\0';

			if (i == 3)
				root = start;
			else if (i == 4)
				mount_point = start;
		}

		if (root && mount_point &&
		    strstr(root, MODULE_MOUNT_ROOT)) {
			pr_info("ksu_umount_all: scan: %s (root=%s)\n",
				mount_point, root);
			try_umount(mount_point, MNT_DETACH);
			found = true;
		}

		line = next_line;
	}

	vfree(buf);
	return found;
}

/*
 * Repeatedly scan and unmount module mounts until none remain.
 * Multiple passes handle stacked / overlapping mounts.
 */
static void umount_module_mounts(void)
{
	int retries = UMOUNT_SCAN_RETRIES;

	while (retries-- > 0 && umount_module_mounts_scan()) {
		pr_info("ksu_umount_all: rescan (%d retries left)\n", retries);
	}
}

void ksu_umount_all(void)
{
	struct mount_entry *entry;
	const struct cred *saved;

	if (!ksu_module_mounted) {
		pr_info("ksu_umount_all: no modules mounted, skip\n");
		return;
	}

	if (!ksu_cred) {
		pr_warn("ksu_umount_all: no ksu_cred, cannot umount\n");
		return;
	}

	saved = override_creds(ksu_cred);

	/* Step 1: unmount paths from the registered mount list */
	down_read(&mount_list_lock);
	list_for_each_entry(entry, &mount_list, list) {
		pr_info("ksu_umount_all: list: %s flags 0x%x\n",
			entry->umountable, entry->flags);
		try_umount(entry->umountable, entry->flags);
	}
	up_read(&mount_list_lock);

	/* Step 2: scan init namespace for any remaining module mounts */
	umount_module_mounts();

	revert_creds(saved);

	ksu_module_mounted = false;
	pr_info("ksu_umount_all: done\n");
}

void ksu_kernel_umount_init(void)
{
	if (ksu_register_feature_handler(&kernel_umount_handler)) {
		pr_err("Failed to register kernel_umount feature handler\n");
	}
}

void ksu_kernel_umount_exit(void)
{
	ksu_unregister_feature_handler(KSU_FEATURE_KERNEL_UMOUNT);
}
