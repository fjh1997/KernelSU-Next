#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/version.h>
#include <linux/workqueue.h>

#include "allowlist.h"
#include "app_profile.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "throne_tracker.h"
#include "syscall_hook_manager.h"
#include "ksud.h"
#include "supercalls.h"
#include "ksu.h"
#include "file_wrapper.h"

struct cred *ksu_cred;

int __init kernelsu_init(void)
{
#ifdef CONFIG_KSU_DEBUG
	pr_alert("*************************************************************");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("**                                                         **");
	pr_alert("**         You are running KernelSU in DEBUG mode          **");
	pr_alert("**                                                         **");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("*************************************************************");
#endif

    ksu_cred = prepare_creds();
    if (!ksu_cred) {
        pr_err("prepare cred failed!\n");
    }

	ksu_app_profile_init();

	ksu_feature_init();

	ksu_supercalls_init();

	ksu_syscall_hook_manager_init();

	ksu_allowlist_init();

	ksu_throne_tracker_init();

	ksu_ksud_init();

    ksu_file_wrapper_init();

#ifdef MODULE
#ifndef CONFIG_KSU_DEBUG
	kobject_del(&THIS_MODULE->mkobj.kobj);
#endif
#endif
	return 0;
}

extern void ksu_observer_exit(void);

static void exit_log_step(const char *msg)
{
	pr_err("kernelsu_exit: %s\n", msg);
}

void kernelsu_exit(void)
{
	exit_log_step("start");

	/*
	 * Flush pending delayed fput work.  When a process exits while holding
	 * file-wrapper fds, fput() cannot use task_work (the task is exiting)
	 * and falls back to the system workqueue (delayed_fput).  If we proceed
	 * to free module memory before those deferred __fput callbacks run, the
	 * kworker will call f_op->release on freed code and crash.
	 *
	 * Flushing the system workqueue here guarantees that all pending
	 * __fput() calls execute while our code is still in memory.
	 */
	exit_log_step("flush_delayed_fput");
	flush_workqueue(system_wq);

	/*
	 * Restore the module kobject deleted in init.  kobject_del() set
	 * kobj->sd = NULL and kobj->parent = NULL.  Without restoration,
	 * mod_sysfs_teardown → sysfs_remove_group passes NULL sd to
	 * kernfs_find_and_get_ns which dereferences it → fatal oops.
	 *
	 * kobject_add with NULL parent falls back to the kset parent
	 * (module_kset → /sys/module), correctly re-creating the directory.
	 * mod_sysfs_teardown then gets a valid sd: modinfo files and param
	 * groups won't be found under the fresh directory, but those
	 * removal functions handle "not found" gracefully (silent or WARN).
	 */
#ifdef MODULE
#ifndef CONFIG_KSU_DEBUG
	exit_log_step("kobject_add");
	if (kobject_add(&THIS_MODULE->mkobj.kobj, NULL,
			"%s", THIS_MODULE->name))
		pr_err("kernelsu: failed to restore module kobject\n");
#endif
#endif

	exit_log_step("allowlist_exit");
	ksu_allowlist_exit();

	exit_log_step("throne_tracker_exit");
	ksu_throne_tracker_exit();

	exit_log_step("observer_exit");
	ksu_observer_exit();

	exit_log_step("ksud_exit");
	ksu_ksud_exit();

	exit_log_step("syscall_hook_manager_exit");
	ksu_syscall_hook_manager_exit();

	exit_log_step("supercalls_exit");
	ksu_supercalls_exit();

	exit_log_step("feature_exit");
	ksu_feature_exit();

	exit_log_step("detach_cred");
	/*
	 * Intentionally leak ksu_cred (~300 bytes) instead of calling
	 * put_cred().  Other code paths (override_creds/revert_creds in
	 * su_mount_ns, kernel_umount) may still hold references that will
	 * be put after our rcu_barrier, causing put_cred_rcu to run from
	 * the rcuop kthread and access freed module memory.  Leaking the
	 * cred avoids the deferred RCU callback entirely.
	 */
	ksu_cred = NULL;

	/* Drain any pending kfree_rcu callbacks (e.g. allowlist perm_data)
	 * and delayed fput work that sub-exit functions may have queued.  */
	exit_log_step("rcu_barrier");
	rcu_barrier();
	exit_log_step("final_flush");
	flush_workqueue(system_wq);

	exit_log_step("done");
}

module_init(kernelsu_init);
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
