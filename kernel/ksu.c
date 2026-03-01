#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/signal.h>
#include <linux/pid.h>

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
#include "kernel_umount.h"
#include "selinux/selinux.h"

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

/*
 * Kill all zygote/usap processes so init restarts them from a clean kernel.
 *
 * This MUST be called between ksu_umount_all() and revert_kernelsu_rules():
 *   - After umount: module overlays are removed, so new zygote won't re-mount them
 *   - Before SELinux revert: kernel-level signal is SELinux-exempt anyway, but
 *     the module's hooks are still being torn down, so init cannot restart
 *     zygote until module_exit() completes — guaranteeing the new zygote is clean.
 *
 * User-space cannot solve this timing problem:
 *   - Before rmmod: zygote restarts while module is loaded → gets re-injected
 *   - After rmmod:  revert_kernelsu_rules() has removed SELinux rules for su domain
 *                   → both setprop and kill are denied by SELinux MAC
 */
static void ksu_kill_zygote(void)
{
	struct task_struct *p;

	rcu_read_lock();
	for_each_process(p) {
		const char *name = p->comm;
		if (!strcmp(name, "main") && p->pid == 1)
			continue; /* skip init */
		if (!strcmp(name, "zygote") ||
		    !strcmp(name, "zygote64") ||
		    !strcmp(name, "usap32") ||
		    !strcmp(name, "usap64") ||
		    !strcmp(name, "webview_zygote")) {
			pr_info("kernelsu: killing %s (pid %d) for clean restart\n",
				name, p->pid);
			send_sig(SIGKILL, p, 1);
		}
	}
	rcu_read_unlock();
}

void kernelsu_exit(void)
{
	/* === Root trace cleanup: must happen before subsystem teardown === */

	/* Unmount all module overlays (needs ksu_cred, must be first) */
	ksu_umount_all();



	/* Revert SELinux policy: set su/ksu_file domains to enforcing,
	 * clear all avtab allow rules for these domains */
	revert_kernelsu_rules();

	/* === Normal subsystem teardown === */

	/* Flush delayed fput work so __fput callbacks run while our code lives */
	flush_workqueue(system_wq);

	/* Restore kobject deleted in init to avoid NULL sd in sysfs teardown */
#ifdef MODULE
#ifndef CONFIG_KSU_DEBUG
	if (kobject_add(&THIS_MODULE->mkobj.kobj, NULL,
			"%s", THIS_MODULE->name))
		pr_err("kernelsu: failed to restore module kobject\n");
#endif
#endif

	ksu_allowlist_exit();

	ksu_throne_tracker_exit();

	ksu_observer_exit();

	ksu_ksud_exit();

	ksu_syscall_hook_manager_exit();

	ksu_supercalls_exit();

	ksu_feature_exit();

	/* Leak ksu_cred: revert_creds may put it after our rcu_barrier */
	ksu_cred = NULL;

	rcu_barrier();
	flush_workqueue(system_wq);

	/* Kill zygote/usap LAST — after every hook, tracker, and subsystem
	 * is fully torn down.  init will auto-restart zygote into a kernel
	 * that no longer has any KSU code, guaranteeing a clean process.
	 * send_sig() is a kernel-internal function immune to SELinux MAC,
	 * so it works even after revert_kernelsu_rules(). */
	ksu_kill_zygote();
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
