#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/version.h>
#include <linux/workqueue.h>

#include "allowlist.h"
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

/* Debug helper: write exit progress to a persistent file so we can
 * tell exactly which step crashed even if pstore is unavailable.    */
static struct file *exit_log;
static loff_t exit_log_pos;

static void exit_log_open(void)
{
	exit_log = filp_open("/data/local/tmp/ksu_exit.log",
			     O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0644);
	if (IS_ERR(exit_log))
		exit_log = NULL;
	exit_log_pos = 0;
}

static void exit_log_step(const char *msg)
{
	pr_err("kernelsu_exit: %s\n", msg);
	if (exit_log) {
		kernel_write(exit_log, msg, strlen(msg), &exit_log_pos);
		kernel_write(exit_log, "\n", 1, &exit_log_pos);
	}
}

static void exit_log_close(void)
{
	if (exit_log) {
		filp_close(exit_log, NULL);
		exit_log = NULL;
	}
}

void kernelsu_exit(void)
{
	exit_log_open();
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

	exit_log_step("put_cred");
	if (ksu_cred) {
		put_cred(ksu_cred);
		ksu_cred = NULL;
	}

	/*
	 * put_cred() defers the actual freeing via call_rcu(&cred->rcu,
	 * put_cred_rcu).  The RCU callback put_cred_rcu calls
	 * security_cred_free() which may access data associated with our
	 * module.  rcu_barrier() waits for all pending RCU callbacks to
	 * complete before we return, preventing a use-after-free when
	 * free_module() reclaims our code/data pages.
	 */
	exit_log_step("rcu_barrier_1");
	rcu_barrier();

	/* Sub-exit functions (fops_proxy restore, fput of hooked files) may
	 * have scheduled new delayed fput work.  Flush it, then drain any
	 * new RCU callbacks that the fput work may have queued (e.g. a
	 * put_cred from __fput → security_file_free path).              */
	exit_log_step("final_flush");
	flush_workqueue(system_wq);

	exit_log_step("done");
	exit_log_close();

	/*
	 * Final synchronisation: the flush_workqueue and filp_close above
	 * may have triggered additional put_cred / call_rcu callbacks.
	 * A second rcu_barrier ensures every RCU callback that could
	 * reference our code/data has finished before free_module() runs.
	 */
	rcu_barrier();
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
