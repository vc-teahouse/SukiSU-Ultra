#include <linux/version.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#include <linux/sched/task.h>
#include <linux/uaccess.h>
#include "klog.h" // IWYU pragma: keep
#include "kernel_compat.h"

extern struct task_struct init_task;

// mnt_ns context switch for environment that android_init->nsproxy->mnt_ns != init_task.nsproxy->mnt_ns, such as WSA
struct ksu_ns_fs_saved {
	struct nsproxy *ns;
	struct fs_struct *fs;
};

static void ksu_save_ns_fs(struct ksu_ns_fs_saved *ns_fs_saved)
{
	ns_fs_saved->ns = current->nsproxy;
	ns_fs_saved->fs = current->fs;
}

static void ksu_load_ns_fs(struct ksu_ns_fs_saved *ns_fs_saved)
{
	current->nsproxy = ns_fs_saved->ns;
	current->fs = ns_fs_saved->fs;
}

static bool android_context_saved_checked = false;
static bool android_context_saved_enabled = false;
static struct ksu_ns_fs_saved android_context_saved;

void ksu_android_ns_fs_check()
{
	if (android_context_saved_checked)
		return;
	android_context_saved_checked = true;
	task_lock(current);
	if (current->nsproxy && current->fs &&
	    current->nsproxy->mnt_ns != init_task.nsproxy->mnt_ns) {
		android_context_saved_enabled = true;
#ifdef CONFIG_KSU_DEBUG
		pr_info("android context saved enabled due to init mnt_ns(%p) != android mnt_ns(%p)\n",
			current->nsproxy->mnt_ns, init_task.nsproxy->mnt_ns);
#endif
		ksu_save_ns_fs(&android_context_saved);
	} else {
		pr_info("android context saved disabled\n");
	}
	task_unlock(current);
}

struct file *ksu_filp_open_compat(const char *filename, int flags, umode_t mode)
{
	// switch mnt_ns even if current is not wq_worker, to ensure what we open is the correct file in android mnt_ns, rather than user created mnt_ns
	struct ksu_ns_fs_saved saved;
	if (android_context_saved_enabled) {
#ifdef CONFIG_KSU_DEBUG
		pr_info("start switch current nsproxy and fs to android context\n");
#endif
		task_lock(current);
		ksu_save_ns_fs(&saved);
		ksu_load_ns_fs(&android_context_saved);
		task_unlock(current);
	}
	struct file *fp = filp_open(filename, flags, mode);
	if (android_context_saved_enabled) {
		task_lock(current);
		ksu_load_ns_fs(&saved);
		task_unlock(current);
#ifdef CONFIG_KSU_DEBUG
		pr_info("switch current nsproxy and fs back to saved successfully\n");
#endif
	}
	return fp;
}

ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count,
			       loff_t *pos)
{
	return kernel_read(p, buf, count, pos);
}

ssize_t ksu_kernel_write_compat(struct file *p, const void *buf, size_t count,
				loff_t *pos)
{
	return kernel_write(p, buf, count, pos);
}

long ksu_strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr,
				   long count)
{
	return strncpy_from_user_nofault(dst, unsafe_addr, count);
}

int ksu_vfs_unlink(struct inode *dir, struct dentry *dentry)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    struct inode *delegated_inode = NULL;
    return vfs_unlink(&nop_mnt_idmap, dir, dentry, &delegated_inode);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    struct inode *delegated_inode = NULL;
    return vfs_unlink(&init_user_ns, dir, dentry, &delegated_inode);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    struct inode *delegated_inode = NULL;
    return vfs_unlink(dir, dentry, &delegated_inode);
#else
    return vfs_unlink(dir, dentry);
#endif
}

int ksu_vfs_rename(struct inode *old_dir, struct dentry *old_dentry,
                   struct inode *new_dir, struct dentry *new_dentry)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    struct renamedata rd = {
        .old_dir = old_dir,
        .old_dentry = old_dentry,
        .new_dir = new_dir,
        .new_dentry = new_dentry,
        .delegated_inode = NULL,
        .flags = 0,
    };
    return vfs_rename(&rd);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    struct inode *delegated_inode = NULL;
    return vfs_rename(old_dir, old_dentry, new_dir, new_dentry, &delegated_inode, 0);
#else
    return vfs_rename(old_dir, old_dentry, new_dir, new_dentry);
#endif
}
