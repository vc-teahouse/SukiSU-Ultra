kernelsu-objs := ksu.o
kernelsu-objs += allowlist.o
kernelsu-objs += dynamic_manager.o
kernelsu-objs += apk_sign.o
kernelsu-objs += sucompat.o
kernelsu-objs += core_hook.o
kernelsu-objs += ksud.o
kernelsu-objs += embed_ksud.o
kernelsu-objs += kernel_compat.o
kernelsu-objs += throne_comm.o

ifeq ($(CONFIG_KSU_TRACEPOINT_HOOK), y)
kernelsu-objs += ksu_trace.o
endif

ifeq ($(CONFIG_KSU_THRONE_TRACKER_LEGACY),y)
$(info -- KernelSU/compat: using legacy throne tracker)
kernelsu-objs += throne_tracker_legacy.o
else
$(info -- KernelSU/compat: using new throne tracker)
kernelsu-objs += throne_tracker.o
endif

kernelsu-objs += selinux/selinux.o
kernelsu-objs += selinux/sepolicy.o
kernelsu-objs += selinux/rules.o

ccflags-y += -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include
ccflags-y += -I$(objtree)/security/selinux -include $(srctree)/include/uapi/asm-generic/errno.h

obj-$(CONFIG_KSU) += kernelsu.o
obj-$(CONFIG_KSU_TRACEPOINT_HOOK) += ksu_trace_export.o

obj-$(CONFIG_KPM) += kpm/

REPO_OWNER := SukiSU-Ultra
REPO_NAME := SukiSU-Ultra
REPO_BRANCH := main
KSU_VERSION_API := 3.2.0

GIT_BIN := /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin git
CURL_BIN := /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin curl

KSU_GITHUB_VERSION := $(shell $(CURL_BIN) -s "https://api.github.com/repos/$(REPO_OWNER)/$(REPO_NAME)/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
KSU_GITHUB_VERSION_COMMIT := $(shell $(CURL_BIN) -sI "https://api.github.com/repos/$(REPO_OWNER)/$(REPO_NAME)/commits?sha=$(REPO_BRANCH)&per_page=1" | grep -i "link:" | sed -n 's/.*page=\([0-9]*\)>; rel="last".*/\1/p')

LOCAL_GIT_EXISTS := $(shell test -e $(srctree)/$(src)/../.git && echo 1 || echo 0)

define get_ksu_version_full
v$1-$(shell cd $(srctree)/$(src); $(GIT_BIN) rev-parse --short=8 HEAD)@$(shell cd $(srctree)/$(src); $(GIT_BIN) rev-parse --abbrev-ref HEAD)
endef

ifeq ($(KSU_GITHUB_VERSION_COMMIT),)
  ifeq ($(LOCAL_GIT_EXISTS),1)
    $(shell cd $(srctree)/$(src); [ -f ../.git/shallow ] && $(GIT_BIN) fetch --unshallow)
    KSU_LOCAL_VERSION := $(shell cd $(srctree)/$(src); $(GIT_BIN) rev-list --count $(REPO_BRANCH))
    KSU_VERSION := $(shell expr 10000 + $(KSU_LOCAL_VERSION) + 700)
    $(info -- $(REPO_NAME) version (local .git): $(KSU_VERSION))
  else
    KSU_VERSION := 13000
    $(warning -- Could not fetch version online or via local .git! Using fallback version: $(KSU_VERSION))
  endif
else
  KSU_VERSION := $(shell expr 10000 + $(KSU_GITHUB_VERSION_COMMIT) + 700)
  $(info -- $(REPO_NAME) version (GitHub): $(KSU_VERSION))
endif

ifeq ($(KSU_GITHUB_VERSION),)
  ifeq ($(LOCAL_GIT_EXISTS),1)
    $(shell cd $(srctree)/$(src); [ -f ../.git/shallow ] && $(GIT_BIN) fetch --unshallow)
    KSU_VERSION_FULL := $(call get_ksu_version_full,$(KSU_VERSION_API))
    $(info -- $(REPO_NAME) version (local .git): $(KSU_VERSION_FULL))
    $(info -- $(REPO_NAME) Formatted version (local .git): $(KSU_VERSION))
  else
    KSU_VERSION_FULL := v$(KSU_VERSION_API)-$(REPO_NAME)-unknown@unknown
    $(warning -- $(REPO_NAME) version: $(KSU_VERSION_FULL))
  endif
else
  $(shell cd $(srctree)/$(src); [ -f ../.git/shallow ] && $(GIT_BIN) fetch --unshallow)
  KSU_VERSION_FULL := $(call get_ksu_version_full,$(KSU_GITHUB_VERSION))
  $(info -- $(REPO_NAME) version (Github): $(KSU_VERSION_FULL))
endif

ccflags-y += -DKSU_VERSION=$(KSU_VERSION)
ccflags-y += -DKSU_VERSION_FULL=\"$(KSU_VERSION_FULL)\"

# Checks hooks state
ifeq ($(CONFIG_KSU_KPROBES_HOOK), y)
$(info -- SukiSU: CONFIG_KSU_KPROBES_HOOK)
else ifeq ($(CONFIG_KSU_TRACEPOINT_HOOK), y)
$(info -- SukiSU: CONFIG_KSU_TRACEPOINT_HOOK)
else ifeq ($(CONFIG_KSU_MANUAL_HOOK), y)
$(info -- SukiSU: CONFIG_KSU_MANUAL_HOOK)
endif

# SELinux drivers check
ifeq ($(shell grep -q "current_sid(void)" $(srctree)/security/selinux/include/objsec.h; echo $$?),0)
ccflags-y += -DKSU_COMPAT_HAS_CURRENT_SID
endif
ifeq ($(shell grep -q "struct selinux_state " $(srctree)/security/selinux/include/security.h; echo $$?),0)
ccflags-y += -DKSU_COMPAT_HAS_SELINUX_STATE
endif

# Handle optional backports
ifeq ($(shell grep -q "strncpy_from_user_nofault" $(srctree)/include/linux/uaccess.h; echo $$?),0)
ccflags-y += -DKSU_OPTIONAL_STRNCPY
endif
ifeq ($(shell grep -q "ssize_t kernel_read" $(srctree)/fs/read_write.c; echo $$?),0)
ccflags-y += -DKSU_OPTIONAL_KERNEL_READ
endif
ifeq ($(shell grep "ssize_t kernel_write" $(srctree)/fs/read_write.c | grep -q "const void" ; echo $$?),0)
ccflags-y += -DKSU_OPTIONAL_KERNEL_WRITE
endif
ifeq ($(shell grep -q "inode_security_struct\s\+\*selinux_inode" $(srctree)/security/selinux/include/objsec.h; echo $$?),0)
ccflags-y += -DKSU_OPTIONAL_SELINUX_INODE
endif
ifeq ($(shell grep -q "int\s\+path_umount" $(srctree)/fs/namespace.c; echo $$?),0)
ccflags-y += -DKSU_HAS_PATH_UMOUNT
endif
# Checks Samsung UH drivers
ifeq ($(shell grep -q "CONFIG_KDP_CRED" $(srctree)/kernel/cred.c; echo $$?),0)
ccflags-y += -DSAMSUNG_UH_DRIVER_EXIST
endif

# Samsung SELinux Porting
ifeq ($(shell grep -q "SEC_SELINUX_PORTING_COMMON" $(srctree)/security/selinux/avc.c; echo $$?),0)
ccflags-y += -DSAMSUNG_SELINUX_PORTING
endif

# Check new vfs_getattr()
ifeq ($(shell grep -A1 "^int vfs_getattr" $(srctree)/fs/stat.c | grep -q "query_flags" ; echo $$?),0)
$(info -- KernelSU/compat: new vfs_getattr() found)
ccflags-y += -DKSU_HAS_NEW_VFS_GETATTR
endif

# Function proc_ops check
ifeq ($(shell grep -q "struct proc_ops " $(srctree)/include/linux/proc_fs.h; echo $$?),0)
ccflags-y += -DKSU_COMPAT_HAS_PROC_OPS
endif

# Custom Signs
ifdef KSU_EXPECTED_SIZE
ccflags-y += -DEXPECTED_SIZE=$(KSU_EXPECTED_SIZE)
$(info -- Custom KernelSU Manager signature size: $(KSU_EXPECTED_SIZE))
endif
ifdef KSU_EXPECTED_HASH
ccflags-y += -DEXPECTED_HASH=\"$(KSU_EXPECTED_HASH)\"
$(info -- Custom KernelSU Manager signature hash: $(KSU_EXPECTED_HASH))
endif

ifdef KSU_MANAGER_PACKAGE
ccflags-y += -DKSU_MANAGER_PACKAGE=\"$(KSU_MANAGER_PACKAGE)\"
$(info -- SukiSU Manager package name: $(KSU_MANAGER_PACKAGE))
endif

$(info -- Supported Unofficial Manager: 5ec1cff (GKI) ShirkNeko udochina (GKI and KPM))
# Kernel version check
KERNEL_VERSION := $(VERSION).$(PATCHLEVEL)
KERNEL_TYPE := Non-GKI
# Check for GKI 2.0 (5.10+ or 6.x+)
ifneq ($(shell test \( $(VERSION) -ge 5 -a $(PATCHLEVEL) -ge 10 \) -o $(VERSION) -ge 6; echo $$?),0)
# Check for GKI 1.0 (5.4)
ifeq ($(shell test $(VERSION)-$(PATCHLEVEL) = 5-4; echo $$?),0)
KERNEL_TYPE := GKI 1.0
endif
else
KERNEL_TYPE := GKI 2.0
endif
$(info -- KERNEL_VERSION: $(KERNEL_VERSION))
$(info -- KERNEL_TYPE: $(KERNEL_TYPE))

$(info -- KERNEL_VERSION: $(KERNEL_VERSION))
ifeq ($(CONFIG_KPM), y)
$(info -- KPM is enabled)
else
$(info -- KPM is disabled)
endif

ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function

## For non-gki compatiblity ##
ifeq ($(shell grep -q " current_sid(void)" $(srctree)/security/selinux/include/objsec.h; echo $$?),0)
ccflags-y += -DKSU_COMPAT_HAS_CURRENT_SID
endif

ifeq ($(shell grep -q "struct selinux_state " $(srctree)/security/selinux/include/security.h; echo $$?),0)
ccflags-y += -DKSU_COMPAT_HAS_SELINUX_STATE
endif

ccflags-y += -DKSU_UMOUNT
ifneq ($(shell grep -Eq "get_cred_rcu" $(srctree)/include/linux/cred.h; echo $$?),0)
$(info -- KSU_SUSFS: adding function 'static inline const struct cred *get_cred_rcu();' to $(srctree)/include/linux/cred.h)
GET_CRED_RCU = static inline const struct cred *get_cred_rcu(const struct cred *cred)\n\
{\n\t\
	struct cred *nonconst_cred = (struct cred *) cred;\n\t\
	if (!cred)\n\t\t\
		return NULL;\n\t\
	if (!atomic_inc_not_zero(&nonconst_cred->usage))\n\t\t\
		return NULL;\n\t\
	validate_creds(cred);\n\t\
	return cred;\n\
}\n
$(shell sed -i '/^static inline void put_cred/i $(GET_CRED_RCU)' $(srctree)/include/linux/cred.h;)
endif

ifneq ($(shell grep -Eq "^static int can_umount" $(srctree)/fs/namespace.c; echo $$?),0)
$(info -- KSU_SUSFS: adding function 'static int can_umount(const struct path *path, int flags);' to $(srctree)/fs/namespace.c)
CAN_UMOUNT = static int can_umount(const struct path *path, int flags)\n\
{\n\t\
        struct mount *mnt = real_mount(path->mnt);\n\t\
        if (flags & ~(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW))\n\t\t\
                return -EINVAL;\n\t\
        if (!may_mount())\n\t\t\
                return -EPERM;\n\t\
        if (path->dentry != path->mnt->mnt_root)\n\t\t\
                return -EINVAL;\n\t\
        if (!check_mnt(mnt))\n\t\t\
                return -EINVAL;\n\t\
        if (mnt->mnt.mnt_flags & MNT_LOCKED)\n\t\t\
                return -EINVAL;\n\t\
        if (flags & MNT_FORCE && !capable(CAP_SYS_ADMIN))\n\t\t\
                return -EPERM;\n\t\
        return 0;\n\
}\n
$(shell sed -i '/^static bool is_mnt_ns_file/i $(CAN_UMOUNT)' $(srctree)/fs/namespace.c;)
endif

ifneq ($(shell grep -Eq "^int path_umount" $(srctree)/fs/namespace.c; echo $$?),0)
$(info -- KSU_SUSFS: adding function 'int path_umount(struct path *path, int flags);' to $(srctree)/fs/namespace.c)
PATH_UMOUNT = int path_umount(struct path *path, int flags)\n\
{\n\t\
        struct mount *mnt = real_mount(path->mnt);\n\t\
        int ret;\n\t\
        ret = can_umount(path, flags);\n\t\
        if (!ret)\n\t\t\
                ret = do_umount(mnt, flags);\n\t\
        dput(path->dentry);\n\t\
        mntput_no_expire(mnt);\n\t\
        return ret;\n\
}\n
$(shell sed -i '/^static bool is_mnt_ns_file/i $(PATH_UMOUNT)' $(srctree)/fs/namespace.c;)
endif

ifneq ($(shell grep -Eq "^int path_umount" $(srctree)/fs/internal.h; echo $$?),0)
$(shell sed -i '/^extern void __init mnt_init/a int path_umount(struct path *path, int flags);' $(srctree)/fs/internal.h;)
$(info -- KSU_SUSFS: adding 'int path_umount(struct path *path, int flags);' to $(srctree)/fs/internal.h)
endif

## For susfs stuff ##
ifeq ($(shell test -e $(srctree)/fs/susfs.c; echo $$?),0)
$(eval SUSFS_VERSION=$(shell cat $(srctree)/include/linux/susfs.h | grep -E '^#define SUSFS_VERSION' | cut -d' ' -f3 | sed 's/"//g'))
$(info )
$(info -- SUSFS_VERSION: $(SUSFS_VERSION))
else
$(info -- You have not integrate susfs in your kernel.)
$(info -- Read: https://gitlab.com/simonpunk/susfs4ksu)
endif
# Keep a new line here!! Because someone may append config
