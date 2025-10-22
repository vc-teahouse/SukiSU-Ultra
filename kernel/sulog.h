#ifndef __KSU_SULOG_H
#define __KSU_SULOG_H

#include <linux/types.h>

void ksu_sulog_report_su_grant(uid_t uid, const char *comm, const char *method);

void ksu_sulog_report_su_attempt(uid_t uid, const char *comm, const char *target_path, bool success);

void ksu_sulog_report_permission_check(uid_t uid, const char *comm, bool allowed);

void ksu_sulog_report_manager_operation(const char *operation, uid_t manager_uid, uid_t target_uid);

void ksu_sulog_set_enabled(bool enabled);
bool ksu_sulog_is_enabled(void);

int ksu_sulog_init(void);
void ksu_sulog_exit(void);

#endif /* __KSU_SULOG_H */