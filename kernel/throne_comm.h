#ifndef __KSU_H_THRONE_COMM
#define __KSU_H_THRONE_COMM

void ksu_request_userspace_scan(void);

void ksu_handle_userspace_update(void);

int ksu_throne_comm_init(void);

void ksu_throne_comm_exit(void);

#endif