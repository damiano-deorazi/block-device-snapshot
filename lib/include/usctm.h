#ifndef _USCTM_
#define _USCTM_

void syscall_table_finder(void);

extern unsigned long sys_call_table_address;
extern unsigned long **hacked_syscall_tbl;
extern unsigned long *hacked_ni_syscall;

#endif