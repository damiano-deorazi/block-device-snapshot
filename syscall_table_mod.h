#ifndef _SYSCALLTABLE_MOD_H
#define _SYSCALLTABLE_MOD_H

int modify_syscall_table(unsigned long my_syscalls[], unsigned long syscall_table_addr, unsigned long ni_syscalls_addr, int restore[]);

int restore_syscall_table(unsigned long syscall_table_addr, unsigned long ni_syscalls_addr, int restore[]);

#endif