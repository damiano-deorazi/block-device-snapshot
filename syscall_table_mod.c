#include <linux/kernel.h>

#include "lib/include/scth.h"
#include "bd_snapshot.h"
#include "syscall_table_mod.h"

int modify_syscall_table(unsigned long my_syscalls[], unsigned long syscall_table_addr, unsigned long ni_syscalls_addr, int restore[]) {
    int i;
    int ret;
    
    printk("%s: tasklet example received sys_call_table address %px\n", MOD_NAME, (void*)syscall_table_addr);
    printk("%s: initializing - hacked entries %d\n", MOD_NAME, HACKED_ENTRIES);

    //new_sys_call_array[0] = (unsigned long)sys_put_work;

    ret = get_entries(restore, HACKED_ENTRIES, (unsigned long*)syscall_table_addr, &ni_syscalls_addr);

    if (ret != HACKED_ENTRIES){
            printk("%s: could not hack %d entries (just %d)\n", MOD_NAME, HACKED_ENTRIES, ret);
            return 0;
    }

    unprotect_memory();

    for(i=0;i<HACKED_ENTRIES;i++){
            ((unsigned long *)syscall_table_addr)[restore[i]] = (unsigned long)my_syscalls[i];
    }

    protect_memory();

    printk("%s: all new system-calls correctly installed on sys-call table\n", MOD_NAME);

    return 1;

}

int restore_syscall_table(unsigned long syscall_table_addr, unsigned long ni_syscalls_addr, int restore[]) {
    int i;

    printk("%s: shutting down\n", MOD_NAME);

    unprotect_memory();

    for(i=0; i<HACKED_ENTRIES; i++){
            ((unsigned long *)syscall_table_addr)[restore[i]] = ni_syscalls_addr;
    }
    
    protect_memory();
    
    printk("%s: sys-call table restored to its original content\n", MOD_NAME);
}