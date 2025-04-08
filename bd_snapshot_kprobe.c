#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/ptrace.h>
#include <linux/version.h>

MODULE_AUTHOR("Francesco Quaglia <francesco.quaglia@uniroma2.it>");
MODULE_DESCRIPTION("This module intecepts the return of the sys_read kernel function for a target process\
	it then audits a maximum of 128 read bytes into the dmesg buffer");


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
#define target_func "__x64_sys_fsopen"
#else
#define target_func "sys_mount"
#endif 

#define MOD_NAME "BD-SNAPSHOT-KPROBE"


static int tail_hook(struct kprobe *ri, struct pt_regs *the_regs) {
    struct pt_regs *regs;
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
	regs = (struct pt_regs*)the_regs->di;
#else
	regs = (struct pt_regs*)the_regs;
#endif

	//printk("%s: Rilevata esecuzione di sys_mount: source %s - target %s\n", MOD_NAME, (char*)regs->di, (char*)regs->si);
	printk("%s: Rilevata mount\n", MOD_NAME);
	return 0;
}

static struct kprobe kp = {
    .symbol_name = target_func,
    .pre_handler = (kprobe_pre_handler_t)tail_hook,
};

static int hook_init(void) {

	int ret;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_info("%s: hook init failed, returned %d\n", MOD_NAME, ret);
		return ret;
	}
	printk("%s: hook module correctly loaded.\n", MOD_NAME);
	
	return 0;
}// hook_init

static void hook_exit(void) {

	unregister_kprobe(&kp);
	//Be carefull, this unregister assumes that none will need to run the hook function after this nodule
	//is unmounted

	printk("%s: hook module unloaded\n", MOD_NAME);

}// hook_exit

module_init(hook_init)
module_exit(hook_exit)
MODULE_LICENSE("GPL");
