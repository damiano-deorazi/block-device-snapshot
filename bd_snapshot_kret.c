#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/ptrace.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
#define target_func "__x64_sys_mount"
#else
#define target_func "sys_mount"
#endif 

#define MOD_NAME "BD-SNAPSHOT"


static int tail_hook(struct kretprobe_instance *ri, struct pt_regs *the_regs) {
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

static struct kretprobe krp = {
	.entry_handler                = tail_hook,
};

static int __init hook_init(void) {

	int ret;

	krp.kp.symbol_name = target_func;
	ret = register_kretprobe(&krp);
	if (ret < 0) {
		pr_info("%s: hook init failed, returned %d\n", MOD_NAME, ret);
		return ret;
	}
	if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
		printk("%s: hook module correctly loaded. Kernel version is >= 4.17\n", MOD_NAME);
	else
		printk("%s: hook module correctly loaded. Kernel version is <= 4.17\n", MOD_NAME);
	//printk("%s: hook module correctly loaded. Kernel version - \n", MOD_NAME);
	
	return 0;
}// hook_init

static void __exit hook_exit(void) {

	unregister_kretprobe(&krp);
	//Be carefull, this unregister assumes that none will need to run the hook function after this nodule
	//is unmounted

	printk("%s: hook module unloaded\n", MOD_NAME);

}// hook_exit

module_init(hook_init)
module_exit(hook_exit)
MODULE_LICENSE("GPL");
