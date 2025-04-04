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



static int tail_hook(struct kretprobe_instance *ri, struct pt_regs *the_regs) {
    struct pt_regs *regs;
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
	regs = the_regs->di;
#else
	regs = the_regs;
#endif

	printk("Rilevata esecuzione di sys_mount: source %s - target %s\n", (char*)regs->di, (char*)regs->si);
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
		pr_info("hook init failed, returned %d\n", ret);
		return ret;
	}
	printk("hook module correctly loaded\n");
	
	return 0;
}// hook_init

static void __exit hook_exit(void) {

	unregister_kretprobe(&krp);
	//Be carefull, this unregister assumes that none will need to run the hook function after this nodule
	//is unmounted

	printk("hook module unloaded\n");

}// hook_exit

module_init(hook_init)
module_exit(hook_exit)
MODULE_LICENSE("GPL");
