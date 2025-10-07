#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/version.h>

MODULE_AUTHOR("Francesco Quaglia <francesco.quaglia@uniroma2.it>");
MODULE_DESCRIPTION("This module intecepts the return of the sys_read kernel function for a target process\
	it then audits a maximum of 128 read bytes into the dmesg buffer");


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
#define target_func "__x64_sys_move_mount"
#else
#define target_func "__x64_sys_fsmount"
#endif 

#define MOD_NAME "BD-SNAPSHOT-KPROBE"


static int tail_hook(struct kprobe *ri, struct pt_regs *the_regs) {
    struct pt_regs *regs = (struct pt_regs *)the_regs->di;
	
	const char __user *from_path, *to_path;
	char fpathbuff[256], tpathbuff[256];

	int from_fd = (int)regs->di;
	from_path = (const char __user *)regs->si;
	int to_df = (int)regs->dx;
	to_path = (const char __user *)regs->r10;
	


	if (from_path) {
        if (strncpy_from_user(fpathbuff, from_path, sizeof(fpathbuff) - 1) < 0){
			printk("%s: error reading from_pathname\n", MOD_NAME);
			return 0;
		}
        fpathbuff[sizeof(fpathbuff) - 1] = '\0';
    } else {
        printk("%s: error reading from_path from register\n", MOD_NAME);
		return 0;
    }

	if (to_path) {
		if (strncpy_from_user(tpathbuff, to_path, sizeof(tpathbuff) - 1) < 0){
			printk("%s: error reading to_pathname\n", MOD_NAME);
			return 0;
		}
		tpathbuff[sizeof(tpathbuff) - 1] = '\0';
	} else {
		printk("%s: error reading to_path from register\n", MOD_NAME);
		return 0;
	}
	
	printk("%s: Rilevata esecuzione di move_mount: from_fd=%d from_pathname=%s to_df=%d to_pathname=%s\n", MOD_NAME, from_fd, fpathbuff, to_df, to_path);
	
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
