#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/sprintf.h>
#include <linux/ioctl.h>
#include <linux/loop.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/timekeeping.h>
#include <linux/list.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include <linux/kdev_t.h>

MODULE_AUTHOR("Francesco Quaglia <francesco.quaglia@uniroma2.it>");
MODULE_DESCRIPTION("This module intecepts the return of the sys_read kernel function for a target process\
	it then audits a maximum of 128 read bytes into the dmesg buffer");


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
#define target_func "__bread_gfp"
#else
#define target_func "__x64_sys_fsmount"
#endif 

#define MOD_NAME "BD-SNAPSHOT-KPROBE"

struct bread_args {
    struct block_device *bdev;
    sector_t block;
    unsigned int size;
};

static int bh_ret_hook(struct kretprobe_instance *ri, struct pt_regs *the_regs){
    printk("%s: bh_hook invoked\n", MOD_NAME);
    
    struct buffer_head *bh = (struct buffer_head *)regs_return_value(the_regs);
    if (bh == NULL){
        printk("%s: __bread_gfp returned NULL buffer_head\n", MOD_NAME);
        return 0;
    }

    if (bh->b_data == NULL){
        printk("%s: buffer_head has NULL data pointer\n", MOD_NAME);
        return 0;
    }
    printk("%s: buffer_head data: %s\n", MOD_NAME, bh->b_data);

    struct bread_args *args = (struct bread_args *)ri->data;

    struct block_device *bdev = args->bdev;
    sector_t block = args->block;
    unsigned int size = args->size;

    const char *device = bdev->bd_inode->i_sb->s_type->name;
    if (device == NULL){
        printk("%s: __bread_gfp invoked with NULL device name\n", MOD_NAME);
        return 0;
    }

    int major = MAJOR(bdev->bd_dev);
    int minor = MINOR(bdev->bd_dev);

    struct block_device *bdev_from_bh = bh->b_bdev;
    const char *device_from_bh = bdev_from_bh->bd_inode->i_sb->s_type->name;
    if (device_from_bh == NULL){
        printk("%s: __bread_gfp invoked with NULL device name from bh\n", MOD_NAME);
        return 0;
    }
    int major_from_bh = MAJOR(bdev_from_bh->bd_dev);
    int minor_from_bh = MINOR(bdev_from_bh->bd_dev);
    sector_t block_from_bh = bh->b_blocknr;
    unsigned int size_from_bh = bh->b_size;

    printk("%s: (from entry data) __bread_gfp invoked on loop device: %s (major: %d, minor: %d) at block number: %llu, block size: %u\n", MOD_NAME, device, major, minor, block, size);  
    printk("%s: (from handler data) __bread_gfp invoked on loop device: %s (major: %d, minor: %d) at block number: %llu, block size: %u\n", MOD_NAME, device_from_bh, major_from_bh, minor_from_bh, block_from_bh, size_from_bh); 

    return 0;

}

static int bh_entry_hook(struct kretprobe_instance *ri, struct pt_regs *the_regs) {
    //struct pt_regs *regs = (struct pt_regs *)the_regs->di;
    printk("%s: bh_entry_hook invoked\n", MOD_NAME);

    struct bread_args *args = (struct bread_args *)ri->data;

    struct block_device *bdev = (struct block_device *)the_regs->di;
    if (bdev == NULL){
        printk("%s: __bread_gfp invoked with NULL block_device\n", MOD_NAME);
        return 0;
    }
    sector_t block = (sector_t)the_regs->si;
    unsigned int size = (unsigned int)the_regs->dx;
    //printk("%s: block number: %llu\n", MOD_NAME, sector);

    args->bdev = bdev;
    args->block = block;
    args->size = size;

    /*struct inode *inode = bdev->bd_inode;
    if (inode == NULL){
        printk("%s: __bread_gfp invoked with NULL inode\n", MOD_NAME);
        return 0;
    }

    struct super_block *sb = inode->i_sb;
    if (sb == NULL){
        printk("%s: __bread_gfp invoked with NULL super_block\n", MOD_NAME);
        return 0;
    }

    char *device = sb->s_type->name;
    if (device == NULL){
        printk("%s: __bread_gfp invoked with NULL device name\n", MOD_NAME);
        return 0;
    }

    int major = MAJOR(bdev->bd_dev);
    int minor = MINOR(bdev->bd_dev);

    printk("%s: __bread_gfp invoked on loop device: %s (major: %d, minor: %d) at block number: %llu, block size: %u\n", MOD_NAME, device, major, minor, block, size);    
    */

    /*if (strcmp(device, "loop0") == 0 ) {
        printk("%s: mark_buffer_dirty invoked on loop device: %s at block number: %llu\n", MOD_NAME, device, sector);
    }
    printk("%s: numero blocco: %llu\n", MOD_NAME, sector);*/
    
    
    //printk("%s: sb_bread invoked\n", MOD_NAME);
    
    return 0;
}


static int tail_hook(struct kprobe *ri, struct pt_regs *the_regs) {
    struct pt_regs *regs = (struct pt_regs *)the_regs->di;
	
	const char __user *from_path, *to_path;
	char fpathbuff[256], tpathbuff[256];

	int from_fd = (int)regs->di;
	from_path = (const char __user *)regs->si;
	int to_df = (int)regs->dx;
	to_path = (const char __user *)regs->r10;


	/*if (from_path) {
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
	}*/

	char *path_buffer;
    const size_t path_max_len = 256; // Sufficiente per /proc/self/fd/ + un int a 10 cifre
    
    struct path path;
    int err = 0;

	path_buffer = kmalloc(path_max_len, GFP_KERNEL);
    if (!path_buffer) {
        printk(KERN_WARNING "MOVE_MOUNT: kmalloc fallito.\n");
        return 0;
    }

    // 2. Costruisci la stringa del percorso: /proc/self/fd/<dfd>
    snprintf(path_buffer, path_max_len, "/proc/self/fd/%d", from_fd);

    // 3. Risolvi il percorso usando l'esportata kern_path (risoluzione del path assoluto)
    // Usiamo LOOKUP_FOLLOW per seguire il symlink da /proc/self/fd/<dfd> all'oggetto reale.
    err = kern_path(path_buffer, LOOKUP_FOLLOW, &path);

    // Rilascia la memoria non appena non serve più il buffer
    kfree(path_buffer);

	struct super_block *sb;
	
	// 2. Accedi al superblock attraverso il path del file
	// f_path.mnt->mnt_sb è la catena di navigazione
	sb = path.mnt->mnt_sb;
	char *res = sb->s_id;

	if (sb) {
		// 3. Estrai il nome del dispositivo
		printk("%s: Nome Device da FD: %s\n", MOD_NAME, res);
	} else {
		printk("%s: Superblock non trovato.\n", MOD_NAME);
	}

    int major = MAJOR(path.mnt->mnt_sb->s_dev);
    int minor = MINOR(path.mnt->mnt_sb->s_dev);

    printk("%s: move_mount invoked on device: %s (major: %d, minor: %d)\n", MOD_NAME, res, major, minor);
	
	// 4. Molto importante: rilasciare il descrittore ottenuto
	path_put(&path);

    //DA QUESTO PUNTO IN POI IL CODICE È SPECIFICO PER LA RISOLUZIONE DEI DISPOSITIVI LOOP


	struct file *filploop = NULL;
    char *sysfs_path = NULL;
    char *backing_file_path = NULL;
    
    // Allocazione buffer per il percorso SysFS e il percorso di ritorno
    sysfs_path = kmalloc(path_max_len, GFP_KERNEL);
    backing_file_path = kmalloc(path_max_len, GFP_KERNEL);

    if (!sysfs_path || !backing_file_path) {
        printk(KERN_ERR "LOOP_RESOLVE: Allocazione memoria fallita.\n");
		return 0;
	}
    

    // 1. Costruisci il percorso SysFS (es. /sys/block/loop0/loop/backing_file)
    snprintf(sysfs_path, path_max_len, "/sys/block/%s/loop/backing_file", res);
    
    // 2. Apri il file SysFS
    // Usiamo O_RDONLY per la sola lettura. I permessi non sono necessari per un file SysFS.
    filploop = filp_open(sysfs_path, O_RDONLY, 0);

    if (IS_ERR(filploop)) {
        printk(KERN_WARNING "LOOP_RESOLVE: Impossibile aprire %s (Errore: %ld).\n", sysfs_path, PTR_ERR(filploop));
        return 0;
    }
    
    loff_t pos = 0;
    ssize_t bytes_read;
    
    bytes_read = kernel_read(filploop, backing_file_path, path_max_len - 1, &pos);
    
    if (bytes_read > 0) {

        if (backing_file_path[bytes_read - 1] == '\n') {
            bytes_read--;
        }
        backing_file_path[bytes_read] = '\0';
        
        printk(KERN_INFO "LOOP_RESOLVE: %s e' attaccato a: %s\n", res, backing_file_path);
        
        kfree(sysfs_path);
        
    } else {
        printk(KERN_WARNING "LOOP_RESOLVE: Lettura SysFS fallita o file vuoto.\n");
    }

    filp_close(filploop, NULL);

	return 0;
}

static struct kprobe kp = {
    .symbol_name = target_func,
    //.pre_handler = (kprobe_pre_handler_t)bh_hook,
    //.post_handler = (kprobe_post_handler_t)bh_hook,
};

static struct kretprobe krp = {
    .kp.symbol_name = target_func,
    .handler = (kretprobe_handler_t)bh_ret_hook,
    .entry_handler = (kretprobe_handler_t)bh_entry_hook,
    .data_size = sizeof(struct bread_args),
    .maxactive = 20,
};


struct mynode {
    int data;
    struct list_head my_list;
};

LIST_HEAD(list_head);

static int list_test(void) {
    for (int i = 0; i < 4; i++) {
        struct mynode *new_node = kmalloc(sizeof(struct mynode), GFP_KERNEL);
        if (!new_node) {
            printk(KERN_ERR "Memory allocation failed\n");
            return -1;
        }
        new_node->data = i;
        list_add(&new_node->my_list, &list_head);
    }

    struct mynode *pos, *tmp;
    list_for_each_entry(pos, &list_head, my_list) {
        printk(KERN_INFO "Node data: %d\n", pos->data);
    }

    printk(KERN_INFO "Last node is %d\n", pos->data);

    /*pos = NULL;
    list_for_each_entry_safe(pos, tmp, &list_head, my_list) {
        list_del(&pos->my_list);
        printk(KERN_INFO "Freeing node with data: %d\n", pos->data);
        kfree(pos);
        printk(KERN_INFO "Node freed\n");
    }*/
    return 0;
}


static int get_real_timestamp(void)
{
    struct timespec64 ts;
    
    // Ottiene il tempo reale (wall-clock time)
    ktime_get_real_ts64(&ts);
    
    printk(KERN_INFO "Tempo Reale (ktime_get_real_ts64): %lld secondi, %ld nanosecondi.\n", 
           ts.tv_sec, ts.tv_nsec);

    return 0;
}

static int hook_init(void) {

	int ret;

	//ret = register_kprobe(&kp);
    ret = register_kretprobe(&krp);

	if (ret < 0) {
		pr_info("%s: hook init failed, returned %d\n", MOD_NAME, ret);
		return ret;
	}
	printk("%s: hook module correctly loaded.\n", MOD_NAME);
	return 0;
}// hook_init

static void hook_exit(void) {

	//unregister_kprobe(&kp);
    unregister_kretprobe(&krp);

	//Be carefull, this unregister assumes that none will need to run the hook function after this module
	//is unmounted

	printk("%s: hook module unloaded\n", MOD_NAME);

}// hook_exit

module_init(hook_init)
module_exit(hook_exit)
MODULE_LICENSE("GPL");
