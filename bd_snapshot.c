#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/slab.h> 
#include <crypto/hash.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/atomic.h>
#include <linux/buffer_head.h>
#include <linux/mnt_idmapping.h>
#include <linux/namei.h>
#include <linux/workqueue.h>

#include "bd_snapshot.h"
#include "bd_snapshot_list.h"
#include "bd_snapshot_kprobe.h"
#include "lib/include/scth.h"
//#include "lib/include/usctm.h"

char *passwd;
module_param(passwd, charp, 0660);

unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0660);

unsigned long the_ni_syscall;
unsigned long new_sys_call_array[] = {0x0, 0x0, 0x0};
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array) / sizeof(unsigned long))
//#define INST_LEN 5
int restore[HACKED_ENTRIES] = {[0 ...(HACKED_ENTRIES - 1)] - 1};

u8 digest_password[SHA256_DIGEST_SIZE];


/*
char jump_inst[INST_LEN];
unsigned long x64_sys_call_addr;
int offset;
struct kprobe kp_x64_sys_call = { .symbol_name = "x64_sys_call" };

//stuff here is using retpoline
inline void call(struct pt_regs *regs, unsigned int nr){
    asm volatile("mov (%1, %0, 8), %%rax\n\t"
         "jmp __x86_indirect_thunk_rax\n\t"
         :
         : "r"((long)nr), "r"(hacked_syscall_tbl)
         : "rax");
}*/

int check_root(void)
{
        kuid_t euid = current_cred()->euid;
        if (euid.val != 0)
                return 0;
        return 1;
}


int hash_password(const char *password, size_t password_len, u8 *hash)
{
        struct crypto_shash *tfm;
        struct shash_desc *desc;
        int ret = -ENOMEM;
        u8 *digest;

        tfm = crypto_alloc_shash(SHA256, 0, 0);
        if (IS_ERR(tfm)){

                printk("%s: allocazione di crypto hash fallita\n", MOD_NAME);
                return PTR_ERR(tfm);
        
        }

        desc = (struct shash_desc *)kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
        if (!desc){

            crypto_free_shash(tfm);
            return ret;
        
        }

        desc->tfm = tfm;

        digest = (u8 *)kmalloc(SHA256_DIGEST_SIZE, GFP_KERNEL);
        if (!digest){

            kfree(desc);
            crypto_free_shash(tfm);
            return ret;

        }

        ret = crypto_shash_digest(desc, password, password_len, digest);
        if (ret){
            
            printk("%s: error hashing password with err %d\n", MOD_NAME, ret);
            kfree(digest);
            kfree(desc);
            crypto_free_shash(tfm);
            return ret;
        }

        memcpy(hash, digest, SHA256_DIGEST_SIZE);

        return ret;
}

int check_password(char *password)
{
        u8 digest[SHA256_DIGEST_SIZE];

        if (strlen(password) <= 0)
                return 0;

        if (hash_password(password, strlen(password), digest) < 0)
                return 0;

        if (memcmp(digest_password, digest, SHA256_DIGEST_SIZE) != 0)
                return 0;

        return 1;
}

__SYSCALL_DEFINEx(2, _activate_snapshot, const char __user*, dev_name, const char __user*, password){

    char pswd[PASSWORD_MAX_LEN];
    char *device_name_copy;
    int ret; 

    int process_is_root = check_root();

    if (!process_is_root) {

        printk("%s: Only root can activate/deactivate snapshots\n", MOD_NAME);
        return 0;

    }
    
    ret = strncpy_from_user(pswd, password, PASSWORD_MAX_LEN);
    if (ret < 0) {

        printk("%s: Error copying password from user\n", MOD_NAME);
        return 0;
    
    }

    int login_success = check_password(pswd);

    if (!login_success) {

        printk("%s: Incorrect password\n", MOD_NAME);
        return 0;
    
    }

    device_name_copy = kmalloc(strlen(dev_name)+1, GFP_KERNEL);
    if (!device_name_copy) {
        printk("%s: Error allocating memory for device name copy\n", MOD_NAME);
        return 0;
    }

    ret = strncpy_from_user(device_name_copy, dev_name, strlen(dev_name)+1);
    if (ret < 0) {

        printk("%s: Error copying device name from user\n", MOD_NAME);
        kfree(device_name_copy);
        return 0;
    
    }

    spin_lock(&lock);

    device_t *device_registered = search_device(device_name_copy);

    if (device_registered == NULL) {

        if(!push(&dev_list_head, device_name_copy)) {

            spin_unlock(&lock);
            printk("%s: Error registering device\n", MOD_NAME);
            kfree(device_name_copy);
            return 0;
        
        }

        enable_kprobe(&kp_mount);
        spin_unlock(&lock);

        printk("%s: Device %s registered\n", MOD_NAME, device_name_copy);
        kfree(device_name_copy);

        return 1;

    } else {

        if (device_registered->ss_is_active) {

            spin_unlock(&lock);
            printk("%s: Snapshot already active for device %s\n", MOD_NAME, device_name_copy);
            kfree(device_name_copy);
            return 1;

        } else {

            device_registered->ss_is_active = 1;
            enable_kprobe(&kp_mount);

            spin_unlock(&lock);

            printk("%s: Snapshot activated for device %s\n", MOD_NAME, device_name_copy);
            kfree(device_name_copy);
            return 1;
        }
    }
}

__SYSCALL_DEFINEx(2, _deactivate_snapshot, const char __user *, dev_name, const char __user *, password){

    char pswd[PASSWORD_MAX_LEN];
    char *device_name_copy;
    int ret;

    int process_is_root = check_root();

    if (!process_is_root) {

        printk("%s: Only root can activate/deactivate snapshots\n", MOD_NAME);
        return 0;

    }

    ret = strncpy_from_user(pswd, password, PASSWORD_MAX_LEN);
    if (ret < 0) {
     
        printk("%s: Error copying password from user\n", MOD_NAME);
        return 0;
    
    }

    int login_success = check_password(pswd);

    if (!login_success) {

        printk("%s: Incorrect password\n", MOD_NAME);
        return 0;

    }

    device_name_copy = kmalloc(strlen(dev_name)+1, GFP_KERNEL);
    if (!device_name_copy) {
    
        printk("%s: Error allocating memory for device name copy\n", MOD_NAME);
        return 0;       
    
    }

    ret = strncpy_from_user(device_name_copy, dev_name, strlen(dev_name)+1);
    if (ret < 0) {  

        printk("%s: Error copying device name from user\n", MOD_NAME);
        kfree(device_name_copy);
        return 0;
    
    }

    spin_lock(&lock);

    device_t *device_registered = search_device(device_name_copy);

    if (device_registered == NULL) {

        spin_unlock(&lock);
        printk("%s: Device %s not registered\n", MOD_NAME, device_name_copy);
        kfree(device_name_copy);
        return 0;

    } else {

        if (device_registered->ss_is_active == 0) {

            spin_unlock(&lock);
            printk("%s: Snapshot already deactive for device %s\n", MOD_NAME, device_name_copy);
            kfree(device_name_copy);
            return 1;

        } else {

            device_registered->ss_is_active = 0;

            device_t *device = NULL; 

            list_for_each_entry (device, &dev_list_head, device_list) { 
            
                if (device->ss_is_active == 1) {
                    goto out;
                }
            }

            disable_kprobe(&kp_mount);
            printk("%s: monitor mount disativato\n", MOD_NAME);

        out:
            spin_unlock(&lock);
            
            printk("%s: Snapshot deactivated for device %s\n", MOD_NAME, device_name_copy);
            kfree(device_name_copy);
            return 1;
        }
    }
}

__SYSCALL_DEFINEx(2, _restore_snapshot, const char __user *, dev_name, const char __user *, password){

    char pswd[PASSWORD_MAX_LEN];
    char *device_name_copy;
    int ret;

    int process_is_root = check_root();

    if (!process_is_root) {

        printk("%s: Only root can restore snapshots\n", MOD_NAME);
        return 0;

    }

    ret = strncpy_from_user(pswd, password, PASSWORD_MAX_LEN);
    if (ret < 0) {  
        
        printk("%s: Error copying password from user\n", MOD_NAME);
        return 0;
    
    }

    int login_success = check_password(pswd);

    if (!login_success) {

        printk("%s: Incorrect password\n", MOD_NAME);
        return 0;
    
    }

    device_name_copy = kmalloc(strlen(dev_name)+1, GFP_KERNEL);
    if (!device_name_copy) {    
    
        printk("%s: Error allocating memory for device name copy\n", MOD_NAME);
        return 0;       
    
    }
    
    ret = strncpy_from_user(device_name_copy, dev_name, strlen(dev_name)+1);
    if (ret < 0) {
    
        printk("%s: Error copying device name from user\n", MOD_NAME);
        kfree(device_name_copy);
        return 0;
    
    }

    spin_lock(&lock);

    device_t *device_registered = search_device(device_name_copy);

    spin_unlock(&lock);

    if (device_registered == NULL) {

        printk("%s: Device %s not registered\n", MOD_NAME, device_name_copy);
        kfree(device_name_copy);
        return 0;

    } else {
        if (device_registered->ss_path[0] == '\0') {

            printk("%s: No snapshot found for device %s\n", MOD_NAME, device_name_copy);
            kfree(device_name_copy);
            return 0;

        } else {
            mutex_lock(&device_registered->snapshot_lock);
            struct file *fp;

            fp = filp_open(device_registered->ss_path, O_RDONLY, 0);
            if (IS_ERR(fp)) {
                mutex_unlock(&device_registered->snapshot_lock);
                printk("%s: filp_open failed for %s.\n", MOD_NAME, device_registered->ss_path);
                kfree(device_name_copy);
                return 0;
            }

            printk("%s: opening file %s\n", MOD_NAME, device_registered->ss_path);

            packed_data *read_data = NULL;
            read_data = kmalloc(sizeof(packed_data), GFP_ATOMIC);
            if (!read_data) {
                mutex_unlock(&device_registered->snapshot_lock);
                printk("%s: kmalloc failed for read_data.\n", MOD_NAME);
                filp_close(fp, NULL);
                kfree(device_name_copy);
                return 0;
            }

            for (;;) {
                printk("%s: posizione attuale file %lld\n", MOD_NAME, fp->f_pos);
                ssize_t bytes_read = kernel_read(fp, read_data, sizeof(packed_data), &fp->f_pos);

                if (bytes_read < 0) {

                    mutex_unlock(&device_registered->snapshot_lock);
                    printk("%s: kernel_read failed for %s.\n", MOD_NAME, device_registered->ss_path);
                    kfree(read_data);
                    kfree(device_name_copy);
                    filp_close(fp, NULL);
                    return 0;

                } else if (bytes_read == 0) {
                    // Fine del file raggiunta
                    printk("%s: end of file\n", MOD_NAME);
                    break;

                } else {
                    
                    sector_t block_number = read_data->block_number;
                    char *data = read_data->data;
                    struct buffer_head *bh = NULL;
                    
                    bh = sb_bread(device_registered->sb, block_number);
                    if (bh == NULL) {
                        printk("%s: sb_bread failed for block number %llu.\n", MOD_NAME, block_number);
                        kfree(read_data);
                        mutex_unlock(&device_registered->snapshot_lock);
                        filp_close(fp, NULL);
                        kfree(device_name_copy);
                        return 0;   
                    }

                    printk("%s: resoring snapshot - bn = %lld data = %s\n", MOD_NAME, block_number, data);
                    
                    memcpy(bh->b_data, data, device_registered->sb->s_blocksize);
                    bh->b_state = bh->b_state | BH_Dirty;
                    write_dirty_buffer(bh, 0);
                    brelse(bh);

                }
            }

            kfree(read_data);
            kfree(device_name_copy);
            mutex_unlock(&device_registered->snapshot_lock);
            filp_close(fp, NULL);

            printk("%s: Snapshot restored for device %s\n", MOD_NAME, dev_name);
            return 1;
        }
    }
}



int hook_init(void) {

    int ret;

    if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0))
    {
            pr_err("%s: unsupported kernel version", MOD_NAME);
            return -1;
    };

    if (!passwd){

            printk("%s: no password provided, module loading aborted (usage: passwd=)\n", MOD_NAME);
            return -1;
    }

    ret = strlen(passwd);
    if (ret <= 0 || ret > PASSWORD_MAX_LEN){

            printk("%s: invalid password length\n", MOD_NAME);
            return -1;
    }

    printk("%s: setting password of length %d\n", MOD_NAME, ret);

    ret = hash_password(passwd, strlen(passwd), digest_password);
    if (ret)
    {
            printk("%s: password hashing failed - err %d\n", MOD_NAME, ret);
            return ret;
    }

    //cancello la password in chiaro dalla memoria
    memset(passwd, 0, strlen(passwd)); 

    
    struct path path_parent;
    struct dentry *new_dentry;
    int err;


    new_dentry = kern_path_create(AT_FDCWD, "/snapshot", &path_parent, LOOKUP_DIRECTORY);
    
    if (IS_ERR(new_dentry)) {
        err = PTR_ERR(new_dentry);
        if (err == -EEXIST) {
            printk("%s: directory /snapshot already exists\n", MOD_NAME);
            goto install_syscall; 
        }
        printk("%s: kern_path_create failed with error %d\n", MOD_NAME, err);
        return err;
    }

    err = vfs_mkdir(&nop_mnt_idmap, d_inode(path_parent.dentry), new_dentry, 0660);
    
    if (err) {
        printk("%s: vfs_mkdir failed with error %d\n", MOD_NAME, err);
        done_path_create(&path_parent, new_dentry);
        return err;
    } 

    printk("%s: directory /snapshot created successfully\n", MOD_NAME);

    done_path_create(&path_parent, new_dentry);
 
install_syscall:
    //syscall_table_finder();
    if (the_syscall_table == 0x0)
    {
            printk("%s: cannot manage sys_call_table address set to 0x0\n", MOD_NAME);
            return -1;
    }
    
    new_sys_call_array[0] = (unsigned long)__x64_sys_activate_snapshot;
    new_sys_call_array[1] = (unsigned long)__x64_sys_deactivate_snapshot;
    new_sys_call_array[2] = (unsigned long)__x64_sys_restore_snapshot;

    ret = get_entries(restore, HACKED_ENTRIES, (unsigned long)sys_call_table_address, &the_ni_syscall);

    if (ret != HACKED_ENTRIES)
    {
            printk("%s: could not hack %d entries (just %d)\n", MOD_NAME, HACKED_ENTRIES, ret);
            return -1;
    }

    /*
    if (register_kprobe(&kp_x64_sys_call)) {
        printk(KERN_ERR "%s: cannot register kprobe for x64_sys_call\n", MOD_NAME);
        return -1;
    }

    x64_sys_call_addr = (unsigned long)kp_x64_sys_call.addr;
    unregister_kprobe(&kp_x64_sys_call);

    // JMP opcode 
    jump_inst[0] = 0xE9;
    // RIP points to the next instruction. Current instruction has length 5 
    offset = (unsigned long)call - x64_sys_call_addr - INST_LEN;
    memcpy(jump_inst + 1, &offset, sizeof(int));
    */
    unprotect_memory();
    
    for (int i = 0; i < HACKED_ENTRIES; i++)
            ((unsigned long *)the_syscall_table)[restore[i]] = (unsigned long)new_sys_call_array[i];
    
    //memcpy((unsigned char *)x64_sys_call_addr, jump_inst, INST_LEN);

    protect_memory();

    printk("%s: all new system-calls correctly installed on sys-call table\n", MOD_NAME);
    printk("%s: %s is at table entry %d\n", MOD_NAME, "_activate_snapshot", restore[0]);
    printk("%s: %s is at table entry %d\n", MOD_NAME, "_deactivate_snapshot", restore[1]);
    printk("%s: %s is at table entry %d\n", MOD_NAME, "_restore_snapshot", restore[2]);

    snapshot_wq = create_workqueue("bd_snapshot_wq");
    if (!work_queue) {
        printk("%s: Error creating workqueue\n", MOD_NAME);
        return -1;
    }    
    
	ret = register_kprobe(&kp_mount);

	if (ret < 0) {
		printk("%s: hook init failed, returned %d\n", MOD_NAME, ret);
		return ret;
	}

    disable_kprobe(&kp_mount);
    
    ret = register_kprobe(&kp_umount);
    if (ret < 0) {
        printk("%s: hook init failed, returned %d\n", MOD_NAME, ret);
        return ret;
    }

    disable_kprobe(&kp_umount);
    
    ret = register_kretprobe(&krp_write);
    if (ret < 0) {
        printk("%s: hook init failed, returned %d\n", MOD_NAME, ret);
        return ret;
    }

    disable_kretprobe(&krp_write);
    
	printk("%s: hook module correctly loaded.\n", MOD_NAME);
	
	return 0;
}

void hook_exit(void) {

    destroy_workqueue(snapshot_wq); 
    
    unregister_kprobe(&kp_mount);
    unregister_kprobe(&kp_umount);
    unregister_kretprobe(&krp_write);
    
    printk("%s: kprobes unregistered\n", MOD_NAME);
    
    printk("%s: restoring sys-call table\n", MOD_NAME);
    
    unprotect_memory();
    
    for (int i = 0; i < HACKED_ENTRIES; i++){
            ((unsigned long *)the_syscall_table)[restore[i]] = the_ni_syscall;
    }
    
    protect_memory();
   
    printk("%s: sys-call table restored to its original content\n", MOD_NAME); 

    printk("%s: hook module unloaded\n", MOD_NAME);

}


module_init(hook_init);
module_exit(hook_exit);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Damiano De Orazi <damianodeorazi@hotmail.com>");
MODULE_DESCRIPTION("BD-SNAPSHOT");
