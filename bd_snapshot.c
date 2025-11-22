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

#include "bd_snapshot.h"
#include "bd_snapshot_list.h"
#include "bd_snapshot_kprobe.h"
#include "syscall_table_mod.h"
//TODO: includere header per la risoluzione di risorse (es. MOD_NAME)


unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0660);

char *passwd;
module_param(passwd, charp, 0660);

unsigned long the_ni_syscall;

unsigned long new_sys_call_array[] = {0x0, 0x0, 0x0};
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};

u8 digest_password[SHA256_DIGEST_SIZE];

atomic_t monitor_mount_is_active = ATOMIC_INIT(0);
atomic_t monitor_umount_is_active = ATOMIC_INIT(0);


int hash_password(const char *password, size_t password_len, u8 *hash)
{
        struct crypto_shash *tfm;
        struct shash_desc *desc;
        int ret = -ENOMEM;
        u8 *digest;

        tfm = crypto_alloc_shash(SHA256, 0, 0);
        if (IS_ERR(tfm))
        {
                printk("%s: allocazione di crypto hash fallita\n", MOD_NAME);
                return PTR_ERR(tfm);
        }

        desc = (struct shash_desc *)kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
        if (!desc)
                goto out_free_tfm;

        desc->tfm = tfm;

        digest = (u8 *)kmalloc(SHA256_DIGEST_SIZE, GFP_KERNEL);
        if (!digest)
                goto out_free_desc;

        ret = crypto_shash_digest(desc, password, password_len, digest);
        if (ret)
        {
                printk("%s: error hashing password with err %d\n", MOD_NAME, ret);
                goto out_free_digest;
        }

        memcpy(hash, digest, SHA256_DIGEST_SIZE);

out_free_digest:
        kfree(digest);
out_free_desc:
        kfree(desc);
out_free_tfm:
        crypto_free_shash(tfm);

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

SYSCALL_DEFINE2(activate_snapshot, const char __user*, dev_name, const char __user*, password){

    char pswd[PASSWORD_MAX_LEN];
    char *device_name_copy;
    int ret; 

    int process_is_root = current_euid().val;

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

        atomic_cmpxchg(&monitor_mount_is_active, 0, 1);
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
            atomic_cmpxchg(&monitor_mount_is_active, 0, 1);

            device_t *device = NULL; 

            list_for_each_entry (device, &dev_list_head, device_list) { 
            
                if (device->ss_is_active == 0) {
                    break;
                }
            }

            if (device->ss_is_active) {
                atomic_cmpxchg(&monitor_umount_is_active, 1, 0); //TODO: controllare se device è NULL o punta all'ultimo elemento della lista dei dispositivi
            }

            spin_unlock(&lock);

            printk("%s: Snapshot activated for device %s\n", MOD_NAME, device_name_copy);
            kfree(device_name_copy);
            return 1;
        }
    }
}

SYSCALL_DEFINE2(deactivate_snapshot, const char __user *, dev_name, const char __user *, password){

    char pswd[PASSWORD_MAX_LEN];
    char *device_name_copy;
    int ret;

    int process_is_root = current_euid().val;

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
            atomic_cmpxchg(&monitor_umount_is_active, 0, 1);

            device_t *device = NULL; 

            list_for_each_entry (device, &dev_list_head, device_list) { 
            
                if (device->ss_is_active == 1) {
                    break;
                }
            }

            if (device->ss_is_active == 0) {
                atomic_cmpxchg(&monitor_mount_is_active, 1, 0); //TODO: controllare se device è NULL o punta all'ultimo elemento della lista dei dispositivi
            }

            spin_unlock(&lock);
            
            printk("%s: Snapshot deactivated for device %s\n", MOD_NAME, device_name_copy);
            kfree(device_name_copy);
            return 1;
        }
    }
}

SYSCALL_DEFINE2(restore_snapshot, const char __user *, dev_name, const char __user *, password){

    char pswd[PASSWORD_MAX_LEN];
    char *device_name_copy;
    int ret;

    int process_is_root = current_euid().val;

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

    ret = strlen(passwd);
    if (ret <= 0 || ret > PASSWORD_MAX_LEN){

            printk("%s: invalid password length\n", MOD_NAME);
            return 0;
    }

    ret = hash_password(passwd, strlen(passwd), digest_password);
    if (ret)
    {
            printk("%s: password hashing failed - err %d\n", MOD_NAME, ret);
            return ret;
    }

    //cancello la password in chiaro dalla memoria
    memset(passwd, 0, strlen(passwd)); 
    
    new_sys_call_array[0] = (unsigned long)sys_activate_snapshot;
    new_sys_call_array[1] = (unsigned long)sys_deactivate_snapshot;
    new_sys_call_array[2] = (unsigned long)sys_restore_snapshot;

    modify_syscall_table(new_sys_call_array, the_syscall_table, the_ni_syscall, restore);

	ret = register_kprobe(&kp_mount);

	if (ret < 0) {
		printk("%s: hook init failed, returned %d\n", MOD_NAME, ret);
		return ret;
	}

    ret = register_kprobe(&kp_umount);
    if (ret < 0) {
        printk("%s: hook init failed, returned %d\n", MOD_NAME, ret);
        return ret;
    }

    ret = register_kretprobe(&krp_write);
    if (ret < 0) {
        printk("%s: hook init failed, returned %d\n", MOD_NAME, ret);
        return ret;
    }

	printk("%s: hook module correctly loaded.\n", MOD_NAME);
	
	return 0;
}

void hook_exit(void) {

    restore_syscall_table(the_syscall_table, the_ni_syscall, restore);

	unregister_kprobe(&kp_mount);
    unregister_kprobe(&kp_umount);
    unregister_kretprobe(&krp_write);

	printk("%s: hook module unloaded\n", MOD_NAME);

}

long sys_activate_snapshot = (unsigned long) __x64_sys_activate_snapshot;
long sys_deactivate_snapshot = (unsigned long) __x64_sys_deactivate_snapshot; 
long sys_restore_snapshot = (unsigned long) __x64_sys_restore_snapshot;      

int init_module(void) {

    int ret;

    ret = hook_init();

    return ret;

}


void cleanup_module(void) {

    hook_exit();

}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Damiano De Orzi <damianodeorazi@hotmail.com>");
MODULE_DESCRIPTION("BD-SNAPSHOT");
