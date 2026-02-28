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

#include "include/bd_snapshot.h"
#include "include/bd_snapshot_list.h"
#include "include/bd_snapshot_kprobe.h"
#include "lib/include/scth.h"

char *passwd;
module_param(passwd, charp, 0660);

unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0660);

unsigned long the_ni_syscall;
unsigned long new_sys_call_array[] = {0x0, 0x0};
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array) / sizeof(unsigned long))
int restore[HACKED_ENTRIES] = {[0 ...(HACKED_ENTRIES - 1)] - 1};

u8 digest_password[SHA256_DIGEST_SIZE];

int check_root(void) {

        kuid_t euid = current_cred()->euid;
        if (euid.val != 0)
                return 0;
        return 1;
}

int hash_password(const char *password, size_t password_len, u8 *hash) {

        struct crypto_shash *tfm;
        struct shash_desc *desc;
        int ret = -ENOMEM;
        u8 *digest;

        tfm = crypto_alloc_shash(SHA256, 0, 0);
        if (IS_ERR(tfm)) {
                printk("%s: crypto hash allocation failed\n", MODNAME);
                return PTR_ERR(tfm);
        }

        desc = (struct shash_desc *)kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
        if (!desc) {
            crypto_free_shash(tfm);
            return ret;
        }

        desc->tfm = tfm;
        digest = (u8 *)kmalloc(SHA256_DIGEST_SIZE, GFP_KERNEL);
        if (!digest) {
            kfree(desc);
            crypto_free_shash(tfm);
            return ret;
        }

        ret = crypto_shash_digest(desc, password, password_len, digest);
        if (ret) { 
            printk("%s: error hashing password with err %d\n", MODNAME, ret);
            kfree(digest);
            kfree(desc);
            crypto_free_shash(tfm);
            return ret;
        }

        memcpy(hash, digest, SHA256_DIGEST_SIZE);

        return ret;
}

int check_password(char *password) {

        u8 digest[SHA256_DIGEST_SIZE];

        if (strlen(password) <= 0)
                return 0;

        if (hash_password(password, strlen(password), digest) < 0)
                return 0;

        if (memcmp(digest_password, digest, SHA256_DIGEST_SIZE) != 0)
                return 0;

        return 1;
}

__SYSCALL_DEFINEx(2, _activate_snapshot, const char __user*, dev_name, const char __user*, password) {

    char pswd[SIZE];
    char device_name_copy[SIZE];
    int ret; 

    int process_is_root = check_root();

    if (!process_is_root) {
        printk("%s: Only root can activate/deactivate snapshots\n", MODNAME);
        return -1;
    }
    
    ret = strncpy_from_user(pswd, password, SIZE);
    if (ret < 0) {
        printk("%s: Error copying password from user\n", MODNAME);
        return -1;
    }

    int login_success = check_password(pswd);
    if (!login_success) {
        printk("%s: Incorrect password\n", MODNAME);
        return -1;
    }

    ret = strncpy_from_user(device_name_copy, dev_name, SIZE);
    if (ret < 0) {
        printk("%s: Error copying device name from user\n", MODNAME);
        return -1;
    }

    spin_lock(&lock);

    device_t *device_registered = search_device(device_name_copy);
    if (device_registered == NULL) {

        if(!push(&dev_list_head, device_name_copy)) {
            printk("%s: Error registering device\n", MODNAME);
            ret = 0;
            goto out_release_lock;
        }

        enable_kretprobe(&krp_mount);

        printk("%s: Device %s registered\n", MODNAME, device_name_copy);
        ret = 0;
        goto out_release_lock;

    } else {

        printk("%s: Snapshot already active for device %s\n", MODNAME, device_name_copy);
        ret = 0;
        goto out_release_lock;
    }

out_release_lock:
    spin_unlock(&lock);
    return ret;
}

__SYSCALL_DEFINEx(2, _deactivate_snapshot, const char __user *, dev_name, const char __user *, password) {

    char pswd[SIZE];
    char device_name_copy[SIZE];
    int ret;

    int process_is_root = check_root();

    if (!process_is_root) {
        printk("%s: Only root can activate/deactivate snapshots\n", MODNAME);
        return -1;
    }

    ret = strncpy_from_user(pswd, password, SIZE);
    if (ret < 0) {
        printk("%s: Error copying password from user\n", MODNAME);
        return -1;
    }

    int login_success = check_password(pswd);
    if (!login_success) {
        printk("%s: Incorrect password\n", MODNAME);
        return -1;
    }

    ret = strncpy_from_user(device_name_copy, dev_name, SIZE);
    if (ret < 0) {  
        printk("%s: Error copying device name from user\n", MODNAME);
        return -1;
    }

    spin_lock(&lock);

    device_t *device_registered = search_device(device_name_copy);
    if (device_registered == NULL) {
        printk("%s: Device %s not registered\n", MODNAME, device_name_copy);
        ret = 0;
        goto out_release_lock;

    } else {

            remove(device_registered);
            printk("%s: Snapshot deactivated for device %s\n", MODNAME, device_name_copy);

            if (list_empty(&dev_list_head)) {
                disable_kretprobe(&krp_mount);
                disable_kprobe(&kp_umount);
                disable_kretprobe(&krp_write);
                printk("%s: All probes disabled\n", MODNAME);
                
            }
            
            ret = 0;
            goto out_release_lock;
    }

out_release_lock:
    spin_unlock(&lock);
    return ret;
}

int hook_init(void) {

    int ret;

    if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)) {
        pr_err("%s: unsupported kernel version", MODNAME);
        return -1;
    };

    if (!passwd) {
        printk("%s: no password provided, module loading aborted (usage: passwd=)\n", MODNAME);
        return -1;
    }

    ret = strlen(passwd);
    if (ret <= 0 || ret > SIZE) {
        printk("%s: invalid password length (max %d characters)\n", MODNAME, SIZE);
        return -1;
    }

    printk("%s: setting password of length %d\n", MODNAME, ret);

    ret = hash_password(passwd, strlen(passwd), digest_password);
    if (ret) {
        printk("%s: password hashing failed - err %d\n", MODNAME, ret);
        return ret;
    }

    memset(passwd, 0, strlen(passwd)); 

    struct path path_parent;
    struct dentry *new_dentry;
    int err;

    new_dentry = kern_path_create(AT_FDCWD, "/snapshot", &path_parent, LOOKUP_DIRECTORY);
    
    if (IS_ERR(new_dentry)) {
        err = PTR_ERR(new_dentry);
        if (err == -EEXIST) {
            printk("%s: directory /snapshot already exists\n", MODNAME);
            goto install_syscall; 
        }

        printk("%s: kern_path_create failed with error %d\n", MODNAME, err);
        return err;
    }

    err = vfs_mkdir(&nop_mnt_idmap, d_inode(path_parent.dentry), new_dentry, 0660);
    
    if (err) {
        printk("%s: vfs_mkdir failed with error %d\n", MODNAME, err);
        done_path_create(&path_parent, new_dentry);
        return err;
    } 

    printk("%s: directory /snapshot created successfully\n", MODNAME);

    done_path_create(&path_parent, new_dentry);
 
install_syscall:
    if (the_syscall_table == 0x0) {
        printk("%s: cannot manage sys_call_table address set to 0x0\n", MODNAME);
        return -1;
    }
    
    new_sys_call_array[0] = (unsigned long)__x64_sys_activate_snapshot;
    new_sys_call_array[1] = (unsigned long)__x64_sys_deactivate_snapshot;

    ret = get_entries(restore, HACKED_ENTRIES, (unsigned long)the_syscall_table, &the_ni_syscall);

    if (ret != HACKED_ENTRIES) {
        printk("%s: could not hack %d entries (just %d)\n", MODNAME, HACKED_ENTRIES, ret);
        return -1;
    }

    unprotect_memory();
    
    for (int i = 0; i < HACKED_ENTRIES; i++)
            ((unsigned long *)the_syscall_table)[restore[i]] = (unsigned long)new_sys_call_array[i];
    
    protect_memory();

    printk("%s: all new system-calls correctly installed on sys-call table\n", MODNAME);
    printk("%s: %s is at table entry %d\n", MODNAME, "_activate_snapshot", restore[0]);
    printk("%s: %s is at table entry %d\n", MODNAME, "_deactivate_snapshot", restore[1]);

    snapshot_wq = create_workqueue("bd_snapshot_wq");
    if (!snapshot_wq) {
        printk("%s: Error creating workqueue\n", MODNAME);
        return -1;
    }   

    ret = register_kretprobe(&krp_mount);
	if (ret < 0) {
		printk("%s: mount kprobe registration failed\n", MODNAME);
		return ret;
	}

    disable_kretprobe(&krp_mount);
    
    ret = register_kprobe(&kp_umount);
    if (ret < 0) {
        printk("%s: umount kprobe registration failed\n", MODNAME);
        return ret;
    }

    disable_kprobe(&kp_umount);
    
    ret = register_kretprobe(&krp_write);
    if (ret < 0) {
        printk("%s: write kretprobe registration failed\n", MODNAME);
        return ret;
    }

    disable_kretprobe(&krp_write);
    
	printk("%s: hook module correctly loaded.\n", MODNAME);
	return 0;
}

void hook_exit(void) {

    destroy_workqueue(snapshot_wq); 
    
    unregister_kretprobe(&krp_mount);
    unregister_kprobe(&kp_umount);
    unregister_kretprobe(&krp_write);
    
    printk("%s: kprobes unregistered\n", MODNAME);
    printk("%s: restoring sys-call table\n", MODNAME);
    
    unprotect_memory();
    
    for (int i = 0; i < HACKED_ENTRIES; i++) {
            ((unsigned long *)the_syscall_table)[restore[i]] = the_ni_syscall;
    }
    
    protect_memory();
   
    printk("%s: sys-call table restored to its original content\n", MODNAME); 
    printk("%s: hook module unloaded\n", MODNAME);

}


module_init(hook_init);
module_exit(hook_exit);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Damiano De Orazi <damianodeorazi@hotmail.com>");
MODULE_DESCRIPTION("BD-SNAPSHOT");
