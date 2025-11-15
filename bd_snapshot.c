#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/slab.h> 
#include <openssl/sha.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/cred.h>
#include <linux/atomic.h>

#include "bd_snapshot.h"
#include "bd_snapshot_list.h"
#include "bd_snapshot_kprobe.h"
#include "syscall_table_mod.h"
//TODO: includere header per la risoluzione di risorse (es. MOD_NAME)

unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0660);

unsigned long the_ni_syscall;

unsigned long new_sys_call_array[] = {0x0, 0x0}; 
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};

unsigned char ss_hpasswd[32] = NULL; //password per l'attivazione/disattivazione degli snapshot 
unsigned char salt[32] = NULL; //sale per l'hashing della password
int iter = -1; //numero di iterazioni per l'algoritmo di hashing

atomic_t monitor_mount_is_active = ATOMIC_INIT(0);
atomic_t monitor_umount_is_active = ATOMIC_INIT(0);


int generate_hash(char *password) {
    /*int salt_ok = RAND_bytes(salt, sizeof(salt));
                                                        -------> decidere se generare un sale random ad ogni avvio del modulo o utilizzare un sale fisso
    if (!salt_ok) {
        printk("Error generating salt\n");
        return 0;
    }*/

    int hash_ok = PKCS5_PBKDF2_HMAC(password, -1,
        salt, sizeof(salt),
        iter, EVP_sha256(),
        sizeof(ss_hpasswd), ss_hpasswd);
    
    if (!hash_ok) {
        printk("%s:  Error generating hash\n", MOD_NAME);
        return 0;
    }
    
    return 1;
}

int check_password(char *password) {
    unsigned char key[32] = {0};
    
    int hash_ok = generate_hash(password);

    if (!hash_ok) {
        return 0;
    }

    if (memcmp(key, ss_hpasswd, sizeof(ss_hpasswd)) == 0) {
        return 1; //password corretta
    } else {
        return 0; //password errata
    }
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
SYSCALL_DEFINE2(activate_snapshot, char *, dev_name, char *, password){
#else
asmlinkage long sys_activate_snapshot(char *dev_name, char *password){
#endif
    int process_is_root = current_euid().val;

    if (!process_is_root) {

        printk("%s: Only root can activate/deactivate snapshots\n", MOD_NAME);
        return 0;

    }

    int login_success = check_password(password);

    if (!login_success) {

        printk("%s: Incorrect password\n", MOD_NAME);
        return 0;
    
    }

    spin_lock(&lock);

    device_t *device_registered = search_device(dev_name);

    if (device_registered == NULL) {

        if(!push(&dev_list_head, dev_name)) {

            spin_unlock(&lock);
            printk("%s: Error registering device\n", MOD_NAME);
            return 0;
        
        }

        atomic_cmpxchg(&monitor_mount_is_active, 0, 1);
        spin_unlock(&lock);

        printk("%s: Device %s registered\n", MOD_NAME, dev_name);
        return 1;

    } else {

        if (device_registered->ss_is_active) {

            spin_unlock(&lock);
            printk("%s: Snapshot already active for device %s\n", MOD_NAME, dev_name);
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

            printk("%s: Snapshot activated for device %s\n", MOD_NAME, dev_name);
            return 1;
        }
    }
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
SYSCALL_DEFINE2(deactivate_snapshot, char *, dev_name, char *, password){
#else
asmlinkage long sys_deactivate_snapshot(char *dev_name, char *password){
#endif

    int process_is_root = current_euid().val;

    if (!process_is_root) {

        printk("%s: Only root can activate/deactivate snapshots\n", MOD_NAME);
        return 0;

    }

    int login_success = check_password(password);

    if (!login_success) {

        printk("%s: Incorrect password\n", MOD_NAME);
        return 0;

    }

    spin_lock(&lock);

    device_t *device_registered = search_device(dev_name);

    if (device_registered == NULL) {

        spin_unlock(&lock);
        printk("%s: Device %s not registered\n", MOD_NAME, dev_name);
        return 0;

    } else {

        if (device_registered->ss_is_active == 0) {

            spin_unlock(&lock);
            printk("%s: Snapshot already deactive for device %s\n", MOD_NAME, dev_name);
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
            
            printk("%s: Snapshot deactivated for device %s\n", MOD_NAME, dev_name);
            return 1;
    }
}

int hook_init(void) {

	int ret;

	ret = register_kprobe(&kp_mount);

	if (ret < 0) {
		pintk("%s: hook init failed, returned %d\n", MOD_NAME, ret);
		return ret;
	}

    ret = register_kprobe(&kp_umount);
    if (ret < 0) {
        printk("%s: hook init failed, returned %d\n", MOD_NAME, ret);
        return ret;
    }

	printk("%s: hook module correctly loaded.\n", MOD_NAME);
	
	return 0;
}

void hook_exit(void) {

	unregister_kprobe(&kp_mount);
    unregister_kprobe(&kp_umount);

	printk("%s: hook module unloaded\n", MOD_NAME);

}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
long sys_activate_snapshot = (unsigned long) __x64_sys_activate_snapshot;
long sys_deactivate_snapshot = (unsigned long) __x64_sys_deactivate_snapshot;       
#else
#endif


int init_module(void) {
    
    new_sys_call_array[0] = (unsigned long)sys_activate_snapshot;
    new_sys_call_array[1] = (unsigned long)sys_deactivate_snapshot;

    modify_syscall_table(new_sys_call_array, the_syscall_table, the_ni_syscall, restore);
    hook_init();

}


void cleanup_module(void) {

    restore_syscall_table(the_syscall_table, the_ni_syscall, restore);
    hook_exit();

}
