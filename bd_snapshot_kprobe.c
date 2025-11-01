#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/namei.h>
#include <linux/string.h>
#include <linux/spinlock.h>

#include "bd_snapshot_kprobe.h"
#include "bd_snapshot_list.h"
#include "bd_snapshot.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
#define target_mount_func "__x64_sys_move_mount"
#define target_umount_func "__x64_sys_umount"
#else
#define target__mount_func "__x64_sys_fsmount"
#endif

int monitor_mount(struct kprobe *ri, struct pt_regs *the_regs) {
    if (atomic_read(&monitor_mount_is_active) == 0) {
        return 1;
    }

    struct pt_regs *regs = (struct pt_regs *)the_regs->di;
    
    const char __user *mount_path;
	char mount_path_buff[BUFF_SIZE];

    int fd = (int)regs->di;
	mount_path = (const char __user *)regs->r10;

    if (mount_path) {
		if (strncpy_from_user(mount_path_buff, mount_path, BUFF_SIZE - 1) < 0){
			printk("%s: error reading the mount pathname\n", MOD_NAME);
			return 0;
		}
		mount_path_buff[BUFF_SIZE - 1] = '\0';
	} else {
		printk("%s: error reading the mount pathname from register\n", MOD_NAME);
		return 0;

    }

    char *fd_path;
    
    struct path the_path;

	fd_path = kmalloc(BUFF_SIZE, GFP_KERNEL);

    if (!fd_path) {
        printk("%s: kmalloc failed.\n", MOD_NAME);
        return 0;
    }

    // 2. Costruisci la stringa del percorso: /proc/self/fd/<dfd>
    if (snprintf(fd_path, BUFF_SIZE, "/proc/self/fd/%d", fd)) < 0 {
        printk("%s: snprintf failed.\n", MOD_NAME);
        kfree(fd_path);
        return 0;
    }

    // 3. Risolvi il percorso usando l'esportata kern_path (risoluzione del path assoluto)
    // Usiamo LOOKUP_FOLLOW per seguire il symlink da /proc/self/fd/<dfd> all'oggetto reale.
    if (kern_path(fd_path, LOOKUP_FOLLOW, &the_path) < 0){
        printk("%s: kern_path failed for %s.\n", MOD_NAME, fd_path);
        kfree(fd_path);
        return 0;
    }
    // Rilascia la memoria non appena non serve più il buffer
    kfree(fd_path);
	
	// 2. Accedi al superblock attraverso il path del file
	// f_path.mnt->mnt_sb è la catena di navigazione

    struct super_block *sb = path.mnt->mnt_sb;
	char *device_name = sb->s_id;

    path_put(&the_path);

    if (strstr(device_name, "loop") == NULL) {

        //controllare la lista dei dispositivi monitorati tramite snapshot e agire di conseguenza
        spin_lock(&lock);

        device_t *device = NULL;    
        list_for_each_entry (device, &dev_list_head, device_list) { 
            
            if (device->ss_is_active == 1 && strcmp(device->device_name, device_name) == 0) {
                device->mount_point = mount_path_buff;
                printk("%s: updated mount point of %s to %s\n", MOD_NAME, device->device_name, device->mount_point);
                spin_unlock(&lock);
                return 1;
            }
        }

        spin_unlock(&lock);
        return 1;
    
    } else {

        struct file *filploop = NULL;
        char *sysfs_path = NULL;
        char *backing_file_path = NULL;
        
        // Allocazione buffer per il percorso SysFS e il percorso di ritorno
        sysfs_path = kmalloc(BUFF_SIZE, GFP_KERNEL);
        backing_file_path = kmalloc(BUFF_SIZE, GFP_KERNEL);

        if (!sysfs_path || !backing_file_path) {
            printk("%s: kmalloc allocazione memoria fallita.\n", MOD_NAME);
            return 0;
        }

        // 1. Costruisci il percorso SysFS (es. /sys/block/loop0/loop/backing_file)
        if (snprintf(sysfs_path, BUFF_SIZE, "/sys/block/%s/loop/backing_file", device_name) < 0) {
            printk("%s: snprintf fallito.\n", MOD_NAME);
            return 0;
        }
        
        // 2. Apri il file SysFS
        // Usiamo O_RDONLY per la sola lettura. I permessi non sono necessari per un file SysFS.
        filploop = filp_open(sysfs_path, O_RDONLY, 0);

        if (IS_ERR(filploop)) {
            printk("%s: Impossibile aprire %s (Errore: %ld).\n", sysfs_path, PTR_ERR(filploop), MOD_NAME);
            return 0;
        }
        
        // 3. Leggi il contenuto del file (il percorso assoluto)
        loff_t pos = 0;
        ssize_t bytes_read;
        
        bytes_read = kernel_read(filploop, backing_file_path, BUFF_SIZE - 1, &pos);
        
        if (bytes_read > 0) {
            // Rimuovi newline e termina la stringa
            if (backing_file_path[bytes_read - 1] == '\n') {
                bytes_read--;
            }
            backing_file_path[bytes_read] = '\0';
            
            // Successo: liberiamo solo il buffer del path SysFS e restituiamo il percorso letto
            kfree(sysfs_path);
            
        } else {
            printk("%s: Lettura SysFS fallita o file vuoto.\n", MOD_NAME);
            return 0;
        }

        // 4. Chiudi il file
        filp_close(filploop, NULL);

        //controllare la lista dei dispositivi monitorati tramite snapshot e agire di conseguenza utilizzando backing_file_path come device_name
        spin_lock(&lock);
        device_t *device = NULL;
        list_for_each_entry (device, &dev_list_head, device_list) { 
            
            if (device->ss_is_active == 1 && strcmp(device->device_name, backing_file_path) == 0) {
                device->mount_point = mount_path_buff;
                printk("%s: updated mount point of %s to %s\n", MOD_NAME, device->device_name, device->mount_point);
                spin_unlock(&lock);
                return 1;
            }
        }
        
        spin_unlock(&lock);

        return 1;
    }
 
}

int monitor_umount(struct kprobe *ri, struct pt_regs *the_regs) {
    
    if (atomic_read(&monitor_umount_is_active) == 0) {
        return 1;
    }

    struct pt_regs *regs = (struct pt_regs *)the_regs->di;
    
    const char __user *mount_path;
	char mount_path_buff[BUFF_SIZE];

	mount_path = (const char __user *)regs->di;

    if (mount_path) {
		if (strncpy_from_user(mount_path_buff, mount_path, BUFF_SIZE - 1) < 0){
			printk("%s: error reading the mount pathname\n", MOD_NAME);
			return 0;
		}
		mount_path_buff[BUFF_SIZE - 1] = '\0';
	} else {
		printk("%s: error reading the mount pathname from register\n", MOD_NAME);
		return 0;

    }

    device_t *device = NULL; 

    spin_lock(&lock);

    list_for_each_entry(device, &dev_list_head, device_list) { 
        
        if (device->ss_is_active == 0 && strcmp(device->mount_point, mount_path_buff) == 0) {
            device->mount_point = "";
            printk("%s: reset of %s mount point \n", MOD_NAME, device->device_name);
            spin_unlock(&lock);
            return 1;
        }
    }

    spin_unlock(&lock);

    return 1;
}

struct kprobe kp_mount = {
    .symbol_name = target_monut_func,
    .post_handler = (kprobe_post_handler_t)monitor_mount,
};

struct kprobe kp_umount = {
    .symbol_name = target_umount_func,
    .post_handler = (kprobe_post_handler_t)monitor_umount,
};

