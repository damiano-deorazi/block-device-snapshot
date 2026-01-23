#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/namei.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/kernel.h>
#include <linux/timekeeping.h>
#include <linux/kdev_t.h>
#include <linux/major.h>
#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/file.h>

#include "bd_snapshot_kprobe.h"
#include "bd_snapshot_list.h"
#include "bd_snapshot.h"

#define target_mount_func "__x64_sys_move_mount"
#define target_umount_func "__x64_sys_umount"
#define target_write_func "__bread_gfp"

void replacechar(char *str, char orig, char rep) {

    char *ix = str;
    
    while((ix = strchr(ix, orig)) != NULL) {

        *ix++ = rep;
    
    }
}

void safe_disable_krp_wr(struct work_struct *work) {

    device_t *device;

    spin_lock(&lock);

    list_for_each_entry(device, &dev_list_head, device_list) { 
        
        //if (!(device->ss_is_active == 0 || (device->ss_is_active == 1 && device->mount_point[0] != '\0'))) {
        if (device->ss_is_active == 1 && device->mount_point[0] != '\0') {
            spin_unlock(&lock);
            return;
        }
        
    }

    spin_unlock(&lock);

    disable_kretprobe(&krp_write);

} 


void create_snapshot_folder(struct work_struct *work) {
    packed_work *the_task = container_of(work, packed_work, the_work);
    char *dir_name = the_task->snapshot_path;
    struct path path_parent;
    struct dentry *new_dentry;
    struct dentry *parent_dentry;
    int err;

    enable_kprobe(&kp_umount);
    enable_kretprobe(&krp_write);
    
    err = kern_path("/snapshot/", LOOKUP_FOLLOW, &path_parent);
    if (err) {
        printk("%s: kern_path failed for /snapshot/ with error %d.\n", MOD_NAME, err);
        goto out_free_task;
    }

    parent_dentry = path_parent.dentry;
    new_dentry = d_alloc_name(parent_dentry, dir_name);
    if (!new_dentry) {
        printk("%s: d_alloc_name failed for /snapshot/%s/.\n", MOD_NAME, dir_name);
        goto out_free_path;
    }

    err = vfs_mkdir(&nop_mnt_idmap, path_parent.dentry->d_inode, new_dentry, S_IRWXU);
    if (err) {
        printk("%s: vfs_mkdir failed for /snapshot/%s/ with error %d.\n", MOD_NAME, dir_name, err);
        goto out_free_dentry;
    }

    printk("%s: Snapshot folder created at /snapshot/%s\n", MOD_NAME, dir_name);

out_free_dentry:
    dput(new_dentry);
out_free_path:
    path_put(&path_parent);
out_free_task:
    kfree(dir_name);
    kfree(the_task);

    return;
}

void write_on_snapshot_folder(struct work_struct *work) {

    packed_work *the_task = container_of(work, packed_work, the_work);
    char *snapshot_path = the_task->snapshot_path;
    struct mutex *snapshot_lock = the_task->snapshot_lock;
    struct buffer_head* bh = the_task->bh;
    sector_t block_number = bh->b_blocknr;
    char *data = bh->b_data;
    struct file *fp;

    printk("%s: scrittura su snapshot in corso..(path=%s, block=%lld, data=%s)\n", MOD_NAME, snapshot_path, block_number, data);

    mutex_lock(snapshot_lock);

    printk("%s: scrittura su snapshot in corso... Lock acquisito\n", MOD_NAME);
    
    fp = filp_open(snapshot_path, O_CREAT|O_RDWR|O_APPEND, 0644);
    if (IS_ERR(fp)) {
        printk("%s: Impossibile aprire %s (Errore: %ld).\n", MOD_NAME, snapshot_path, PTR_ERR(fp));
        goto out_free_task;
    }

    printk("%s: cartella snapshot aperta (path=%s)\n", MOD_NAME, snapshot_path);
    printk("%s: posizione iniziale seek %lld\n", MOD_NAME, fp->f_pos);

    packed_data *read_data;
    read_data = kmalloc(sizeof(packed_data), GFP_KERNEL);
    if (!read_data) {
        printk("%s: kmalloc failed for read_data.\n", MOD_NAME);
        goto out_close;
    }
    
    for (;;) {
        ssize_t bytes_read = kernel_read(fp, read_data, sizeof(packed_data), &fp->f_pos);

        if (bytes_read < 0) {
            printk("%s: kernel_read failed for %s.\n", MOD_NAME, snapshot_path);
            goto out_free_rdata;
        } else if (bytes_read == 0) {
            // Fine del file raggiunta
            break;
        }

        if (read_data->block_number == block_number) {
            printk("%s: Block number %llu already exists in snapshot file %s. Skipping write.\n", MOD_NAME, block_number, snapshot_path);
            goto out_free_rdata;
        }
    }

    packed_data *data_to_write = NULL;
    data_to_write = kmalloc(sizeof(packed_data), GFP_KERNEL);
    if (!data_to_write) {
        printk("%s: kmalloc failed for data_to_write.\n", MOD_NAME);
        goto out_free_rdata;
    }
    data_to_write->block_number = block_number;
    memcpy(data_to_write->data, data, strlen(data));

    ssize_t bytes_written = kernel_write(fp, data_to_write, sizeof(packed_data), &fp->f_pos);

    if (bytes_written < 0) {
        printk("%s: kernel_write failed for %s.\n", MOD_NAME, snapshot_path);
        goto out_free_wdata;
    }
     
    printk("%s: Wrote %zd bytes to snapshot file %s (block number %llu).\n", MOD_NAME, bytes_written, snapshot_path, block_number);
    

out_free_wdata:
    kfree(data_to_write);
out_free_rdata:
    kfree(read_data);
    
out_close:
    filp_close(fp, NULL);
out_free_task:
    mutex_unlock(snapshot_lock);
    kfree(the_task);
    
    return;
}

int monitor_mount(struct kprobe *ri, struct pt_regs *the_regs) {
    printk("%s: mount rilevata\n", MOD_NAME);

    struct timespec64 ts;
    
    // Ottiene il tempo reale (wall-clock time)
    ktime_get_real_ts64(&ts);

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

	fd_path = kmalloc(BUFF_SIZE, GFP_ATOMIC);

    if (!fd_path) {
        printk("%s: kmalloc failed.\n", MOD_NAME);
        return 0;
    }

    if (snprintf(fd_path, BUFF_SIZE, "/proc/self/fd/%d", fd) < 0) {
        printk("%s: snprintf failed.\n", MOD_NAME);
        kfree(fd_path);
        return 0;
    }

    if (kern_path(fd_path, LOOKUP_FOLLOW, &the_path) < 0){
        printk("%s: kern_path failed for %s.\n", MOD_NAME, fd_path);
        kfree(fd_path);
        return 0;
    }

    kfree(fd_path);

    struct super_block *sb = the_path.mnt->mnt_sb;
    dev_t bd_dev = sb->s_dev;
    char *device_name = sb->s_id;

    path_put(&the_path);

    printk("%s: checking if dev is loop\n", MOD_NAME);

    if (MAJOR(bd_dev) != LOOP_MAJOR) {
        printk("%s: dev is not loop\n", MOD_NAME);

        char *snapshot_path = kmalloc(BUFF_SIZE, GFP_ATOMIC);

        if (!snapshot_path) {
            printk("%s: kmalloc failed for snapshot_path.\n", MOD_NAME);
            return 0;
        }
    
        if (snprintf(snapshot_path, BUFF_SIZE, "/snapshot/%s_%lld/snapshot_data", device_name, ts.tv_sec) < 0) {
            printk("%s: snprintf failed for snapshot_path.\n", MOD_NAME);
            kfree(snapshot_path);
            return 0;
        }
    
        //controllare la lista dei dispositivi monitorati tramite snapshot e agire di conseguenza
        spin_lock(&lock);

        device_t *device = NULL;    
        list_for_each_entry (device, &dev_list_head, device_list) { 
            
            if (device->ss_is_active == 1 && strcmp(device->device_name, device_name) == 0) {
                
                strcpy(device->mount_point, mount_path_buff);
                strcpy(device->ss_path, snapshot_path);
                device->sb = sb;
                
                printk("%s: updated mount point of %s to %s\n", MOD_NAME, device->device_name, device->mount_point);
                spin_unlock(&lock);

                //creazione della cartella dello snapshot

                packed_work *the_task;

                the_task = kmalloc(sizeof(packed_work), GFP_ATOMIC);
                if (the_task == NULL) {
                    printk("%s: workqueue task allocation failure\n", MOD_NAME);
                    return 0;
                }

                if (snprintf(snapshot_path, BUFF_SIZE, "%s_%lld", device_name, ts.tv_sec) < 0) {
                    printk("%s: snprintf failed for snapshot direcotry name.\n", MOD_NAME);
                    kfree(snapshot_path);
                    return 0;
                }
                
                the_task->snapshot_path = snapshot_path;
                INIT_WORK(&(the_task->the_work), (void*)create_snapshot_folder);
                schedule_work(&the_task->the_work);
                return 0;
            }
        }

        spin_unlock(&lock);
        return 0;
    
    } else {
        printk("%s: dev is loop\n", MOD_NAME);

        struct file *filploop;
        char *sysfs_path;
        char *backing_file_path;
        char *repc_backing_file_path;
        
        // Allocazione buffer per il percorso SysFS e il percorso di ritorno
        sysfs_path = kmalloc(BUFF_SIZE, GFP_ATOMIC);
        backing_file_path = kmalloc(BUFF_SIZE, GFP_ATOMIC);
        repc_backing_file_path = kmalloc(BUFF_SIZE, GFP_ATOMIC);

        if (!sysfs_path || !backing_file_path || !repc_backing_file_path) {
            printk("%s: kmalloc allocazione memoria fallita.\n", MOD_NAME);
            return 0;
        }

        // 1. Costruisci il percorso SysFS (es. /sys/block/loop0/loop/backing_file)
        if (snprintf(sysfs_path, BUFF_SIZE, "/sys/block/%s/loop/backing_file", device_name) < 0) {
            printk("%s: snprintf fallito.\n", MOD_NAME);
            goto out_free_data;
        }
        
        // 2. Apri il file SysFS
        // Usiamo O_RDONLY per la sola lettura. I permessi non sono necessari per un file SysFS.
        filploop = filp_open(sysfs_path, O_RDONLY, 0);

        if (IS_ERR(filploop)) {
            printk("%s: Impossibile aprire %s (Errore: %ld).\n", MOD_NAME, sysfs_path, PTR_ERR(filploop));
            goto out_free_data;
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
                        
        } else {
            printk("%s: Lettura SysFS fallita o file vuoto.\n", MOD_NAME);
            goto out_close_file;
        }

        printk("%s: devname is %s, trying to get lock\n", MOD_NAME, backing_file_path);

        //controllare la lista dei dispositivi monitorati tramite snapshot e agire di conseguenza utilizzando backing_file_path come device_name
        spin_lock(&lock);

        printk("%s: got the lock\n", MOD_NAME);
        
        char *snapshot_path = kmalloc(BUFF_SIZE, GFP_ATOMIC);

        if (!snapshot_path) {
            printk("%s: kmalloc failed for snapshot_path.\n", MOD_NAME);
            goto out_unlock_spin;
        }

        strcpy(repc_backing_file_path, backing_file_path);

        replacechar(repc_backing_file_path, '/', '_');

        //TODO verificare che il primo caraattere di backing_file_path sia '/' o gestire il caso contrario 
        if (snprintf(snapshot_path, BUFF_SIZE, "/snapshot/%s_%lld/snapshot_data", repc_backing_file_path, ts.tv_sec) < 0) {
            printk("%s: snprintf failed for snapshot_path.\n", MOD_NAME);
            goto out_unlock_spin;
        }

        printk("%s: new device name is %s\n", MOD_NAME, repc_backing_file_path);

        device_t *device = NULL;
        
        list_for_each_entry (device, &dev_list_head, device_list) { 
            
            if (device->ss_is_active == 1 && strcmp(device->device_name, backing_file_path) == 0) {
                
                strcpy(device->mount_point, mount_path_buff);
                strcpy(device->ss_path, snapshot_path);
                device->sb = sb;

                printk("%s: updated mount point of %s to %s\n", MOD_NAME, device->device_name, device->mount_point);
                spin_unlock(&lock);

                //creazione cartella dello snapshot

                packed_work *the_task;
                the_task = kmalloc(sizeof(packed_work), GFP_ATOMIC);
                if (the_task == NULL) {
                    printk("%s: workqueue task allocation failure\n", MOD_NAME);
                    goto out_close_file;
                }

                if (snprintf(snapshot_path, BUFF_SIZE, "%s_%lld", repc_backing_file_path, ts.tv_sec) < 0) {
                    printk("%s: snprintf failed for snapshot directory name.\n", MOD_NAME);
                    goto out_close_file;
                }
                    
                the_task->snapshot_path = snapshot_path;
                INIT_WORK(&(the_task->the_work), (void*)create_snapshot_folder);
                schedule_work(&the_task->the_work);

                goto out_close_file;

            }
        }
        
    out_unlock_spin:
        spin_unlock(&lock);
    out_close_file:
        filp_close(filploop, NULL);
    out_free_data:
        kfree(sysfs_path);
        kfree(backing_file_path);
        kfree(repc_backing_file_path);

        return 0;
    }
 
}

int monitor_umount(struct kprobe *ri, struct pt_regs *the_regs) {

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
            
            printk("%s: Removing %s device\n", MOD_NAME, device->device_name);

            remove(device);

            printk("%s: Removed\n", MOD_NAME);

            //TODO valutare se andare a rimuovere la cartella snapshot associata (non viene comunque utilizzata da nessuno)

            break;
        }

        if (device->ss_is_active == 1 && strcmp(device->mount_point, mount_path_buff) == 0) {

            device->mount_point[0] = '\0';
            printk("%s: reset of %s mount point \n", MOD_NAME, device->device_name);
            break;        
        }
    }

    spin_unlock(&lock);

    /*

    struct work_struct the_work; 

    INIT_WORK(&the_work, (void*)safe_disable_krp_wr);
    schedule_work(&the_work);

    */
    return 0;
}

int monitor_write(struct kretprobe_instance *ri, struct pt_regs *the_regs) {

    printk("%s: inizio gestione scrittura\n", MOD_NAME);

    struct buffer_head *bh = (struct buffer_head *)regs_return_value(the_regs);

    dev_t bd_dev = bh->b_bdev->bd_dev;

    device_t *device = NULL;

    spin_lock(&lock);

    list_for_each_entry(device, &dev_list_head, device_list) { 
        
        if (device->ss_is_active == 1 && device->sb->s_dev == bd_dev) {
            char *snapshot_path = device->ss_path;
            struct mutex *snapshot_lock = &device->snapshot_lock;
            
            spin_unlock(&lock);

            packed_work *the_task;
            the_task = kmalloc(sizeof(packed_work), GFP_ATOMIC);
            if (the_task == NULL) {
                printk("%s: workqueue task allocation failure\n", MOD_NAME);
                return 0;
            }
            
            the_task->snapshot_path = snapshot_path;
            the_task->snapshot_lock = snapshot_lock;
            the_task->bh = bh;
            INIT_WORK(&(the_task->the_work), (void*)write_on_snapshot_folder);
            schedule_work(&the_task->the_work);

            return 0;
        }
    }   

    return 0;
}

struct kprobe kp_mount = {
    .symbol_name = target_mount_func,
    .pre_handler = (kprobe_pre_handler_t)monitor_mount,
};

struct kprobe kp_umount = {
    .symbol_name = target_umount_func,
    .pre_handler = (kprobe_pre_handler_t)monitor_umount,
};

struct kretprobe krp_write = {
    .kp.symbol_name = target_write_func,
    .handler = (kretprobe_handler_t)monitor_write,
};
