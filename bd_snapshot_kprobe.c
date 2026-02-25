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
#include <linux/dcache.h>

#include "include/bd_snapshot_kprobe.h"
#include "include/bd_snapshot_data.h"
#include "include/bd_snapshot_list.h"
#include "include/bd_snapshot.h"
#include "SINGLEFILE-FS/singlefilefs.h"


#define target_mount_func "mount_bdev"
#define target_umount_func "kill_block_super"
#define target_write_func "__bread_gfp"

struct workqueue_struct *snapshot_wq;

void replacechar(char *str, char orig, char rep) {

    char *ix = str;
    
    while((ix = strchr(ix, orig)) != NULL) {
        *ix++ = rep;
    }
}

void create_snapshot_folder(struct work_struct *work) {

    packed_work *the_task = container_of(work, packed_work, the_work);
    char *dir_name = the_task->snapshot_path;
    struct path path_parent;
    struct dentry *new_dentry;
    struct dentry *parent_dentry;
    int err;
    
    err = kern_path("/snapshot/", LOOKUP_FOLLOW, &path_parent);
    if (err) {
        printk("%s: kern_path failed for /snapshot/ with error %d.\n", MODNAME, err);
        goto out_free_task;
    }

    parent_dentry = path_parent.dentry;
    new_dentry = d_alloc_name(parent_dentry, dir_name);
    if (!new_dentry) {
        printk("%s: d_alloc_name failed for /snapshot/%s/.\n", MODNAME, dir_name);
        goto out_free_path;
    }

    err = vfs_mkdir(&nop_mnt_idmap, path_parent.dentry->d_inode, new_dentry, S_IRWXU);
    if (err) {
        printk("%s: vfs_mkdir failed for /snapshot/%s/ with error %d.\n", MODNAME, dir_name, err);
        goto out_free_dentry;
    }

    printk("%s: Snapshot folder created at /snapshot/%s\n", MODNAME, dir_name);

    enable_kretprobe(&krp_write);

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
    unsigned long long block_number = bh->b_blocknr;
    char *data = bh->b_data;
    struct file *fp;
    size_t size;

    mutex_lock(snapshot_lock);

    if (block_number == 1) {
        struct onefilefs_inode *inode_info = (struct onefilefs_inode *)data;
        printk("%s: Block number 1 contains inode information - inode_no: %lld, file size: %llu (SIZE da strlen(data)=%ld)\n", 
            MODNAME, inode_info->inode_no, inode_info->file_size, strlen(data));
    }


    
    fp = filp_open(snapshot_path, O_CREAT|O_RDWR|O_APPEND, 0644);
    if (IS_ERR(fp)) {
        printk("%s: error opening snapshot directory %s (Errore: %ld).\n", MODNAME, snapshot_path, PTR_ERR(fp));
        goto out_free_task;
    }

    packed_data *read_data;
    read_data = kmalloc(sizeof(packed_data), GFP_KERNEL);
    if (!read_data) {
        printk("%s: kmalloc failed for read_data.\n", MODNAME);
        goto out_close;
    }
    
    for (;;) {
        ssize_t bytes_read = kernel_read(fp, read_data, sizeof(packed_data), &fp->f_pos);
        if (bytes_read < 0) {
            printk("%s: kernel_read failed for %s.\n", MODNAME, snapshot_path);
            goto out_free_rdata;
        } else if (bytes_read == 0) {
            break;
        }

        if (read_data->block_number == block_number) {
            printk("%s: Block number %llu already exists in snapshot file %s. Skipping write.\n", MODNAME, block_number, snapshot_path);
            goto out_free_rdata;
        }
    }

    packed_data *data_to_write = NULL;
    data_to_write = kmalloc(sizeof(packed_data), GFP_KERNEL);
    if (!data_to_write) {
        printk("%s: kmalloc failed for data_to_write.\n", MODNAME);
        goto out_free_rdata;
    }

    //blocco inode
    if (block_number == 1) {
        size = sizeof(struct onefilefs_inode);
    }

    //blocco dati
    if (block_number == 2)  {
        size = strlen(data);
    }

    data_to_write->block_number = block_number;
    memcpy(data_to_write->data, data, size);

    brelse(bh); //rilascio il buffer head dopo aver copiato i dati 

    ssize_t bytes_written = kernel_write(fp, data_to_write, sizeof(packed_data), &fp->f_pos);
    if (bytes_written < 0) {
        printk("%s: kernel_write failed for %s.\n", MODNAME, snapshot_path);
        goto out_free_wdata;
    }
    
    printk("%s: Wrote %zd bytes to snapshot file %s (block number %llu).\n", MODNAME, bytes_written, snapshot_path, block_number);

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

int monitor_mount_entry_handler(struct kretprobe_instance *ri, struct pt_regs *the_regs) {

    kret_data *data;

    data = (kret_data *)ri->data;
    data->fs_type = (struct file_system_type *)the_regs->di;
    data->flags = (int)the_regs->si;
    data->dev_name = (const char *)the_regs->dx;

    return 0;
}

int monitor_mount_ret_handler(struct kretprobe_instance *ri, struct pt_regs *the_regs) {

    const char *dev_name;
    device_t *device;   
    struct timespec64 ts;
    struct dentry *dev_dentry;
    kret_data *data;
    struct super_block *sb;
    dev_t bd_dev;


    data = (kret_data *)ri->data;
    ktime_get_real_ts64(&ts);

    dev_dentry = (struct dentry *)regs_return_value(the_regs);
    if (IS_ERR(dev_dentry)) {
        printk("%s: mount failed with error %ld.\n", MODNAME, PTR_ERR(dev_dentry));
        return 0;
    }

    sb = dev_dentry->d_sb;
    bd_dev = sb->s_bdev->bd_dev;
    dev_name = data->dev_name;

    if (MAJOR(bd_dev) != LOOP_MAJOR) {
        char *snapshot_path = kmalloc(BUFF_SIZE, GFP_ATOMIC);
        if (!snapshot_path) {
            printk("%s: kmalloc failed for snapshot_path.\n", MODNAME);
            return 0;
        }
    
        if (snprintf(snapshot_path, BUFF_SIZE, "/snapshot/%s_%lld/snapshot_data", dev_name, ts.tv_sec) < 0) {
            printk("%s: snprintf failed for snapshot_path.\n", MODNAME);
            kfree(snapshot_path);
            return 0;
        }
    
        spin_lock(&lock);

        device = search_device(dev_name);
        if (device == NULL) {
            printk("%s: Device %s not registered, skipping snapshot creation.\n", MODNAME, dev_name);
            spin_unlock(&lock);
            return 0;

        } else {

            strcpy(device->ss_path, snapshot_path);
            device->dev_is_mounted = 1;
            device->dev_id = bd_dev;
            
            spin_unlock(&lock);

            enable_kprobe(&kp_umount);

            packed_work *the_task;

            the_task = kmalloc(sizeof(packed_work), GFP_ATOMIC);
            if (the_task == NULL) {
                printk("%s: workqueue task allocation failure\n", MODNAME);
                return 0;
            }

            if (snprintf(snapshot_path, BUFF_SIZE, "%s_%lld", dev_name, ts.tv_sec) < 0) {
                printk("%s: snprintf failed for snapshot direcotry name.\n", MODNAME);
                kfree(snapshot_path);
                return 0;
            }
            
            the_task->snapshot_path = snapshot_path;
            INIT_WORK(&(the_task->the_work), (void*)create_snapshot_folder);
            queue_work(snapshot_wq, &the_task->the_work);
            return 0;
        }
    
    } else {

        struct file *filploop;
        char *sysfs_path, *backing_file_path, *repc_backing_file_path;
        
        sysfs_path = kmalloc(BUFF_SIZE, GFP_ATOMIC);
        backing_file_path = kmalloc(BUFF_SIZE, GFP_ATOMIC);
        repc_backing_file_path = kmalloc(BUFF_SIZE, GFP_ATOMIC);

        if (!sysfs_path || !backing_file_path || !repc_backing_file_path) {
            printk("%s: kmalloc failed.\n", MOD_NAME);
            return 0;
        }

        if (snprintf(sysfs_path, BUFF_SIZE, "/sys/block/%s/loop/backing_file", dev_name+4) < 0) {
            printk("%s: snprintf failed.\n", MOD_NAME);
            goto out_free_data;
        }
        
        filploop = filp_open(sysfs_path, O_RDONLY, 0);

        if (IS_ERR(filploop)) {
            printk("%s: error opening %s (Errore: %ld).\n", MOD_NAME, sysfs_path, PTR_ERR(filploop));
            goto out_free_data;
        }
        
        loff_t pos = 0;
        ssize_t bytes_read;
        
        bytes_read = kernel_read(filploop, backing_file_path, BUFF_SIZE - 1, &pos);
        
        if (bytes_read > 0) {
            if (backing_file_path[bytes_read - 1] == '\n') {
                bytes_read--;
            }

            backing_file_path[bytes_read] = '\0';
                        
        } else {
            printk("%s: kernel_read failed for %s.\n", MOD_NAME, sysfs_path);
            goto out_close_file;
        }

        spin_lock(&lock);
                
        char *snapshot_path = kmalloc(BUFF_SIZE, GFP_ATOMIC);

        if (!snapshot_path) {
            printk("%s: kmalloc failed for snapshot_path.\n", MOD_NAME);
            goto out_unlock_spin;
        }

        strcpy(repc_backing_file_path, backing_file_path);
        replacechar(repc_backing_file_path, '/', '_');

        if (snprintf(snapshot_path, BUFF_SIZE, "/snapshot/%s_%lld/snapshot_data", repc_backing_file_path, ts.tv_sec) < 0) {
            printk("%s: snprintf failed for snapshot_path.\n", MOD_NAME);
            goto out_unlock_spin;
        }

        device = search_device(backing_file_path);
        if (device == NULL) {
            printk("%s: Device %s not registered, skipping snapshot creation.\n", MODNAME, backing_file_path);
            goto out_unlock_spin;

        } else {

            strcpy(device->ss_path, snapshot_path);
            device->dev_is_mounted = 1;
            device->dev_id = bd_dev;

            spin_unlock(&lock);

            enable_kprobe(&kp_umount);

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
            queue_work(snapshot_wq, &the_task->the_work);

            goto out_close_file;
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
    
    struct super_block *sb;
    device_t *device; 
    int umount_notified, mnt_devices;
    
    sb = (struct super_block *)the_regs->di;
    if (sb == NULL) {
        printk("%s: error reading the super_block pointer from register\n", MODNAME);
        return 0;
    }

    spin_lock(&lock);

    umount_notified = 0;
    mnt_devices = 0;
    list_for_each_entry(device, &dev_list_head, device_list) {   
 
        if (umount_notified && mnt_devices > 0) {
            break;
        }

        if (device->dev_id == sb->s_dev) {
            device->dev_is_mounted = 0;
            umount_notified = 1;
            printk("%s: device %s unmounted\n", MODNAME, device->device_name);
            continue; 

        }

        if (device->dev_is_mounted) {
            mnt_devices++;
        }
    }

    if (umount_notified && mnt_devices == 0) {
        disable_kretprobe(&krp_write);
        disable_kprobe(&kp_umount);
        printk("%s: umount and write probes disabled\n", MODNAME);
    }

    spin_unlock(&lock);
  
    return 0;
}

int monitor_write(struct kretprobe_instance *ri, struct pt_regs *the_regs) {

    struct buffer_head *bh = (struct buffer_head *)regs_return_value(the_regs);
    dev_t bd_dev = bh->b_bdev->bd_dev;
    device_t *device = NULL;

    if (bh->b_blocknr == 0) {   //ignoro il superblock
        printk("%s: block number is 0. Skipped...\n", MODNAME);
        return 0;
    }

    spin_lock(&lock);
    
    list_for_each_entry(device, &dev_list_head, device_list) {    
        if (device->dev_id == bd_dev) {
            char *snapshot_path = device->ss_path;
            struct mutex *snapshot_lock = &device->snapshot_lock;
            
            spin_unlock(&lock);

            packed_work *the_task;
            the_task = kmalloc(sizeof(packed_work), GFP_ATOMIC);
            if (the_task == NULL) {
                printk("%s: workqueue task allocation failure\n", MODNAME);
                return 0;
            }
            
            the_task->snapshot_path = snapshot_path;
            the_task->snapshot_lock = snapshot_lock;
            the_task->bh = bh;
            get_bh(bh); //incremento il contatore di utilizzo del buffer head per evitare che venga rilasciato prima che la workqueue abbia finito di usarlo
            INIT_WORK(&(the_task->the_work), (void*)write_on_snapshot_folder);
            queue_work(snapshot_wq, &the_task->the_work);

            return 0;
        }
    }   

    spin_unlock(&lock);

    return 0;
}

struct kretprobe krp_mount = {
    .handler = monitor_mount_ret_handler,
    .entry_handler = monitor_mount_entry_handler,
    .data_size = sizeof(kret_data),
    .maxactive = 20,
    .kp.symbol_name = target_mount_func,
};

struct kprobe kp_umount = {
    .symbol_name = target_umount_func,
    .pre_handler = (kprobe_pre_handler_t)monitor_umount,
};

struct kretprobe krp_write = {
    .kp.symbol_name = target_write_func,
    .handler = (kretprobe_handler_t)monitor_write,
};
