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
#include "include/bd_snapshot_list.h"
#include "include/bd_snapshot.h"

//#define target_move_mount_func "__x64_sys_move_mount"
//#define target_move_mount_func "__x64_sys_mount"
#define target_mount_func "mount_bdev"
//#define target_umount_func "__x64_sys_umount"
#define target_umount_func "kill_block_super"
#define target_write_func "__bread_gfp"
//#define target_write_func "write_dirty_buffer"

struct workqueue_struct *snapshot_wq;


struct onefilefs_inode {
	mode_t mode;//not exploited
	uint64_t inode_no;
	uint64_t data_block_number;//not exploited

	union {
		uint64_t file_size;
		uint64_t dir_children_count;
	};
};




void replacechar(char *str, char orig, char rep) {

    char *ix = str;
    
    while((ix = strchr(ix, orig)) != NULL) {
        *ix++ = rep;
    }
}


//TODO valutare se rimouovere o meno gli spinlock (non sono necessari se si usano le workqueue)
void safe_disable_krp_wr(struct work_struct *work) {

    device_t *device;

    spin_lock(&lock);

    list_for_each_entry(device, &dev_list_head, device_list) {   
        //if (device->ss_is_active == 1 && device->mount_point[0] != '\0') {
        if (device->ss_is_active && device->dev_is_mounted) {
        
            spin_unlock(&lock);
            return;
        }
    }

    spin_unlock(&lock);

    disable_kretprobe(&krp_write);
    //disable_kprobe(&kp_write);

    kfree(work);

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
    //enable_kprobe(&kp_write);
    
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
    unsigned long long block_number = bh->b_blocknr;
    char *data = bh->b_data;
    struct file *fp;
    size_t size;

    mutex_lock(snapshot_lock);

    if (block_number == 1) {
        struct onefilefs_inode *inode_info = (struct onefilefs_inode *)data;
        printk("%s: Block number 1 contains inode information - inode_no: %lld, file size: %llu (SIZE da strlen(data)=%ld)\n", 
            MOD_NAME, inode_info->inode_no, inode_info->file_size, strlen(data));
    }


    
    fp = filp_open(snapshot_path, O_CREAT|O_RDWR|O_APPEND, 0644);
    if (IS_ERR(fp)) {
        printk("%s: error opening snapshot directory %s (Errore: %ld).\n", MOD_NAME, snapshot_path, PTR_ERR(fp));
        goto out_free_task;
    }

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

    //blocco inode
    if (block_number == 1) {
        size = sizeof(struct onefilefs_inode);
    }

    //blocco dati
    if (block_number ==2)  {
        size = strlen(data);
    }

    data_to_write->block_number = block_number;
    memcpy(data_to_write->data, data, size);

    brelse(bh); //rilascio il buffer head dopo aver copiato i dati 

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

    /* packed_work *the_task = container_of(work, packed_work, the_work);
    char *snapshot_path = the_task->snapshot_path;
    struct mutex *snapshot_lock = the_task->snapshot_lock;
    unsigned long long block_number = the_task->block_number;
    char *data = the_task->data;
    struct file *fp;

    mutex_lock(snapshot_lock);
    
    fp = filp_open(snapshot_path, O_CREAT|O_RDWR|O_APPEND, 0644);
    if (IS_ERR(fp)) {
        printk("%s: error opening snapshot directory %s (Errore: %ld).\n", MOD_NAME, snapshot_path, PTR_ERR(fp));
        goto out_free_task;
    }

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
 */
}

int monitor_mount_entry_handler(struct kretprobe_instance *ri, struct pt_regs *the_regs) {

    const char *dev_name;
    int flags;
    struct file_system_type *fs_type;
    kret_data *data;

    data = (kret_data *)ri->data;
    data->fs_type = (struct file_system_type *)the_regs->di;
    data->flags = (int)the_regs->si;
    data->dev_name = (const char *)the_regs->dx;

    return 0;
}

int monitor_mount_ret_handler(struct kretprobe_instance *ri, struct pt_regs *the_regs) {

    const char *dev_name;
    struct timespec64 ts;
    struct dentry *dev_dentry;
    kret_data *data;
    struct super_block *sb;
    dev_t bd_dev;


    data = (kret_data *)ri->data;
    ktime_get_real_ts64(&ts);

    dev_dentry = (struct dentry *)regs_return_value(the_regs);
    if (IS_ERR(dev_dentry)) {
        printk("%s: mount failed with error %ld.\n", MOD_NAME, PTR_ERR(dev_dentry));
        return 0;
    }

    sb = dev_dentry->d_sb;
    bd_dev = sb->s_bdev->bd_dev;
    dev_name = data->dev_name;

    if (MAJOR(bd_dev) != LOOP_MAJOR) {
        char *snapshot_path = kmalloc(BUFF_SIZE, GFP_ATOMIC);
        if (!snapshot_path) {
            printk("%s: kmalloc failed for snapshot_path.\n", MOD_NAME);
            return 0;
        }
    
        if (snprintf(snapshot_path, BUFF_SIZE, "/snapshot/%s_%lld/snapshot_data", dev_name, ts.tv_sec) < 0) {
            printk("%s: snprintf failed for snapshot_path.\n", MOD_NAME);
            kfree(snapshot_path);
            return 0;
        }
    
        spin_lock(&lock);

        device_t *device = NULL;    
        list_for_each_entry (device, &dev_list_head, device_list) { 
            if (device->ss_is_active == 1 && strcmp(device->device_name, dev_name) == 0) {
                strcpy(device->ss_path, snapshot_path);
                device->dev_is_mounted = 1;
                device->dev_id = bd_dev;
                
                spin_unlock(&lock);

                packed_work *the_task;

                the_task = kmalloc(sizeof(packed_work), GFP_ATOMIC);
                if (the_task == NULL) {
                    printk("%s: workqueue task allocation failure\n", MOD_NAME);
                    return 0;
                }

                if (snprintf(snapshot_path, BUFF_SIZE, "%s_%lld", dev_name, ts.tv_sec) < 0) {
                    printk("%s: snprintf failed for snapshot direcotry name.\n", MOD_NAME);
                    kfree(snapshot_path);
                    return 0;
                }
                
                the_task->snapshot_path = snapshot_path;
                INIT_WORK(&(the_task->the_work), (void*)create_snapshot_folder);
                queue_work(snapshot_wq, &the_task->the_work);
                return 0;
            }
        }

        spin_unlock(&lock);
        return 0;
    
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

        device_t *device = NULL;        
        list_for_each_entry (device, &dev_list_head, device_list) {     
            if (device->ss_is_active == 1 && strcmp(device->device_name, backing_file_path) == 0) {  
                //strcpy(device->mount_point, mount_path_buff);
                strcpy(device->ss_path, snapshot_path);
                device->dev_is_mounted = 1;
                device->dev_id = bd_dev;

                spin_unlock(&lock);

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

/* int monitor_move_mount(struct kprobe *ri, struct pt_regs *the_regs) {

    struct timespec64 ts;
    ktime_get_real_ts64(&ts);

    struct pt_regs *regs = (struct pt_regs *)the_regs->di;
    
    const char __user *mount_path;
	char mount_path_buff[BUFF_SIZE];

    int fd = (int)regs->di;
	mount_path = (const char __user *)regs->r10;

    if (mount_path) {
		if (strncpy_from_user(mount_path_buff, mount_path, BUFF_SIZE - 1) < 0) {
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

    if (MAJOR(bd_dev) != LOOP_MAJOR) {
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
    
        spin_lock(&lock);

        device_t *device = NULL;    
        list_for_each_entry (device, &dev_list_head, device_list) { 
            if (device->ss_is_active == 1 && strcmp(device->device_name, device_name) == 0) {
                strcpy(device->mount_point, mount_path_buff);
                strcpy(device->ss_path, snapshot_path);
                device->sb = sb;
                
                printk("%s: updated mount point of %s to %s\n", MOD_NAME, device->device_name, device->mount_point);
                spin_unlock(&lock);

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
                queue_work(snapshot_wq, &the_task->the_work);
                return 0;
            }
        }

        spin_unlock(&lock);
        return 0;
    
    } else {

        struct file *filploop;
        char *sysfs_path;
        char *backing_file_path;
        char *repc_backing_file_path;
        
        sysfs_path = kmalloc(BUFF_SIZE, GFP_ATOMIC);
        backing_file_path = kmalloc(BUFF_SIZE, GFP_ATOMIC);
        repc_backing_file_path = kmalloc(BUFF_SIZE, GFP_ATOMIC);

        if (!sysfs_path || !backing_file_path || !repc_backing_file_path) {
            printk("%s: kmalloc failed.\n", MOD_NAME);
            return 0;
        }

        if (snprintf(sysfs_path, BUFF_SIZE, "/sys/block/%s/loop/backing_file", device_name) < 0) {
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

        device_t *device = NULL;        
        list_for_each_entry (device, &dev_list_head, device_list) {     
            if (device->ss_is_active == 1 && strcmp(device->device_name, backing_file_path) == 0) {  
                strcpy(device->mount_point, mount_path_buff);
                strcpy(device->ss_path, snapshot_path);
                device->sb = sb;

                printk("%s: updated mount point of %s to %s\n", MOD_NAME, device->device_name, device->mount_point);
                spin_unlock(&lock);

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
 */

int monitor_umount(struct kprobe *ri, struct pt_regs *the_regs) {
    //printk("%s: unmounting device\n", MOD_NAME);

    //struct pt_regs *regs = (struct pt_regs *)the_regs->di;

    //const char __user *mount_path;
	//char mount_path_buff[BUFF_SIZE];
    
    struct super_block *sb;
    
    sb = (struct super_block *)the_regs->di;
    if (sb == NULL) {
        printk("%s: error reading the super_block pointer from register\n", MOD_NAME);
        return 0;
    }

    printk("%s: unmounting device \n", MOD_NAME);
    printk("%s: unmounting device with dev_id %u\n", MOD_NAME, sb->s_dev);

    /* if (mount_path) {
		if (strncpy_from_user(mount_path_buff, mount_path, BUFF_SIZE - 1) < 0){
			printk("%s: error reading the mount pathname\n", MOD_NAME);
			return 0;
		}
		mount_path_buff[BUFF_SIZE - 1] = '\0';
	} else {
		printk("%s: error reading the mount pathname from register\n", MOD_NAME);
		return 0;
    } */



    device_t *device = NULL; 

    spin_lock(&lock);

    list_for_each_entry(device, &dev_list_head, device_list) {   
 


        /*if (device->ss_is_active == 0 && strcmp(device->mount_point, mount_path_buff) == 0) {    
            printk("%s: Removing %s device\n", MOD_NAME, device->device_name);
            remove(device);
            printk("%s: Removed\n", MOD_NAME);
            break;
        }

        if (device->ss_is_active == 1 && strcmp(device->mount_point, mount_path_buff) == 0) {
            device->mount_point[0] = '\0';
            printk("%s: reset of %s mount point \n", MOD_NAME, device->device_name);
            break;        
        }*/


        //printk("%s: Checking device %s with dev_id %u\n", MOD_NAME, device->device_name, device->dev_id);
        //printk("%s: loop in corso...\n", MOD_NAME);

        if (device->ss_is_active && device->dev_id == sb->s_dev) {
            //device->mount_point[0] = '\0';
            device->dev_is_mounted = 0;
            printk("%s: device %s unmounted\n", MOD_NAME, device->device_name);
            break;        
        }

        //TODO valutare se lasciare questo controllo per la rimozione di uno snapshot disattivato
        /* if (device->ss_is_active == 0 && device->dev_id == sb->s_dev) {    
            printk("%s: Removing %s device\n", MOD_NAME, device->device_name);
            remove(device);
            printk("%s: Removed\n", MOD_NAME);
            break;
        } */
    }

    spin_unlock(&lock);

    struct work_struct *the_work; 
    the_work = kmalloc(sizeof(struct work_struct), GFP_ATOMIC);
    if (the_work == NULL) {
        printk("%s: workqueue task allocation failure\n", MOD_NAME);
        return 0;
    }

    INIT_WORK(the_work, (void*)safe_disable_krp_wr);
    queue_work(snapshot_wq, the_work);
  
    return 0;
}

int monitor_write(struct kretprobe_instance *ri, struct pt_regs *the_regs) {

    struct buffer_head *bh = (struct buffer_head *)regs_return_value(the_regs);
    dev_t bd_dev = bh->b_bdev->bd_dev;
    device_t *device = NULL;

    if (bh->b_blocknr == 0) {   //ignoro il superblock
        printk("%s: block number is 0. Skipped...\n", MOD_NAME);
        return 0;
    }

    /*if (bh->b_blocknr == 1){
        printk("%s: block number is 1\n", MOD_NAME);
        struct onefilefs_inode *inode = (struct onefilefs_inode *)bh->b_data;
        printk("%s: inode info - inode_no: %llu, file size: %llu\n", MOD_NAME, inode->inode_no, inode->file_size);
        return 0;
    } */


    spin_lock(&lock);
    
    list_for_each_entry(device, &dev_list_head, device_list) {    
        if (device->ss_is_active == 1 && device->dev_id == bd_dev) {
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
            get_bh(bh); //incremento il contatore di utilizzo del buffer head per evitare che venga rilasciato prima che la workqueue abbia finito di usarlo
            INIT_WORK(&(the_task->the_work), (void*)write_on_snapshot_folder);
            queue_work(snapshot_wq, &the_task->the_work);

            return 0;
        }
    }   

    spin_unlock(&lock);

    return 0;
}

/* int monitor_write(struct kprobe *ri, struct pt_regs *the_regs) {

    struct buffer_head *bh, *bh_um;
    struct super_block *sb;
    dev_t bd_dev;
    
    bh = (struct buffer_head *)the_regs->di;
    bd_dev = bh->b_bdev->bd_dev;
    
    device_t *device = NULL;

    spin_lock(&lock);
    
    list_for_each_entry(device, &dev_list_head, device_list) {    
        if (device->ss_is_active && device->dev_id == bd_dev) {
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
            //the_task->bh = bh;            
            the_task->block_number = bh->b_blocknr;
            sb = (struct super_block *)bh->b_bdev->bd_holder; //TODO se non vanno bene entrambe le istruzioni, salvare il super blocco nel device_t al momento del mount 
            bh_um = sb_bread(sb, bh->b_blocknr);
            strcpy(the_task->data, bh_um->b_data);

            printk("%s: data to restore: %s\n", MOD_NAME, bh_um->b_data);

            INIT_WORK(&(the_task->the_work), (void*)write_on_snapshot_folder);
            queue_work(snapshot_wq, &the_task->the_work);

            return 0;
        }
    }   

    spin_unlock(&lock);

    return 0;
} */

/* struct kprobe kp_move_mount = {
    .symbol_name = target_move_mount_func,
    .pre_handler = (kprobe_pre_handler_t)monitor_move_mount,
}; */

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

/* struct kprobe kp_write = {
    .symbol_name = target_write_func,
    .pre_handler = (kprobe_pre_handler_t)monitor_write,
}; */

struct kretprobe krp_write = {
    .kp.symbol_name = target_write_func,
    .handler = (kretprobe_handler_t)monitor_write,
};
