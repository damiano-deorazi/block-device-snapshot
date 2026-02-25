#ifndef _BD_SNAPSHOT_KPROBE_H
#define _BD_SNAPSHOT_KPROBE_H

#include <linux/kprobes.h>
#include <linux/workqueue.h>
#include <linux/types.h>

#define BUFF_SIZE 256

typedef struct _packed_work {
    char *snapshot_path;
    struct mutex *snapshot_lock;
    struct buffer_head* bh;
    struct work_struct the_work;
} packed_work;

/* typedef struct _packed_data {
    unsigned long long block_number;
    char data[DEFAULT_BLOCK_SIZE];
} packed_data;
 */
typedef struct _kret_data {
    struct file_system_type *fs_type;
    int flags;
    const char *dev_name;
} kret_data;

int monitor_umount(struct kprobe *ri, struct pt_regs *the_regs);
int monitor_write(struct kretprobe_instance *ri, struct pt_regs *the_regs);
int monitor_mount_entry_handler(struct kretprobe_instance *ri, struct pt_regs *the_regs);
int monitor_mount_ret_handler(struct kretprobe_instance *ri, struct pt_regs *the_regs);
void create_snapshot_folder(struct work_struct *work);
void write_on_snapshot_folder(struct work_struct *work);

//bd_snapshot_kprobe.c
extern struct kretprobe krp_mount;
extern struct kprobe kp_umount;
extern struct kretprobe krp_write;
extern struct workqueue_struct *snapshot_wq;

#endif