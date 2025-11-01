#ifndef _BD_SNAPSHOT_KPROBE_H
#define _BD_SNAPSHOT_KPROBE_H

#include <linux/atomic.h>
#include <linux/kprobes.h>

#define BUFF_SIZE 256

int monitor_mount(struct kprobe *ri, struct pt_regs *the_regs);
int monitor_umount(struct kprobe *ri, struct pt_regs *the_regs);

//bd_snapshot.c
extern atomic_t monitor_mount_is_active;
extern atomic_t monitor_umount_is_active;

//bd_snapshot_kprobe.c
extern struct kprobe kp_mount;
extern struct kprobe kp_umount;

#endif
