#ifndef _BD_SNAPSHOT_LIST_H
#define _BD_SNAPSHOT_LIST_H

#include <linux/list.h>
#include <linux/spinlock.h>

#define SIZE 256

//struct per la gestione della lista (collegata) dei dispositivi
typedef struct device {
    char device_name[SIZE];
    char mount_point[SIZE];
    char ss_path[SIZE];
    bool ss_is_active;    
    struct list_head device_list;
} device_t;

device_t *search_device(char *device_name);

int push(struct list_head *head, char *device_name, char *mount_point, bool ss_is_active);

int remove(device_t *device);

//bd_snapshot_list.c
extern struct list_head dev_list_head;
extern spinlock_t lock;

#endif