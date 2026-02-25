#ifndef _BD_SNAPSHOT_LIST_H
#define _BD_SNAPSHOT_LIST_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/types.h>

#define SIZE 256

//struct per la gestione della lista (collegata) dei dispositivi
typedef struct {
    char device_name[SIZE];
    dev_t dev_id;
    int dev_is_mounted;
    char ss_path[SIZE];
    struct mutex snapshot_lock;
    struct list_head device_list;
} device_t;

device_t *search_device(const char *device_name);
int push(struct list_head *head, char *device_name);
int remove(device_t *device);

//bd_snapshot_list.c
extern struct list_head dev_list_head;
extern spinlock_t lock;

#endif