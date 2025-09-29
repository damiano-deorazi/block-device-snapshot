#ifndef _BD_SNAPSHOT_LIST_H
#define _BD_SNAPSHOT_LIST_H

#include <linux/list.h>

//struct per la gestione della lista (collegata) dei dispositivi
typedef struct device {
    char device_name[128];
    char mount_point[128];
    bool ss_is_active;    
    struct list_head device_list;
} device_t;

int push(struct list_head *head, char *device_name, char *mount_point, bool ss_is_active);

int pop(device_t **head);

int remove_by_index(device_t **head, int n);

#endif