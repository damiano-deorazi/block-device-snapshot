#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h> 
#include <linux/spinlock.h>
#include <linux/mutex.h>

#include "include/bd_snapshot_list.h"
#include "include/bd_snapshot.h"

DEFINE_SPINLOCK(lock);

LIST_HEAD(dev_list_head);

device_t *search_device(char *device_name) {

    device_t *pos = NULL; 

    list_for_each_entry (pos, &dev_list_head, device_list) {     
        if (strcmp(pos->device_name, device_name) == 0) {
            return pos;
        }
    }

    return NULL;
}

int push(struct list_head *head, char *device_name) {

    device_t *new_device;
    new_device = (device_t *) kmalloc(sizeof(device_t), GFP_KERNEL);

    if (new_device == NULL) {  
        printk("%s: Memory allocation of a new device failed\n", MOD_NAME);
        return 0;
    }
    
    strncpy(new_device->device_name, device_name, SIZE);
    new_device->ss_is_active = 1;
    new_device->dev_is_mounted = 0;
    mutex_init(&new_device->snapshot_lock);    
    
    list_add(&new_device->device_list, head);

    return 1;
}

int remove(device_t *device) {

    if (device == NULL) {
        printk("%s: Device not found, cannot remove\n", MOD_NAME);
        return 0;
    }

    list_del(&device->device_list);
    kfree(device);

    return 1;

}
