#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h> 

#include "bd_snapshot_list.h"
#include "bd_snapshot.h"

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

int push(struct list_head *head, char *device_name, char *mount_point, bool ss_is_active) {

    device_t *new_device;
    //TODO decidere se utilizzare kmalloc (utile per allocazione < PAGSIZE, memoria fisica contigua) o vmalloc (utile per allocazione > PAGSIZE, memoria fisica non contigua)
    new_device = (device_t *) kmalloc(sizeof(device_t));

    if (new_device == NULL) {
        
        printk("%s: Memory allocation of a new device failed\n", MOD_NAME);
        return 0;
    
    }
    
    new_device->device_name = device_name;
    new_device->mount_point = mount_point;
    new_device->ss_is_active = ss_is_active;
    
    list_add(&new_device->device_list, head);

    return 1;
}

int remove(device_t *device) {
    if (device == NULL) {
        printk("%s: Device is NULL, cannot remove\n", MOD_NAME);
        return 0;
    }

    list_del(&device->device_list) // TODO cotrollare se va bene così
    kfree(device);

    return 1;

}
