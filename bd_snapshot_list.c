#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h> 

#include "bd_snapshot_list.h"
#include "bd_snapshot.h"

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

int pop(device_t **head) {
    device_t *next_node = NULL;

    if (*head == NULL) {
        printk("%s: List is empty, cannot pop\n", MOD_NAME);
        return 0;
    }

    next_node = (*head)->next;
    free(*head);
    *head = next_node;

    return 1;
}

int remove_by_index(device_t **head, int n) {
    int i = 0;
    device_t *current = *head;
    device_t *temp_node = NULL;

    if (n == 0) {
        return pop(head);
    }

    for (i = 0; i < n-1; i++) {
        if (current->next == NULL) {
            printk("%s: Index out of bounds, cannot remove\n", MOD_NAME);
            return 0;
        }
        current = current->next;
    }

    if (current->next == NULL) {
        printk("%s: Index out of bounds, cannot remove\n", MOD_NAME);
        return 0;
    }

    temp_node = current->next;
    current->next = temp_node->next;
    kfree(temp_node);

    return 1;

}
