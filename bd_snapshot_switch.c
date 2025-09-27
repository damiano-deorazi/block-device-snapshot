#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/slab.h> 
#include "bd_snapshot.h"

device_t *dev_list_head = NULL;
char *ss_password = NULL; //password per l'attivazione/disattivazione degli snapshot 

int push(device_t **head, char *device_name, char *mount_point, bool ss_is_active) {
    device_t * new_device;
    //TODO decidere se utilizzare kmalloc (utile per allocazione < PAGSIZE, memoria fisica contigua) o vmalloc (utile per allocazione > PAGSIZE, memoria fisica non contigua)
    new_device = (device_t *) kmalloc(sizeof(device_t));
    if (new_device == NULL) {
        printk("Memory allocation of a new device failed\n");
        return 0;
    }
    new_device->device_name = device_name;
    new_device->mount_point = mount_point;
    new_device->ss_is_active = ss_is_active;
    new_device->next = *head;
    *head = new_device;
    return 1;
}

int pop(device_t **head) {
    device_t *next_node = NULL;

    if (*head == NULL) {
        printk("List is empty, cannot pop\n");
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
            printk("Index out of bounds, cannot remove\n");
            return 0;
        }
        current = current->next;
    }

    if (current->next == NULL) {
        printk("Index out of bounds, cannot remove\n");
        return 0;
    }

    temp_node = current->next;
    current->next = temp_node->next;
    free(temp_node);

    return 1;

}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINE2(activate_snapshot, char *, dev_name, char *, password){
#else
asmlinkage long sys_activate_snapshot(char *dev_name, char *password){
#endif

}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINE2(deactivate_snapshot, char *, dev_name, char *, password){
#else
asmlinkage long sys_deactivate_snapshot(char *dev_name, char *password){
#endif

}
