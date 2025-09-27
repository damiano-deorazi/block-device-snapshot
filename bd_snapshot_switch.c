#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/slab.h> 
#include <openssl/sha.h>

#include "bd_snapshot.h"

device_t *dev_list_head = NULL;
unsigned char ss_hpasswd[32] = NULL; //password per l'attivazione/disattivazione degli snapshot 
unsigned char salt[32] = NULL; //sale per l'hashing della password
int iter = -1; //numero di iterazioni per l'algoritmo di hashing


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
    kfree(temp_node);

    return 1;

}

int generate_hash(char *password) {
    /*int salt_ok = RAND_bytes(salt, sizeof(salt));
                                                        -------> decidere se generare un sale random ad ogni avvio del modulo o utilizzare un sale fisso
    if (!salt_ok) {
        printk("Error generating salt\n");
        return 0;
    }*/

    int hash_ok = PKCS5_PBKDF2_HMAC(password, -1,
        salt, sizeof(salt),
        iter, EVP_sha256(),
        sizeof(ss_hpasswd), ss_hpasswd);
    
    if (!hash_ok) {
        printk("Error generating hash\n");
        return 0;
    }
    
    return 1;
}

int check_password(char *password) {
    unsigned char key[32] = {0};
    
    int hash_ok = generate_hash(password);

    if (!hash_ok) {
        return 0;
    }

    if (memcmp(key, ss_hpasswd, sizeof(ss_hpasswd)) == 0) {
        return 1; //password corretta
    } else {
        return 0; //password errata
    }
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINE2(activate_snapshot, char *, dev_name, char *, password){
#else
asmlinkage long sys_activate_snapshot(char *dev_name, char *password){
#endif
    int login_success = check_password(password);
    if (!login_success) {
        printk("Incorrect password\n");
        return 0;
    }

    //TODO cercare il device nella lista e attivare lo snapshot
    
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINE2(deactivate_snapshot, char *, dev_name, char *, password){
#else
asmlinkage long sys_deactivate_snapshot(char *dev_name, char *password){
#endif

}
