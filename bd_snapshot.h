#ifndef BD_SNAPSHOT_H
#define BD_SNAPSHOT_H

//struct per la gestione della lista (collegata) dei dispositivi
typedef struct device {
    char device_name[128];
    char mount_point[128];
    bool ss_is_active;
    
    struct device *next;
} device_t;

int push(device_t **head, char *device_name, char *mount_point, bool ss_is_active);

int pop(device_t **head);

int remove_by_index(device_t **head, int n);

/*int activate_snapshot(char *dev_name, char *password);

int deactivate_snapshot(char *dev_name, char *password);
*/

#endif