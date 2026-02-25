#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <stdint.h>

#include "../include/bd_snapshot_data.h"
#include "../SINGLEFILE-FS/singlefilefs.h"

#define SIZE 256
#define ACTIVATE_SYSCALL_N 156
#define DEACTIVATE_SYSCALL_N 174
#define DEFAULT_BLOCK_SIZE 4096

char *device_path = "../SINGLEFILE-FS/image";
char *the_file = "../SINGLEFILE-FS/mount/the-file";
char *mount_point = "../SINGLEFILE-FS/mount";
char *snapshot_path = "/snapshot";
char *device_name;
char *password;

void activate_snapshot() {
    int ret;

    ret = syscall(ACTIVATE_SYSCALL_N, device_name, password);
    if (ret == 0) {
        printf("Failed to activate snapshot for device %s\n", device_name);
        return;
    }

    printf("Snapshot activated successfully for device %s\n", device_name);
}

void deactivate_snapshot() {
    int ret;

    ret = syscall(DEACTIVATE_SYSCALL_N, device_name, password);
    if (ret == 0) {
        printf("Failed to deactivate snapshot for device %s\n", device_name);
        return;
    }
    
    printf("Snapshot deactivated successfully for device %s\n", device_name);
}

void mount_device() {
    char command[SIZE];
    snprintf(command, SIZE, "mount -o loop -t singlefilefs %s %s", device_path, mount_point);
    int ret = system(command);
    if (ret != 0) {
        printf("Failed to mount device %s\n", device_name);
        return;
    }

    printf("Device %s mounted successfully\n", device_name);
}

int filter(const struct dirent *entry) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
        return 0;
    }
    return 1;
}

void restore_device(const char *snapshot_select) {
    int fd_snapshot, fd_device;
    char snapshot_file_path[SIZE];

    snprintf(snapshot_file_path, SIZE, "%s/%s/snapshot_data", snapshot_path, snapshot_select);

    fd_snapshot = open(snapshot_file_path, O_RDONLY);
    if (fd_snapshot == -1) {
        if (errno == ENOENT) {
            printf("This snapshot is empty\n");
            return;
        } 
        
        perror("Failed to open the snapshot file\n");
        return;
    }

    fd_device = open(device_name, O_RDWR);
    if (fd_device == -1) {
        perror("Failed to open the device\n");
        goto out_close_fd_snapshot;
    }

    packed_data snapshot_data;
    ssize_t nbytes;
    for (;;) {
        nbytes = read(fd_snapshot, &snapshot_data, sizeof(snapshot_data));
        if (nbytes < 0) {
            perror("Failed to read from the snapshot file\n");
            goto out_close_fd_device;
        } else if (nbytes == 0) {
            break;
        }

        printf("Restoring block number %llu with data: %s\n", snapshot_data.block_number, snapshot_data.data);

        if (snapshot_data.block_number == 1){
            struct onefilefs_inode *inode = (struct onefilefs_inode *)snapshot_data.data;
            printf("inode info - inode_no: %ld, file size: %lu\n", inode->inode_no, inode->file_size);
        }
        
        nbytes = pwrite(fd_device, snapshot_data.data, DEFAULT_BLOCK_SIZE, snapshot_data.block_number * DEFAULT_BLOCK_SIZE);
        if (nbytes < DEFAULT_BLOCK_SIZE) {
            printf("Failed to write to the device (wrote %ld bytes instead of %d)\n", nbytes, DEFAULT_BLOCK_SIZE);
            goto out_close_fd_device;
        }
    }

    printf("Snapshot '%s' restored successfully.\n", snapshot_select);

out_close_fd_device:
    close(fd_device);
out_close_fd_snapshot:
    close(fd_snapshot);
}

int restore_from_snapshot() {
    struct dirent **namelist;
    int n;

    n = scandir(snapshot_path, &namelist, filter, alphasort);

    if (n < 0) {
        perror("Failed to open snapshot directory\n");
        return 1;
    }

    if (n == 0) {
        printf("No snapshot found in '%s'.\n", snapshot_path);
        free(namelist);
        return 0;
    }

    printf("------------- AVAILABLE SNAPSHOTS -------------\n");

    for (int i = 0; i < n; i++) {
        printf("[%d] %s\n", i + 1, namelist[i]->d_name);
    }

    printf("[0] Cancel\n");
    printf("-----------------------------------------------\n");

    int choice;
    char *snapshot_select;
    while (1) {
        printf("Insert the number of the snapshot to restore: ");
        if (scanf("%d", &choice) != 1) {
            choice = -1;
        }

        if (choice > 0 && choice <= n) {
            snapshot_select = namelist[choice - 1]->d_name;
            restore_device(snapshot_select);
            break;
            
        } else if (choice == 0) {
            printf("Operation canceled.\n");
            break;
        } else {
            printf("Invalid choice, please try again.\n");
        }
    }

    for (int i = 0; i < n; i++) {
        free(namelist[i]);
    }
    free(namelist);

    return 1;
}   

void unmount_restore_device() {
    char command[SIZE];
    char choice;

    snprintf(command, SIZE, "umount %s", mount_point);
    int ret = system(command);
    if (ret != 0) {
        //printf("Failed to unmount device %s\n", device_name);
        return;
    }

    printf("Device %s unmounted successfully\n", device_name);

    printf("Do you want to restore the snapshot for device %s? (y/n)", device_name);

    if (scanf(" %c", &choice) != 1) {
        printf("Failed to read choice\n");
        return;
    }

    if (choice == 'y' || choice == 'Y') {
        printf("Restoring snapshot for device %s...\n", device_name);
        restore_from_snapshot();
        return;
    } 

    printf("Restoring skipped.\n");
}

void read_file() {

    int fd = open(the_file, O_RDWR|O_APPEND);
    if (fd < 0) {    
        perror("Failed to open the file\n");
        return;
    }

    char *read_data = malloc(SIZE);
    ssize_t bytes_read = read(fd, read_data, SIZE);
    if (bytes_read < 0) {
        perror("Failed to read from the file\n");
        return;   
    }

    printf("Read data: '%s', bytes: %zd\n", read_data, bytes_read);
    free(read_data);
    close(fd);
}

void write_file() {

    char *data;

    data = malloc(SIZE);
    if (data == NULL) {
        perror("Failed to allocate memory for data\n");
        return;
    }

    printf("Enter data to write to the file (max %d characters): ", SIZE - 1);

    if (scanf("%s", data) != 1) { //TODO verificare il formato corretto per scanf
        perror("Failed to read data\n");
        return;
    }

    int fd = open(the_file, O_RDWR|O_APPEND);
    if (fd < 0) {    
        perror("Failed to open the file\n");
        free(data);
        return;
    }

    ssize_t bytes_written = write(fd, data, strlen(data));
    if (bytes_written < 0) {
        perror("Failed to write to the file\n");
        free(data);
        return;    
    }

    printf("Wrote %zd bytes to the file.\n", bytes_written);
    free(data);
    close(fd);
}

int main(int argc, char *argv[]) {

    int choice;

    if (argc != 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return EXIT_FAILURE;
    }

    password = argv[1];

    device_name = realpath(device_path, NULL);
    if (device_name == NULL) {
        perror("realpath failed\n");
        return EXIT_FAILURE;
    }

    while (1) {
        printf("\nChoose an option:\n");
        printf("1. Activate snapshot\n");
        printf("2. Deactivate snapshot\n");
        printf("3. Mount device\n");
        printf("4. Unmount device (and restore)\n");
        //printf("3. Restore snapshot\n");
        printf("5. Read file\n");
        printf("6. Write file\n");
        printf("7. Exit\n");

        if (scanf("%d", &choice) != 1) {
            perror("Failed to read choice\n");
            return EXIT_FAILURE;
        }

        switch (choice) {
            case 1:
                activate_snapshot();
                break;
            case 2:
                deactivate_snapshot();
                break;
            case 3:
                //restore_snapshot();
                mount_device();
                break;
            case 4:
                unmount_restore_device();
                break;
            case 5:
                read_file();
                break;
            case 6:
                write_file();
                break;
            case 7:
                return EXIT_SUCCESS;
            default:
                printf("Invalid choice, please try again.\n");
        }
    }
}
