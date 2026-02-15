#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define SIZE 256
#define ACTIVATE_SYSCALL_N 156
#define DEACTIVATE_SYSCALL_N 174
#define RESTORE_SYSCALL_N 177

char *device_path = "../SINGLEFILE-FS/image";
char *the_file = "../SINGLEFILE-FS/mount/the-file";
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

void restore_snapshot() {
    int ret;

    ret = syscall(RESTORE_SYSCALL_N, device_name, password);
    if (ret == 0) {
        printf("Failed to restore snapshot for device %s\n", device_name);
        return;    
    } 

    printf("Snapshot restored successfully for device %s\n", device_name);
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

    char *data, *input;

    data = malloc(SIZE);
    if (data == NULL) {
        perror("Failed to allocate memory for data\n");
        return;
    }

    printf("Enter data to write to the file (max %d characters): ", SIZE - 1);

    if (scanf("%s", data) != 1) {
        perror("Failed to read choice\n");
        return EXIT_FAILURE;
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
        close(fd);
        return;    
    }

    printf("Wrote %zd bytes to the file.\n", bytes_written);
    free(data);
    close(fd);
}

int main(int argc, char *argv[]) {

    int ret, choice;

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
        printf("3. Restore snapshot\n");
        printf("4. Read file\n");
        printf("5. Write file\n");
        printf("6. Exit\n");

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
                restore_snapshot();
                break;
            case 4:
                read_file();
                break;
            case 5:
                write_file();
                break;
            case 6:
                return EXIT_SUCCESS;
            default:
                printf("Invalid choice, please try again.\n");
        }
    }
}
