#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define SIZE 256
#define AUDIT if (1)

char *device_path = "./SINGLEFILE-FS/image";
char *password = "correct_password";

int main() {
    
    /*char *device_name = realpath(device_path, NULL);
    if (device_name == NULL) {
    
        perror("realpath failed");
        return EXIT_FAILURE;
    
    }

    int ret;

    ret = syscall(134, device_name, password);  //activate_snapshot
    if (ret == 0) {
    
        printf("Failed to activate snapshot for device %s\n", device_name);
        return EXIT_FAILURE;
    
    }

    printf("Snapshot activated successfully for device %s\n", device_name);

    int fd = open("./SINGLEFILE-FS/mount/the-file", O_RDWR);
    if (fd < 0) {
    
        perror("Failed to open the file");
        return EXIT_FAILURE;
    
    }

    char *read_data = malloc(SIZE);
    ssize_t bytes_read = read(fd, read_data, SIZE);
    if (bytes_read < 0) {

        perror("Failed to read from the file");
        return EXIT_FAILURE;    
    
    }

    printf("Read non-modified data: %s\n", read_data);

    // attivare/disattivare per il testing dello snapshot durante le operazioni di scrittura
    AUDIT {
        
        ret = syscall(156, device_name, password); // deactivate_snapshot
        if (ret == 0) {
        
            printf("Failed to deactivate snapshot for device %s\n", device_name);
            return EXIT_FAILURE;
        
        }
        
        printf("Snapshot deactivated successfully for device %s\n", device_name);
    
    }

    const char *data = "Data written to the file to test snapshot functionality.\n";
    ssize_t bytes_written = write(fd, data, strlen(data));
    if (bytes_written < 0) {
    
        perror("Failed to write to the file");
        return EXIT_FAILURE;
    
    }

    printf("Wrote %zd bytes to the file.\n", bytes_written);

    bytes_read = read(fd, read_data, SIZE);
    if (bytes_read < 0) {
    
        perror("Failed to read from the file");
        return EXIT_FAILURE;    
    
    }

    printf("Read modified data: %s\n", read_data);

    ret = syscall(174, device_name, password); // restore_snapshot
    if (ret == 0) {

        printf("Failed to restore snapshot for device %s\n", device_name);
        return EXIT_FAILURE;     
    
    } 

    printf("Snapshot restored successfully for device %s\n", device_name);

    bytes_read = read(fd, read_data, SIZE);
    if (bytes_read < 0) {
    
        perror("Failed to read from the file");
        return EXIT_FAILURE;    
    
    }

    printf("Read data after snapshot restoration: %s\n", read_data);

    ret = syscall(156, device_name, password); // deactivate_snapshot
    if (ret == 0) {
    
        printf("Failed to deactivate snapshot for device %s\n", device_name);
        return EXIT_FAILURE;
    
    }

    */

    if (syscall(134, "", "correct_password") == -1)
        printf("funzione non implementata\n");// deactivate_snapshot
}