#ifndef _BD_SNAPSHOT_DATA_H
#define _BD_SNAPSHOT_DATA_H

#define DEFAULT_BLOCK_SIZE 4096

typedef struct _packed_data {
    unsigned long long block_number;
    char data[DEFAULT_BLOCK_SIZE];
} packed_data;

#endif