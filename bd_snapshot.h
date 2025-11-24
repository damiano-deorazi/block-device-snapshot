#ifndef _BD_SNAPSHOT_H
#define _BD_SNAPSHOT_H

#include <linux/atomic.h>

#define MOD_NAME "BD-SNAPSHOT"
#define PASSWORD_MAX_LEN 32
#define SHA256 "sha256"
#define SHA256_DIGEST_SIZE 32

//bd_snapshot.c
extern atomic_t monitor_mount_is_active;
extern atomic_t monitor_umount_is_active;

#endif