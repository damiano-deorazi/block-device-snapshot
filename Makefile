obj-m += bd_snapshot.o
bd_snapshot-objs += bd_snapshot_list.o bd_snapshot_kprobe.o syscall_table_mod.o 

all:
	gcc user.c -o user
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
