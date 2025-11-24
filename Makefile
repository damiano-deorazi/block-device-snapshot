obj-m += the_bd_snapshot.o
the_bd_snapshot-objs += bd_snapshot.o bd_snapshot_list.o bd_snapshot_kprobe.o lib/scth.o lib/vtpmo.o lib/usctm.o

all:
	gcc user.c -o user
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm user
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
