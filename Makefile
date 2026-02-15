obj-m += the_bd_snapshot.o
the_bd_snapshot-objs += bd_snapshot.o bd_snapshot_list.o bd_snapshot_kprobe.o lib/scth.o

A = $(shell cat /sys/module/the_usctm/parameters/sys_call_table_address)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

mount:
	@if [ -z "$(pw)" ]; then \
		echo "Errore: Devi specificare una password. Esempio: make install pw=la_tua_password"; \
		exit 1; \
	fi
	insmod the_bd_snapshot.ko passwd=$(pw) the_syscall_table=$(A)

unmount:
	rmmod the_bd_snapshot