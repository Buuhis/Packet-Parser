obj-m += mwan_kmod.o

mwan_kmod-objs := mwan_main.o mwan_state.o mwan_netlink.o mwan_steer.o \
                 encap/encap_none.o \
                 encap/encap_macsec.o \
                 encap/encap_l3.o

all:
	make -C /lib/modules/$(shell uname -r)/build M="$(CURDIR)" modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M="$(CURDIR)" clean
