obj-m += mwan_kmod.o

mwan_kmod-objs := mwan_main.o mwan_state.o mwan_key_rotation.o mwan_l2_flow.o mwan_netlink.o mwan_steer.o \
                 mwan_multicore.o \
                 mwan_mtu.o \
                 mwan_mac_discovery.o \
                 encap/encap_none.o \
                 encap/encap_macsec.o \
                 encap/encap_l3.o \
                 encap/encap_l3_pqc.o \
                 encap/encap_l2_pqc.o \
                 decap/decap_l3.o \
                 decap/decap_l3_pqc.o \
                 decap/decap_l2_pqc.o

all:
	make -C /lib/modules/$(shell uname -r)/build M="$(CURDIR)" modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M="$(CURDIR)" clean
