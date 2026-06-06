# SPDX-License-Identifier: GPL-2.0
#
# Out-of-tree build for the PX-W3PE Rev1.3 (ASV5220 / ASIE5606) DVB driver.
#
#   make            build pxw3pe.ko against the running kernel
#   make KDIR=...    build against a specific kernel build tree
#   make install     install the module + run depmod
#   make clean       remove build artifacts
#
# Optional: build the per-core lock self-test (adds the `selftest` module param):
#   make ccflags-y=-DCONFIG_DVB_PXW3PE_DEBUG

ifneq ($(KERNELRELEASE),)

# ---- kbuild pass (invoked by the kernel build system) ----
obj-m       := pxw3pe.o
pxw3pe-objs := pxw3pe_pci.o

else

# ---- normal make pass ----
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all: modules

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install: modules
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: all modules install clean

endif
