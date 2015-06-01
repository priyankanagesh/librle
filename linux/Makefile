################################################################################
#	Name       : Makefile
#	Authors    : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	             Henrick Deschamps <henrick.deschamps@toulouse.viveris.com>
#	             Thales Alenia Space France
#	Date       : 05/2015
#	Description: Build a module for Linux kernel
#	             (for the librle library build system)
################################################################################

librle_modname = librle
librle_mod = $(librle_modname).ko

KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build

CFLAGS += -I$(CURDIR)/include

all:
	$(MAKE) $(CFLAGS) -C $(KDIR) M=$(CURDIR)/kmod modules

clean:
	rm \
	    $(CURDIR)/kmod.o \
	    $(CURDIR)/src/*.o \
	    $(CURDIR)/kmod/*.o \
	    $(CURDIR)/kmod/$(librle_modname).ko \
	    $(CURDIR)/kmod/$(librle_modname).mod.c \
	    $(CURDIR)/kmod/modules.order \
	    $(CURDIR)/kmod/Module.symvers

install:
	$(INSTALL) -d $(DESTDIR)/$(librle_moddir)
	$(INSTALL) -m 644 $(builddir)/kmod/$(librle_mod) $(DESTDIR)/$(librle_moddir)/$(librle_mod)
	-/sbin/depmod -a

uninstall:
	rm -f $(DESTDIR)/$(librle_moddir)/$(librle_mod)
	-/sbin/depmod -a
