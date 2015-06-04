################################################################################
#	Name       : Makefile
#	Authors    : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	             Henrick Deschamps <henrick.deschamps@toulouse.viveris.com>
#	             Thales Alenia Space France
#	Date       : 05/2015
#	Description: Build a module and its test for Linux kernel
#	             (for the librle library build system)
################################################################################

CC = gcc

librle_modname = librle
librle_mod = $(librle_modname).ko

librle_test_modname = librle_test
librle_test_mod = $(librle_test_modname).ko

userspace_test_name = kmod_test_userspace

KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build

CFLAGS += -I$(CURDIR)/include

all:
	$(MAKE) $(CFLAGS) -C $(KDIR) M=$(CURDIR)/kmod modules
	$(CC) $(userspace_test_name).c -o $(CURDIR)/$(userspace_test_name) -lpcap
	# $(MAKE) -C $(KDIR) M=$(CURDIR)/librle/linux/kmod modules # For ksatintegration.

clean:
	rm \
	    $(CURDIR)/kmod.o \
	    $(CURDIR)/kmod_test.o \
	    $(CURDIR)/src/*.o \
	    $(CURDIR)/kmod/*.o \
	    $(CURDIR)/kmod/$(librle_modname).ko \
	    $(CURDIR)/kmod/$(librle_modname).mod.c \
	    $(CURDIR)/kmod/$(librle_test_modname).ko \
	    $(CURDIR)/kmod/$(librle_test_modname).mod.c \
	    $(CURDIR)/kmod/modules.order \
	    $(CURDIR)/kmod/Module.symvers \
	    $(CURDIR)/$(userspace_test_name) \
	    $(CURDIR)/kmod/.$(librle_modname).ko.cmd \
	    $(CURDIR)/kmod/.$(librle_test_modname).ko.cmd \
	    $(CURDIR)/kmod/.tmp_versions/*
	rmdir \
	    $(CURDIR)/kmod/.tmp_versions

MDIR := kernel/drivers/misc/librle
librle_moddir = /lib/modules/${KVER}/${MDIR}/kmod
INSTALL = install
INSTALL = install

install:
	$(INSTALL) -d $(DESTDIR)/$(librle_moddir)
	$(INSTALL) -m 644 $(CURDIR)/kmod/$(librle_mod) $(DESTDIR)/$(librle_moddir)/$(librle_mod)
	$(INSTALL) -m 644 $(CURDIR)/kmod/$(librle_test_mod) $(DESTDIR)/$(librle_moddir)/$(librle_test_mod)

uninstall:
	rm -f $(DESTDIR)/$(librle_moddir)/$(librle_mod)
	rm -f $(DESTDIR)/$(librle_moddir)/$(librle_test_mod)
