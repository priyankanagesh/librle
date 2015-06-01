################################################################################
#	Name       : Makefile
#	Authors    : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	             Henrick Deschamps <henrick.deschamps@toulouse.viveris.com>
#	             Thales Alenia Space France
#	Description: Build a module for Linux kernel
#	             (for the librle library build system)
################################################################################


librle_modname = librle
librle_mod = $(librle_modname).ko

librle_common_sources = ../src/crc.c \
						../src/deencap.c \
						../src/encap.c \
						../src/fragmentation.c \
						../src/reassembly.c \
						../src/rle.c \
						../src/rle_conf.c \
						../src/rle_ctx.c \
						../src/rle_header_proto_type_field.c \
						../src/rle_receiver.c \
						../src/rle_transmitter.c 

librle_sources = ../kmod.c \
				 $(librle_common_sources)

INCDIRS = -I$(M)/../include \
		  -I$(M)/../src
EXTRA_CFLAGS += -Wall $(INCDIRS)

librle_objs = $(patsubst %.c,%.o,$(librle_sources))

# Module that exports the librle library in kernel land
obj-m += $(librle_modname).o
$(librle_modname)-objs = \
	$(librle_objs)
