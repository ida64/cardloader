# CardLoader as a Tesla overlay (.ovl). devkitPro libnx template, reduced.
#
#   make LIBTESLA=<checkout>/libs/libtesla
#
# LIBTESLA is the pinned libtesla from Tesla-Menu (device/tesla/build.sh sets
# it); nothing third-party lives in this repository.
.SUFFIXES:

ifeq ($(strip $(DEVKITPRO)),)
$(error "Please set DEVKITPRO in your environment. export DEVKITPRO=<path to>/devkitpro")
endif
ifeq ($(strip $(LIBTESLA)),)
ifneq ($(MAKECMDGOALS),clean)
$(error "Set LIBTESLA to the pinned libtesla checkout; use device/tesla/build.sh")
endif
endif

TOPDIR ?= $(CURDIR)
include $(DEVKITPRO)/libnx/switch_rules

TARGET		:=	xci-switcher
BUILD		:=	build
SOURCES		:=	source ../xci/client
DATA		:=
INCLUDES	:=	../xci/source ../xci/client ../hookhost
NO_ICON		:=	1
APP_TITLE	:=	CardLoader
APP_AUTHOR	:=	CardLoader
APP_VERSION	:=	0.1

ARCH	:=	-march=armv8-a+crc+crypto -mtune=cortex-a57 -mtp=soft -fPIE

CFLAGS	:=	-g -Wall -O2 -ffunction-sections $(ARCH) $(DEFINES)
CFLAGS	+=	$(INCLUDE) -I$(LIBTESLA)/include -D__SWITCH__
CXXFLAGS	:= $(CFLAGS) -fno-exceptions -std=c++20
ASFLAGS	:=	-g $(ARCH)
LDFLAGS	=	-specs=$(DEVKITPRO)/libnx/switch.specs -g $(ARCH) -Wl,-Map,$(notdir $*.map)
LIBS	:=	-lnx
LIBDIRS	:=	$(PORTLIBS) $(LIBNX)

ifneq ($(BUILD),$(notdir $(CURDIR)))

export OUTPUT	:=	$(CURDIR)/$(TARGET)
export TOPDIR	:=	$(CURDIR)
export LIBTESLA
export VPATH	:=	$(foreach dir,$(SOURCES),$(CURDIR)/$(dir))
export DEPSDIR	:=	$(CURDIR)/$(BUILD)

CFILES		:=	$(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.c)))
CPPFILES	:=	$(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.cpp)))
export LD	:=	$(CXX)

export OFILES	:=	$(CPPFILES:.cpp=.o) $(CFILES:.c=.o)
export INCLUDE	:=	$(foreach dir,$(INCLUDES),-I$(CURDIR)/$(dir)) \
			$(foreach dir,$(LIBDIRS),-I$(dir)/include) -I$(CURDIR)/$(BUILD)
export LIBPATHS	:=	$(foreach dir,$(LIBDIRS),-L$(dir)/lib)
export NROFLAGS	+=	--nacp=$(CURDIR)/$(TARGET).nacp

.PHONY: $(BUILD) clean all

all: $(BUILD)

$(BUILD):
	@[ -d $@ ] || mkdir -p $@
	@$(MAKE) --no-print-directory -C $(BUILD) -f $(CURDIR)/Makefile

clean:
	@rm -fr $(BUILD) $(TARGET).ovl $(TARGET).nacp $(TARGET).elf

else
.PHONY:	all

DEPENDS	:=	$(OFILES:.o=.d)

all	:	$(OUTPUT).ovl

$(OUTPUT).ovl	:	$(OUTPUT).elf $(OUTPUT).nacp
	@elf2nro $< $@ $(NROFLAGS)
	@echo "built ... $(notdir $(OUTPUT).ovl)"

$(OUTPUT).elf	:	$(OFILES)

-include $(DEPENDS)

endif
