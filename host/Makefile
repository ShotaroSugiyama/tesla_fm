all: build

# Build a console application
CONSOLE:=1

# Name of the application
NAME:=tesla_test

# Name of the FM
FM_NAME:=tesla

# Directory where the FM is built from
FM_PATH:=../fm

include $(FMDIR)/cfgbuild.mak

CFLAGS+=-I../include

# if we are doing emulation build, copy test program to where the FM DLL is.
ifneq ($(EMUL),$(NULL))
FM_PATH:=..$(PS)fm
INSTALL_EXE=$(FM_PATH)$(PS)$(ARCH_EXE)
endif

build: $(ARCH_EXE) $(INSTALL_EXE)

OBJS:=\
	tesla_test

LIBS:=\
	cryptoki \
	ethsm

ifneq ($(EMUL), $(NULL))
	LFLAGS += -L$(FM_PATH)$(PS)$(OBJDIR) -Wl,-rpath $(FM_PATH)$(PS)$(OBJDIR)
endif

# build the test program
$(ARCH_EXE): $(OBJDIR) $(ARCH_OBJS)
	$(LN) $(OUT)$(ARCH_EXE) $(LFLAGS) $(ARCH_OBJS) $(ARCH_LIBS)

# install the test program to another location (if specified)
$(INSTALL_EXE): $(ARCH_EXE)
	$(CP) $^ $@

clean :
	-$(RM) $(ARCH_CLEAN)
ifneq ($(INSTALL_EXE),$(NULL))
	-$(RM) $(INSTALL_EXE)
endif
	-$(RMDIR) $(subst /,$(PS),$(OBJDIR))
