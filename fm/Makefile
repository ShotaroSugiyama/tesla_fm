all: build

# Tell the cfgbuild.mak that we want an FM
FM:=1

# include all the special rules
include $(FMDIR)/cfgbuild.mak

# name of FM to build
NAME:=tesla

#standard libs are used automatically - define any addition libs here
LIBS+=

OBJS:=\
	tesla \
	hdr \
	random \
	ring \
	hash

ifeq ($(EMUL),)
#
# FM Build
#

.phony: build
build: $(OBJDIR) $(ARCH_BIN)

# build the elf file
$(ARCH_EXE): $(ARCH_OBJS)
	$(LN) $(LFLAGS) $(OUT)$@ $(ARCH_OBJS) $(ARCH_LIBS)

# strip symbols and cleanup elf to create unsigned FM image
$(ARCH_BIN): $(ARCH_EXE)
	$(OBJCOPY) $< $@

clean:
	-$(RM) $(ARCH_CLEAN)
	-$(RMDIR) $(subst /,$(PS),$(OBJDIR))

else

#
# EMULATION Build
#

# Include rules to build the emulation Cryptoki and Access Provider wrappers
# This also populates $(EMUL_WRAPPERS) and $(EMUL_CLEAN) constants.
include $(FMDIR)/src/emul/emucommon.mak

.phony: build
build: $(OBJDIR) $(ARCH_BIN) $(EMUL_WRAPPERS)

# build the emulation FM
$(ARCH_BIN): $(ARCH_OBJS)
	$(LN) $(LFLAGS) $(OUT)$@ $(ARCH_OBJS) $(ARCH_LIBS)

# cleanup emulation build
clean: $(EMUL_CLEAN)
	-$(RM) $(ARCH_CLEAN)
	-$(RMDIR) $(subst /,$(PS),$(OBJDIR))

endif
