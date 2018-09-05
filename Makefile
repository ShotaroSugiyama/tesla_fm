#############################################################################
#
#  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
#
#  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
#  This file is protected by laws protecting trade secrets and confidential
#  information, as well as copyright laws and international treaties.
#
# Filename: samples/rsaenc/Makefile.mak
# $Date: 2014/09/10 19:13:37GMT-05:00 $
#
#############################################################################

%:
ifeq ($(HOSTONLY),)
	$(MAKE) -C fm $@
endif
ifeq ($(FMONLY),)
	$(MAKE) -C host $@
endif