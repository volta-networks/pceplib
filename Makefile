PROJECT_ROOT = $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

AR= ar
ARFLAGS = rc
RANLIB = ranlib
BUILD_DIR = ./build
INSTALL_DIR = ./install
PCEP_PCC_LIB = $(INSTALL_DIR)/lib/libpcep_pcc.a
LIBS = $(BUILD_DIR)/libpcep_utils.a \
       $(BUILD_DIR)/libpcep_messages.a \
       $(BUILD_DIR)/libpcep_timers.a \
       $(BUILD_DIR)/libpcep_socket_comm.a \
       $(BUILD_DIR)/libpcep_session_logic.a \
       $(BUILD_DIR)/libpcep_pcc_api.a 


SUBDIRS := pcep_utils pcep_messages pcep_timers pcep_socket_comm pcep_session_logic pcep_pcc
PCEP_PCC_HEADERS := $(foreach dir,$(SUBDIRS),$(wildcard $(dir)/include/*))
OBJS := $(foreach dir,$(SUBDIRS),$(wildcard $(dir)/obj/*.o))
TOPTARGETS := all clean test

$(TOPTARGETS): $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

install: $(PCEP_PCC_LIB) $(PCEP_PCC_HEADERS)

$(PCEP_PCC_LIB): $(LIBS)
	$(shell [ ! -d $(@D) ] && mkdir -p $(@D))
	$(AR) $(ARFLAGS) $@ $(OBJS)
	$(RANLIB) $@
	$(shell [ ! -d $(INSTALL_DIR)/include ] && mkdir -p $(INSTALL_DIR)/include)
	cp $(PCEP_PCC_HEADERS) $(INSTALL_DIR)/include


.PHONY: $(TOPTARGETS) $(SUBDIRS) install
