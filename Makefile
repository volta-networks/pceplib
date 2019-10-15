PROJECT_ROOT = $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

ifeq ($(BUILD_MODE),debug)
	CFLAGS += -g
else ifeq ($(BUILD_MODE),run)
	CFLAGS += -O2
#else
#	$(error Build mode $(BUILD_MODE) not supported by this Makefile)
endif

TOPTARGETS := all clean test

SUBDIRS := pcep_utils pcep_messages pcep_timers pcep_socket_comm pcep_session_logic pcep_pcc

$(TOPTARGETS): $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

.PHONY: $(TOPTARGETS) $(SUBDIRS)
