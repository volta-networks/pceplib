AR= ar
ARFLAGS = rc
RANLIB = ranlib
CC= gcc
CFLAGS = -g -Wall -Werror \
 -I$(PCEP_SESSION_LOGIC_INC_DIR) \
 -I$(PCEP_UTILS_INC_DIR) \
 -I$(PCEP_MESSAGES_INC_DIR) \
 -I$(PCEP_TIMERS_INC_DIR) \
 -I$(PCEP_SOCKETCOMM_INC_DIR) \
 -I$(INC_DIR)

INC_DIR = include
OBJ_DIR = ./obj
SRC_DIR = ./src
BUILD_DIR = ../build
PCEP_SESSION_LOGIC_INC_DIR = ../pcep_session_logic/include
PCEP_UTILS_INC_DIR = ../pcep_utils/include
PCEP_MESSAGES_INC_DIR = ../pcep_messages/include
PCEP_TIMERS_INC_DIR = ../pcep_timers/include
PCEP_SOCKETCOMM_INC_DIR = ../pcep_socket_comm/include

LIB = $(BUILD_DIR)/libpcep_pcc_api.a
BIN = $(BUILD_DIR)/pcep_pcc

LIB_DEPS = $(LIB) \
 $(BUILD_DIR)/libpcep_session_logic.a \
 $(BUILD_DIR)/libpcep_socket_comm.a \
 $(BUILD_DIR)/libpcep_timers.a \
 $(BUILD_DIR)/libpcep_messages.a \
 $(BUILD_DIR)/libpcep_utils.a
_LIBS = $(subst $(BUILD_DIR)/lib,-l,$(LIB_DEPS))
LIBS = $(subst .a,,$(_LIBS)) -lpthread

_DEPS = *.h
DEPS = $(patsubst %,$(INC_DIR)/%,$(_DEPS))
EXTERNAL_DEPS = $(patsubst %,$(PCEP_SESSION_LOGIC_INC_DIR)/%,$(_DEPS))

# This module has both the API library code and the code for an example binary
# The primary target is the API library
BIN_OBJ = $(OBJ_DIR)/pcep_pcc.o
LIB_OBJ = $(OBJ_DIR)/pcep_pcc_api.o

all: $(LIB) $(BIN)

$(LIB): $(LIB_OBJ)
	$(shell [ ! -d $(@D) ] && mkdir -p $(@D))
	$(AR) $(ARFLAGS) $@ $^ 
	$(RANLIB) $@

$(BIN): $(BIN_OBJ) $(LIB_DEPS)
	$(shell [ ! -d $(@D) ] && mkdir -p $(@D))
	$(CC) -o $@ $(BIN_OBJ) -L$(BUILD_DIR) $(LIBS) 

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(DEPS) $(EXTERNAL_DEPS)
	$(shell [ ! -d $(@D) ] && mkdir -p $(@D))
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: all clean test

test:

clean:
	rm -f $(LIB) $(BIN) $(OBJ_DIR)/*.o *~ core $(SRC_DIR)/*~

