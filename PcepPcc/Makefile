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
PCEP_SESSION_LOGIC_INC_DIR = ../PcepSessionLogic/include
PCEP_UTILS_INC_DIR = ../PcepUtils/include
PCEP_MESSAGES_INC_DIR = ../PcepMessages/include
PCEP_TIMERS_INC_DIR = ../PcepTimers/include
PCEP_SOCKETCOMM_INC_DIR = ../PcepSocketComm/include

LIB = $(BUILD_DIR)/libPcepPccApi.a
BIN = $(BUILD_DIR)/pcep_pcc

LIB_DEPS = $(LIB) \
 $(BUILD_DIR)/libPcepSessionLogic.a \
 $(BUILD_DIR)/libPcepSocketComm.a \
 $(BUILD_DIR)/libPcepTimers.a \
 $(BUILD_DIR)/libPcepMessages.a \
 $(BUILD_DIR)/libPcepUtils.a
_LIBS = $(subst $(BUILD_DIR)/lib,-l,$(LIB_DEPS))
LIBS = $(subst .a,,$(_LIBS)) -lpthread

_DEPS = *.h
DEPS = $(patsubst %,$(INC_DIR)/%,$(_DEPS))
EXTERNAL_DEPS = $(patsubst %,$(PCEP_SESSION_LOGIC_INC_DIR)/%,$(_DEPS))

# This module has both the API library code and the code for an example binary
# The primary target is the API library
BIN_OBJ = $(OBJ_DIR)/pcep_pcc.o
LIB_OBJ = $(OBJ_DIR)/PcepPccApi.o

all: $(LIB) $(BIN)

$(LIB): $(LIB_OBJ)
	$(AR) $(ARFLAGS) $@ $^ 
	$(RANLIB) $@

$(BIN): $(BIN_OBJ) $(LIB_DEPS)
	$(CC) -o $@ $(BIN_OBJ) -L$(BUILD_DIR) $(LIBS) 

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(DEPS) $(EXTERNAL_DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(LIB) $(BIN) $(OBJ_DIR)/*.o *~ core $(SRC_DIR)/*~

