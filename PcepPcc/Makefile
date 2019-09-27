CC= gcc
CFLAGS = -g -Wall -Werror \
 -I$(PCEP_SESSION_LOGIC_INC_DIR) \
 -I$(PCEP_UTILS_INC_DIR) \
 -I$(PCEP_MESSAGES_INC_DIR) \
 -I$(PCEP_TIMERS_INC_DIR) \
 -I$(PCEP_SOCKETCOMM_INC_DIR)

BUILD_DIR = ../build
TEST_DIR = ./test
PCEP_SESSION_LOGIC_INC_DIR = ../PcepSessionLogic/include
PCEP_UTILS_INC_DIR = ../PcepUtils/include
PCEP_MESSAGES_INC_DIR = ../PcepMessages/include
PCEP_TIMERS_INC_DIR = ../PcepTimers/include
PCEP_SOCKETCOMM_INC_DIR = ../PcepSocketComm/include

BIN = $(BUILD_DIR)/pcep_pcc

LIB_DEPS = $(BUILD_DIR)/libPcepSessionLogic.a \
 $(BUILD_DIR)/libPcepSocketComm.a \
 $(BUILD_DIR)/libPcepTimers.a \
 $(BUILD_DIR)/libPcepMessages.a \
 $(BUILD_DIR)/libPcepUtils.a
_LIBS = $(subst $(BUILD_DIR)/lib,-l,$(LIB_DEPS))
LIBS = $(subst .a,,$(_LIBS)) -lpthread

_DEPS = *.h
EXTERNAL_DEPS = $(patsubst %,$(PCEP_SESSION_LOGIC_INC_DIR)/%,$(_DEPS))

OBJ = pcep_pcc.o

$(BIN): $(OBJ) $(LIB_DEPS)
	$(CC) -o $@ $(OBJ) -L$(BUILD_DIR) $(LIBS) 

$(OBJ): *.c $(DEPS) $(EXTERNAL_DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(BIN) $(OBJ_DIR)/*.o *~ core $(SRC_DIR)/*~

