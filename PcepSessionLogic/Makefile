AR= ar
ARFLAGS = rc
RANLIB = ranlib
CC= gcc
CFLAGS = -g -Wall -Werror -I$(INC_DIR) \
 -I$(PCEP_UTILS_INC_DIR) \
 -I$(PCEP_MESSAGES_INC_DIR) \
 -I$(PCEP_TIMERS_INC_DIR) \
 -I$(PCEP_SOCKETCOMM_INC_DIR)

INC_DIR = include
OBJ_DIR = ./obj
SRC_DIR = ./src
LIB_DIR = ../build
PCEP_UTILS_INC_DIR = ../PcepUtils/include
PCEP_MESSAGES_INC_DIR = ../PcepMessages/include
PCEP_TIMERS_INC_DIR = ../PcepTimers/include
PCEP_SOCKETCOMM_INC_DIR = ../PcepSocketComm/include

LIB = $(LIB_DIR)/libPcepSessionLogic.a

_DEPS = *.h
DEPS = $(patsubst %,$(INC_DIR)/%,$(_DEPS)) $(patsubst %,$(SRC_DIR)/%,$(_DEPS))
EXTERNAL_DEPS = $(patsubst %,$(PCEP_UTILS_INC_DIR)/%,$(_DEPS))  \
                $(patsubst %,$(PCEP_MESSAGES_INC_DIR)/%,$(_DEPS)) \
                $(patsubst %,$(PCEP_TIMERS_INC_DIR)/%,$(_DEPS)) \
                $(patsubst %,$(PCEP_SOCKETCOMM_INC_DIR)/%,$(_DEPS))

_OBJ = PcepSessionLogic.o PcepSessionLogicLoop.o PcepSessionLogicStates.o
OBJ = $(patsubst %,$(OBJ_DIR)/%,$(_OBJ))

$(LIB): $(OBJ)
	$(AR) $(ARFLAGS) $@ $^ 
	$(RANLIB) $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(DEPS) $(EXTERNAL_DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)


.PHONY: clean

clean:
	rm -f $(LIB) $(OBJ_DIR)/*.o *~ core $(INC_DIR)/*~ $(SRC_DIR)/*~

