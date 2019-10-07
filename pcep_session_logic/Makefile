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
PCEP_UTILS_INC_DIR = ../pcep_utils/include
PCEP_MESSAGES_INC_DIR = ../pcep_messages/include
PCEP_TIMERS_INC_DIR = ../pcep_timers/include
PCEP_SOCKETCOMM_INC_DIR = ../pcep_socket_comm/include

LIB = $(LIB_DIR)/libpcep_session_logic.a

_DEPS = *.h
DEPS = $(patsubst %,$(INC_DIR)/%,$(_DEPS)) $(patsubst %,$(SRC_DIR)/%,$(_DEPS))
EXTERNAL_DEPS = $(patsubst %,$(PCEP_UTILS_INC_DIR)/%,$(_DEPS))  \
                $(patsubst %,$(PCEP_MESSAGES_INC_DIR)/%,$(_DEPS)) \
                $(patsubst %,$(PCEP_TIMERS_INC_DIR)/%,$(_DEPS)) \
                $(patsubst %,$(PCEP_SOCKETCOMM_INC_DIR)/%,$(_DEPS))

_OBJ = pcep_session_logic.o pcep_session_logic_loop.o pcep_session_logic_states.o
OBJ = $(patsubst %,$(OBJ_DIR)/%,$(_OBJ))

all: $(LIB)

$(LIB): $(OBJ)
	$(AR) $(ARFLAGS) $@ $^ 
	$(RANLIB) $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(DEPS) $(EXTERNAL_DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)


.PHONY: clean

clean:
	rm -f $(LIB) $(OBJ_DIR)/*.o *~ core $(INC_DIR)/*~ $(SRC_DIR)/*~

