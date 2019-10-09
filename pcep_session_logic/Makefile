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
BUILD_DIR = ../build
PCEP_UTILS_INC_DIR = ../pcep_utils/include
PCEP_MESSAGES_INC_DIR = ../pcep_messages/include
PCEP_TIMERS_INC_DIR = ../pcep_timers/include
PCEP_SOCKETCOMM_INC_DIR = ../pcep_socket_comm/include
TEST_DIR = ./test
TEST_LIB_DIRS = -L$(BUILD_DIR) -L/usr/local/lib
TEST_LIBS = -l$(LIB_NAME) -lpcep_messages -lpcep_utils -lpcep_timers -lpcep_socket_comm -lcunit -lpthread

LIB_NAME = pcep_session_logic
LIB = $(BUILD_DIR)/lib$(LIB_NAME).a
TEST = $(BUILD_DIR)/pcep_session_logic_tests

_DEPS = *.h
DEPS = $(patsubst %,$(INC_DIR)/%,$(_DEPS)) $(patsubst %,$(SRC_DIR)/%,$(_DEPS))
EXTERNAL_DEPS = $(patsubst %,$(PCEP_UTILS_INC_DIR)/%,$(_DEPS))  \
                $(patsubst %,$(PCEP_MESSAGES_INC_DIR)/%,$(_DEPS)) \
                $(patsubst %,$(PCEP_TIMERS_INC_DIR)/%,$(_DEPS)) \
                $(patsubst %,$(PCEP_SOCKETCOMM_INC_DIR)/%,$(_DEPS))

_OBJ = pcep_session_logic.o pcep_session_logic_loop.o pcep_session_logic_states.o
OBJ = $(patsubst %,$(OBJ_DIR)/%,$(_OBJ))

_TEST_OBJ = mock_socket_comm.o pcep_session_logic_tests.o pcep_session_logic_test.o pcep_session_logic_loop_test.o pcep_session_logic_states_test.o
TEST_OBJ = $(patsubst %,$(TEST_DIR)/%,$(_TEST_OBJ))

all: $(LIB) $(TEST)

$(LIB): $(OBJ)
	$(AR) $(ARFLAGS) $@ $^ 
	$(RANLIB) $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(DEPS) $(EXTERNAL_DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(TEST): $(TEST_OBJ) $(LIB)
	$(CC) -o $@ $(TEST_OBJ) $(CFLAGS) -static $(TEST_LIB_DIRS) $(TEST_LIBS)

$(TEST_DIR)/%.o: $(TEST_DIR)/%.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) -I$(SRC_DIR)

.PHONY: clean

clean:
	rm -f $(LIB) $(TEST) $(OBJ_DIR)/*.o $(TEST_DIR)/*.o *~ core $(INC_DIR)/*~ $(SRC_DIR)/*~

