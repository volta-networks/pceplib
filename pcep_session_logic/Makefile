AR= ar
ARFLAGS = rc
RANLIB = ranlib
CC= gcc
CFLAGS += -Wall -Werror -fPIC \
 -I$(INC_DIR) \
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
TEST_LIBS = -l$(LIB_NAME) -lpcep_messages -lpcep_utils -lpcep_socket_comm_mock -lpcep_timers -lcunit -lpthread
VALGRIND=G_SLICE=always-malloc G_DEBUG=gc-friendly valgrind -v --tool=memcheck --leak-check=full --num-callers=40 --error-exitcode=1

LIB_NAME = pcep_session_logic
LIB = $(BUILD_DIR)/lib$(LIB_NAME).a
TEST_BIN = $(BUILD_DIR)/pcep_session_logic_tests

_DEPS = *.h
DEPS = $(patsubst %,$(INC_DIR)/%,$(_DEPS)) $(patsubst %,$(SRC_DIR)/%,$(_DEPS))
EXTERNAL_DEPS = $(patsubst %,$(PCEP_UTILS_INC_DIR)/%,$(_DEPS))  \
                $(patsubst %,$(PCEP_MESSAGES_INC_DIR)/%,$(_DEPS)) \
                $(patsubst %,$(PCEP_TIMERS_INC_DIR)/%,$(_DEPS)) \
                $(patsubst %,$(PCEP_SOCKETCOMM_INC_DIR)/%,$(_DEPS))

_OBJ = pcep_session_logic.o pcep_session_logic_loop.o pcep_session_logic_states.o pcep_session_logic_counters.o
OBJ = $(patsubst %,$(OBJ_DIR)/%,$(_OBJ))

_TEST_OBJ = pcep_session_logic_tests.o pcep_session_logic_test.o pcep_session_logic_loop_test.o pcep_session_logic_states_test.o
TEST_OBJ = $(patsubst %,$(TEST_DIR)/%,$(_TEST_OBJ))

all: $(LIB) $(TEST_BIN)

$(LIB): $(OBJ)
	$(shell [ ! -d $(@D) ] && mkdir -p $(@D))
	$(AR) $(ARFLAGS) $@ $^ 
	$(RANLIB) $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(DEPS) $(EXTERNAL_DEPS)
	$(shell [ ! -d $(@D) ] && mkdir -p $(@D))
	$(CC) -c -o $@ $< $(CFLAGS) $(COVERAGE_FLAGS)

$(TEST_BIN): $(TEST_OBJ) $(LIB)
	$(CC) -o $@ $(TEST_OBJ) $(CFLAGS) $(TEST_LIB_DIRS) $(TEST_LIBS) $(COVERAGE_FLAGS)

$(TEST_DIR)/%.o: $(TEST_DIR)/%.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) -I$(SRC_DIR) $(COVERAGE_FLAGS)

.PHONY: all clean test

test: $(TEST_BIN)
	$(TEST_BIN)
	$(VALGRIND) --log-file=valgrind.$(LIB_NAME).log $(TEST_BIN) || ({ echo "Valgrind memory check error"; exit 1; })

clean:
	rm -f $(LIB) $(TEST_BIN) $(OBJ_DIR)/*.o $(TEST_DIR)/*.o valgrind*.log *~ core $(INC_DIR)/*~ $(SRC_DIR)/*~

