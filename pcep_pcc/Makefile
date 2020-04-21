AR= ar
ARFLAGS = rc
RANLIB = ranlib
CC= gcc
CFLAGS += -Wall -Werror -fPIC \
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
TEST_DIR = ./test
TEST_LIB_DIRS = -L$(BUILD_DIR) -L/usr/local/lib
TEST_LIBS = -l$(LIB_NAME) -lpcep_session_logic -lpcep_socket_comm_mock -lpcep_messages -lpcep_utils -lpcep_timers -lcunit -lpthread
VALGRIND=G_SLICE=always-malloc G_DEBUG=gc-friendly valgrind -v --tool=memcheck --leak-check=full --num-callers=40 --error-exitcode=1

LIB_NAME = pcep_pcc_api
LIB = $(BUILD_DIR)/lib$(LIB_NAME).a
BIN = $(BUILD_DIR)/pcep_pcc
TEST_BIN = $(BUILD_DIR)/pcep_pcc_api_tests

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
_TEST_OBJ = pcep_pcc_api_tests.o pcap_pcc_api_test.o
TEST_OBJ = $(patsubst %,$(TEST_DIR)/%,$(_TEST_OBJ))

all: $(LIB) $(BIN) $(TEST_BIN)

$(LIB): $(LIB_OBJ)
	$(shell [ ! -d $(@D) ] && mkdir -p $(@D))
	$(AR) $(ARFLAGS) $@ $^ 
	$(RANLIB) $@

$(BIN): $(BIN_OBJ) $(LIB_DEPS)
	$(shell [ ! -d $(@D) ] && mkdir -p $(@D))
	$(CC) -o $@ $(BIN_OBJ) -L$(BUILD_DIR) $(LIBS)  $(COVERAGE_FLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(DEPS) $(EXTERNAL_DEPS)
	$(shell [ ! -d $(@D) ] && mkdir -p $(@D))
	$(CC) -c -o $@ $< $(CFLAGS) $(COVERAGE_FLAGS)

$(TEST_BIN): $(TEST_OBJ) $(LIB)
	$(CC) -o $@ $(TEST_OBJ) $(CFLAGS) $(TEST_LIB_DIRS) $(TEST_LIBS) $(COVERAGE_FLAGS)

$(TEST_DIR)/%.o: $(TEST_DIR)/%.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) -I$(SRC_DIR) $(COVERAGE_FLAGS)

.PHONY: all clean test

test: $(TEST_BIN)
	$(VALGRIND) --log-file=valgrind.$(LIB_NAME).log $(TEST_BIN) || ({ echo "Valgrind memory check error"; exit 1; })

clean:
	rm -f $(LIB) $(BIN) $(TEST_BIN) $(OBJ_DIR)/*.o $(TEST_DIR)/*.o valgrind*.log *~ core $(INC_DIR)/*~ $(SRC_DIR)/*~

