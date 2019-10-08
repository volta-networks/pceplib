AR= ar
ARFLAGS = rc
CC= gcc
CFLAGS = -I$(INC_DIR) -I$(PCEP_UTILS_INC_DIR) -g -Wall -Werror
RANLIB = ranlib

INC_DIR = include
OBJ_DIR = ./obj
SRC_DIR = ./src
BUILD_DIR = ../build
PCEP_UTILS_INC_DIR = ../pcep_utils/include
TEST_DIR = ./test
TEST_LIB_DIRS = -L$(BUILD_DIR) -L/usr/local/lib
TEST_LIBS = -l$(LIB_NAME) -lpcep_utils -lcunit -lpthread

LIB_NAME = pcep_socket_comm
LIB = $(BUILD_DIR)/lib$(LIB_NAME).a
TEST = $(BUILD_DIR)/pcep_socket_comm_tests

_DEPS = *.h
DEPS = $(patsubst %,$(INC_DIR)/%,$(_DEPS)) $(patsubst %,$(SRC_DIR)/%,$(_DEPS))
EXTERNAL_DEPS = $(patsubst %,$(PCEP_UTILS_INC_DIR)/%,$(_DEPS))

_OBJ = pcep_socket_comm_loop.o pcep_socket_comm.o
OBJ = $(patsubst %,$(OBJ_DIR)/%,$(_OBJ))

_TEST_OBJ = pcep_socket_comm_tests.o pcep_socket_comm_test.o pcep_socket_comm_loop_test.o
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

