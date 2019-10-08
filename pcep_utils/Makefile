AR= ar
ARFLAGS = rc
CC= gcc
CFLAGS = -I$(INC_DIR) -g -Wall -Werror
RANLIB = ranlib

INC_DIR = include
OBJ_DIR = ./obj
SRC_DIR = ./src
BUILD_DIR = ../build
TEST_DIR = ./test
TEST_LIB_DIRS = -L$(BUILD_DIR) -L/usr/local/lib
TEST_LIBS = -l$(LIB_NAME) -lcunit

LIB_NAME = pcep_utils
LIB = $(BUILD_DIR)/lib$(LIB_NAME).a
TEST = $(BUILD_DIR)/pcep_utils_tests

_DEPS = *.h
DEPS = $(patsubst %,$(INC_DIR)/%,$(_DEPS))

_OBJ = pcep_utils_ordered_list.o pcep_utils_queue.o
OBJ = $(patsubst %,$(OBJ_DIR)/%,$(_OBJ))

_TEST_OBJ = pcep_utils_tests.o pcep_utils_ordered_list_test.o pcep_utils_queue_test.o
TEST_OBJ = $(patsubst %,$(TEST_DIR)/%,$(_TEST_OBJ))


all: $(LIB) $(TEST)

$(LIB): $(OBJ)
	$(AR) $(ARFLAGS) $@ $^ 
	$(RANLIB) $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(TEST): $(TEST_OBJ) $(LIB)
	$(CC) -o $@ $(TEST_OBJ) $(CFLAGS) -static $(TEST_LIB_DIRS) $(TEST_LIBS)

$(TEST_DIR)/%.o: $(TEST_DIR)/%.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(LIB) $(TEST) $(OBJ_DIR)/*.o $(TEST_DIR)/*.o *~ core $(INC_DIR)/*~ $(SRC_DIR)/*~

