AR= ar
ARFLAGS = rc
CC= gcc
CFLAGS = -I$(INC_DIR) -g -Wall -Werror
RANLIB = ranlib

INC_DIR = include
OBJ_DIR = ./obj
SRC_DIR = ./src
LIB_DIR = ../build
TEST_DIR = ./test

LIB = $(LIB_DIR)/libpcep_utils.a

_DEPS = *.h
DEPS = $(patsubst %,$(INC_DIR)/%,$(_DEPS))

_OBJ = pcep_utils_ordered_list.o pcep_utils_queue.o
OBJ = $(patsubst %,$(OBJ_DIR)/%,$(_OBJ))

_TEST_OBJ = pcep_utils_ordered_list_test.o pcep_utils_queue_test.o
TEST_OBJ = $(patsubst %,$(TEST_DIR)/%,$(_TEST_OBJ))

all: $(LIB)

$(LIB): $(OBJ)
	$(AR) $(ARFLAGS) $@ $^ 
	$(RANLIB) $@

test: $(TEST_OBJ)
	$(CC) -o $(TEST_DIR)/$@ $< $(CFLAGS) -L$(LIB_DIR) -lpcep_utils

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(LIB) $(OBJ_DIR)/*.o $(TEST_DIR)/*.o *~ core $(INC_DIR)/*~ $(SRC_DIR)/*~

