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

LIB = $(LIB_DIR)/libPcepUtils.a

_DEPS = *.h
DEPS = $(patsubst %,$(INC_DIR)/%,$(_DEPS))

_OBJ = PcepUtilsOrderedList.o PcepUtilsQueue.o
OBJ = $(patsubst %,$(OBJ_DIR)/%,$(_OBJ))

_TEST_OBJ = PcepUtilsOrderedListTest.o PcepUtilsQueueTest.o
TEST_OBJ = $(patsubst %,$(TEST_DIR)/%,$(_TEST_OBJ))

$(LIB): $(OBJ)
	$(AR) $(ARFLAGS) $@ $^ 
	$(RANLIB) $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

test: $(TEST_OBJ)
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(LIB) $(OBJ_DIR)/*.o *~ core $(INC_DIR)/*~ $(SRC_DIR)/*~

