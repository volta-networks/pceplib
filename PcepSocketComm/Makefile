AR= ar
ARFLAGS = rc
CC= gcc
CFLAGS = -I$(INC_DIR) -I$(PCEP_UTILS_INC_DIR) -g -Wall -Werror
RANLIB = ranlib

INC_DIR = include
OBJ_DIR = ./obj
SRC_DIR = ./src
LIB_DIR = ../build
TEST_DIR = ./test
PCEP_UTILS_INC_DIR = ../PcepUtils/include

LIB = $(LIB_DIR)/libPcepSocketComm.a

_DEPS = *.h
DEPS = $(patsubst %,$(INC_DIR)/%,$(_DEPS)) $(patsubst %,$(SRC_DIR)/%,$(_DEPS))
EXTERNAL_DEPS = $(patsubst %,$(PCEP_UTILS_INC_DIR)/%,$(_DEPS))

_OBJ = PcepSocketCommLoop.o PcepSocketComm.o
OBJ = $(patsubst %,$(OBJ_DIR)/%,$(_OBJ))

$(LIB): $(OBJ)
	$(AR) $(ARFLAGS) $@ $^ 
	$(RANLIB) $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(DEPS) $(EXTERNAL_DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(LIB) $(OBJ_DIR)/*.o *~ core $(INC_DIR)/*~ $(SRC_DIR)/*~

