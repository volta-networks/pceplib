AR= ar
ARFLAGS = rc
CC= gcc
CFLAGS = -I$(INC_DIR) -g -Wall -Werror
RANLIB = ranlib

INC_DIR = include
OBJ_DIR = ./obj
SRC_DIR = ./src
LIB_DIR = ../build

LIB = $(LIB_DIR)/libpcep_messages.a

_DEPS = *.h
DEPS = $(patsubst %,$(INC_DIR)/%,$(_DEPS))

_OBJ = pcep-messages.o pcep-objects.o pcep-tools.o
OBJ = $(patsubst %,$(OBJ_DIR)/%,$(_OBJ))

all: $(LIB)

$(LIB): $(OBJ)
	$(AR) $(ARFLAGS) $@ $^ 
	$(RANLIB) $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(LIB) $(OBJ_DIR)/*.o *~ core $(INC_DIR)/*~ $(SRC_DIR)/*~

