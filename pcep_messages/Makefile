AR= ar
ARFLAGS = rc
CC= gcc
CFLAGS = -I$(INC_DIR) -I$(PCEP_UTILS_INC_DIR) -g -Wall -Werror -fPIC
RANLIB = ranlib

INC_DIR = include
OBJ_DIR = ./obj
SRC_DIR = ./src
BUILD_DIR = ../build
PCEP_UTILS_INC_DIR = ../pcep_utils/include
TEST_DIR = ./test
TEST_LIB_DIRS = -L$(BUILD_DIR) -L/usr/local/lib
TEST_LIBS = -l$(LIB_NAME) -lpcep_utils -lcunit
VALGRIND=G_SLICE=always-malloc G_DEBUG=gc-friendly valgrind -v --tool=memcheck --leak-check=full --num-callers=40 --error-exitcode=1

LIB_NAME = pcep_messages
LIB = $(BUILD_DIR)/lib$(LIB_NAME).a
TEST_BIN = $(BUILD_DIR)/pcep_messages_tests

_DEPS = *.h
DEPS = $(patsubst %,$(INC_DIR)/%,$(_DEPS))
EXTERNAL_DEPS = $(patsubst %,$(PCEP_UTILS_INC_DIR)/%,$(_DEPS))

_OBJ = pcep-messages.o pcep-objects.o pcep-tools.o pcep-tlvs.o
OBJ = $(patsubst %,$(OBJ_DIR)/%,$(_OBJ))

_TEST_OBJ = pcep-messages-tests.o pcep-messages-test.o pcep-tlvs-test.o pcep-objects-test.o
TEST_OBJ = $(patsubst %,$(TEST_DIR)/%,$(_TEST_OBJ))

all: $(LIB) $(TEST_BIN)

$(LIB): $(OBJ)
	$(shell [ ! -d $(@D) ] && mkdir -p $(@D))
	$(AR) $(ARFLAGS) $@ $^ 
	$(RANLIB) $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(DEPS) $(EXTERNAL_DEPS)
	$(shell [ ! -d $(@D) ] && mkdir -p $(@D))
	$(CC) -c -o $@ $< $(CFLAGS)

$(TEST_BIN): $(TEST_OBJ) $(LIB)
	$(CC) -o $@ $(TEST_OBJ) $(CFLAGS) $(TEST_LIB_DIRS) $(TEST_LIBS)

$(TEST_DIR)/%.o: $(TEST_DIR)/%.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: all clean test

test: $(TEST_BIN)
	$(TEST_BIN)
	$(VALGRIND) --log-file=valgrind.$(LIB_NAME).log $(TEST_BIN)
	$(VALGRIND) --log-file=valgrind.$(LIB_NAME).log $(TEST_BIN) || ({ echo "Valgrind memory check error"; exit 1; })

clean:
	rm -f $(LIB) $(TEST_BIN) $(OBJ_DIR)/*.o valgrind*.log *~ core $(INC_DIR)/*~ $(SRC_DIR)/*~

