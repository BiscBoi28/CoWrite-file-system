CC := gcc
CFLAGS := -Wall -Wextra -Werror -std=c11 -pedantic -I.
LDFLAGS :=

COMMON_SRCS := common/net_proto.c common/json_util.c common/error.c common/log.c common/array.c common/randutil.c
COMMON_OBJS := $(COMMON_SRCS:.c=.o)

NM_SRCS := nm/nm_main.c nm/nm_state.c
NM_OBJS := $(NM_SRCS:.c=.o)

SS_SRCS := ss/ss_main.c ss/ss_state.c
SS_OBJS := $(SS_SRCS:.c=.o)

CLI_SRCS := client/cli_main.c
CLI_OBJS := $(CLI_SRCS:.c=.o)

BIN_DIR := bin

NM_BIN := $(BIN_DIR)/nm
SS_BIN := $(BIN_DIR)/ss
CLI_BIN := $(BIN_DIR)/docs_client

.PHONY: all clean

all: $(NM_BIN) $(SS_BIN) $(CLI_BIN)

.PHONY: test
test: all
	python3 tests/test_basic.py

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(NM_BIN): $(BIN_DIR) $(COMMON_OBJS) $(NM_OBJS)
	$(CC) $(CFLAGS) -o $@ $(COMMON_OBJS) $(NM_OBJS) $(LDFLAGS)

$(SS_BIN): $(BIN_DIR) $(COMMON_OBJS) $(SS_OBJS)
	$(CC) $(CFLAGS) -o $@ $(COMMON_OBJS) $(SS_OBJS) $(LDFLAGS)

$(CLI_BIN): $(BIN_DIR) $(COMMON_OBJS) $(CLI_OBJS)
	$(CC) $(CFLAGS) -o $@ $(COMMON_OBJS) $(CLI_OBJS) $(LDFLAGS)

clean:
	rm -f $(COMMON_OBJS) $(NM_OBJS) $(SS_OBJS) $(CLI_OBJS)
	rm -rf $(BIN_DIR)
