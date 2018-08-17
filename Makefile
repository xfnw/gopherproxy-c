.POSIX:

BIN = gopherproxy
OBJ = $(BIN:=.o)

# OpenBSD: use pledge(2).
#CFLAGS += -DUSE_PLEDGE
# build static: useful in www chroot.
LDFLAGS += -static
# Linux
#CPPFLAGS += -D_DEFAULT_SOURCE

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(OBJ) $(LDFLAGS) -o $@

$(OBJ): Makefile

clean:
	rm -f $(BIN) $(OBJ)
