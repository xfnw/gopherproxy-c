.POSIX:

BIN = gopherproxy
OBJ = $(BIN:=.o)

# OpenBSD: use pledge(2).
#CFLAGS += -DUSE_PLEDGE
# build static: useful in www chroot.
#LDFLAGS += -static

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(OBJ) $(LDFLAGS) -o $@

clean:
	rm -f $(BIN) $(OBJ)
