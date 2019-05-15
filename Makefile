.POSIX:

BIN = gopherproxy
OBJ = $(BIN:=.o)

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
