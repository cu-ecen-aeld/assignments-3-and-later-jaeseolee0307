# Compiler and flags
CC := $(CROSS_COMPILE)gcc
CFLAGS := -Wall -Wextra

# Source files and object files
SRC := aesdsocket.c
OBJ := $(SRC:.c=.o)
TARGET := aesdsocket

# Phony targets
.PHONY: all clean

# Default target
all: $(TARGET)

# Linking target
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# Compilation target
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Clean target
clean:
	rm -f $(OBJ) $(TARGET)

