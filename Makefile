CC := gcc 
CFLAGS := -Wall -Wextra -O1 -g 
# Simplified includes - using standard paths
INCLUDES := -Iinclude -I/usr/include/ncursesw
LIBS := -lpcap -lpthread -lncursesw 

SRC_DIR := src
OBJ_DIR := obj
BIN_NAME := sniffer

# 1. Find all .c files in the src directory
SRCS := $(wildcard $(SRC_DIR)/*.c)

# 2. Convert that list into .o files in the obj directory
# This uses 'patsubst' which is more reliable than shorthand on some systems
OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

# Default target 
all: $(BIN_NAME)

# Link the binary - Depends on the object files
$(BIN_NAME): $(OBJS)
	@echo "Linking executable: $@..."
	$(CC) $(OBJS) -o $(BIN_NAME) $(LIBS)

# Compile .c to .o
# The mkdir ensures the obj directory exists before the first file compiles
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	@echo "Compiling: $<"
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Clean up
clean:
	@echo "Cleaning up build artifacts..."
	rm -rf $(OBJ_DIR) $(BIN_NAME)

run: $(BIN_NAME)
	sudo ./$(BIN_NAME) $(ARGS)

.PHONY: all clean run