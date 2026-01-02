CC := gcc

SRC := src
BUILD := build

COMP_FLAGS := -Wall -Wextra -fPIC
LINK_FLAGS := -shared

OUTPUT := $(BUILD)/libhashmap.so

INPUT_FILES := $(shell find $(SRC) -name "*.c")
OUTPUT_FILES := $(patsubst $(SRC)/%.c, $(BUILD)/%.o, $(INPUT_FILES))

.PHONY: all clean run touch_all

all: $(OUTPUT)

$(OUTPUT): $(OUTPUT_FILES)
	$(CC) $(LINK_FLAGS) -o $@ $^

$(BUILD)/%.o: $(SRC)/%.c
	@mkdir -p $(dir $@)
	$(CC) -c -o $@ $(COMP_FLAGS) -MMD -MP $<

clean:
	@rm -rf $(BUILD)

# this rule allows you to do `make touch_all` and on next `make`/`make run` since the files "changed" make will recompile them all.
touch_all:
	@touch $(INPUT_FILES)

-include $(OUTPUT_FILES:.o=.d)