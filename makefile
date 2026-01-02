CC := gcc

SRC := src
BUILD := build

COMP_FLAGS := -Wall -Wextra -fPIC
LINK_FLAGS_SHARED := -shared

OUTPUT_SHARED := $(BUILD)/libhashmap.so
OUTPUT_STATIC := $(BUILD)/libhashmap.a

INPUT_FILES := $(shell find $(SRC) -name "*.c")
OUTPUT_FILES := $(patsubst $(SRC)/%.c, $(BUILD)/%.o, $(INPUT_FILES))

.PHONY: all clean touch_all static dynamic

all: $(OUTPUT_SHARED)

static: $(OUTPUT_STATIC)

dynamic: $(OUTPUT_SHARED)

$(OUTPUT_SHARED): $(OUTPUT_FILES)
	$(CC) $(LINK_FLAGS_SHARED) -o $@ $^

$(OUTPUT_STATIC): $(OUTPUT_FILES)
	ar -rcs $@ $^

$(BUILD)/%.o: $(SRC)/%.c
	@mkdir -p $(dir $@)
	$(CC) -c -o $@ $(COMP_FLAGS) -MMD -MP $<

clean:
	@rm -rf $(BUILD)

# this rule allows you to do `make touch_all` and on next `make`/`make run` since the files "changed" make will recompile them all.
touch_all:
	@touch $(INPUT_FILES)

-include $(OUTPUT_FILES:.o=.d)