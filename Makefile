CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -g -Wall -Wextra -Werror -Icore -Isim
# Header changes (e.g. l3_t layout) must rebuild every object that uses them.
override CFLAGS += -MMD -MP
LDFLAGS ?=

BUILD := build

CORE_OBJS := $(BUILD)/crypto.o $(BUILD)/image.o $(BUILD)/xci.o $(BUILD)/lotus3.o $(BUILD)/gc_cert.o $(BUILD)/asic.o $(BUILD)/fat.o $(BUILD)/mount.o $(BUILD)/nca.o
DEMO_OBJS := $(BUILD)/fs.o $(BUILD)/main.o
TESTS     := $(BUILD)/test_crypto $(BUILD)/test_mount $(BUILD)/test_fat $(BUILD)/test_hh $(BUILD)/test_cert $(BUILD)/test_l3raw $(BUILD)/test_swap $(BUILD)/test_view $(BUILD)/test_nca

.PHONY: all check demo demo-raw image clean device nro-switch tesla
all: check demo

$(BUILD):
	@mkdir -p $(BUILD)

-include $(wildcard $(BUILD)/*.d)

$(BUILD)/%.o: core/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%.o: sim/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%.o: tests/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_%: $(BUILD)/test_%.o $(CORE_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BUILD)/test_hh.o: tests/test_hh.c | $(BUILD)
	$(CC) $(CFLAGS) -Idevice/hookhost -c $< -o $@

$(BUILD)/hh_layout.o: device/hookhost/hh_layout.c | $(BUILD)
	$(CC) $(CFLAGS) -Idevice/hookhost -c $< -o $@

$(BUILD)/test_hh: $(BUILD)/test_hh.o $(BUILD)/hh_layout.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Hot swap: both halves of the window (hook hh_swap.c, sysmodule xci_lib.c).
SWAP_INC := -Idevice/hookhost -Idevice/xci/source -Idevice/xci/client

$(BUILD)/test_swap.o: tests/test_swap.c | $(BUILD)
	$(CC) $(CFLAGS) $(SWAP_INC) -c $< -o $@

$(BUILD)/hh_swap.o: device/hookhost/hh_swap.c | $(BUILD)
	$(CC) $(CFLAGS) $(SWAP_INC) -c $< -o $@

$(BUILD)/xci_lib.o: device/xci/source/xci_lib.c | $(BUILD)
	$(CC) $(CFLAGS) $(SWAP_INC) -c $< -o $@

$(BUILD)/test_swap: $(BUILD)/test_swap.o $(BUILD)/hh_swap.o $(BUILD)/xci_lib.o $(CORE_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -lpthread

# Client presentation (switcher NRO, Tesla overlay); no libnx.
$(BUILD)/test_view.o: tests/test_view.c | $(BUILD)
	$(CC) $(CFLAGS) $(SWAP_INC) -c $< -o $@

$(BUILD)/xci_view.o: device/xci/client/xci_view.c | $(BUILD)
	$(CC) $(CFLAGS) $(SWAP_INC) -c $< -o $@

$(BUILD)/test_view: $(BUILD)/test_view.o $(BUILD)/xci_view.o $(BUILD)/xci_lib.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

device: $(BUILD)
	docker run --rm -u $$(id -u):$$(id -g) -e HOME=/tmp \
		-v "$$PWD":/work -w /work devkitpro/devkita64:libnx26 \
		env CC=aarch64-none-elf-gcc sh device/hookhost/build.sh

nro-switch:
	docker run --rm -u $$(id -u):$$(id -g) -e HOME=/tmp \
		-v "$$PWD":/work -w /work/device/nro/switcher devkitpro/devkita64:libnx26 make

tesla:
	sh device/tesla/build.sh

ro:
	python3 tools/gen_hh_layout.py
	sh device/ro/build.sh

$(BUILD)/demo: $(DEMO_OBJS) $(CORE_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

check: $(TESTS)
	@for t in $(TESTS); do echo "== $$t"; ./$$t || exit 1; done

image: $(BUILD)
	@python3 tools/mkimage.py $(BUILD)/game.xci --sd $(BUILD)/sd.img

demo: $(BUILD)/demo image
	@./$(BUILD)/demo $(BUILD)/sd.img

demo-raw: $(BUILD)/demo image
	@./$(BUILD)/demo $(BUILD)/sd.img --raw

clean:
	rm -rf $(BUILD)
