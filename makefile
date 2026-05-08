BUILD_DIR = build
MAKEFLAGS += --no-print-directory

DOXYGEN_EXISTS := $(shell command -v doxygen 2> /dev/null)

.PHONY: build clean run debug docs

build:
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake .. && cmake --build .
	@ln -sf "build/compile_commands.json"

clean_hooks:
	@rm -rf build/ebpf

clean:
	@rm -rf $(BUILD_DIR)
	@rm -rf ebpf/include/vmlinux.h
	@rm -rf ebpf/skeletons/
	@rm -rf docs/html
	@rm -rf docs/latex
	@echo "Build directory cleaned." 

docs:
ifndef DOXYGEN_EXISTS
	@echo "Error: Doxygen is not installed."
	@echo "Install it using: 'sudo pacman -S doxygen'"
	@exit 1
else
	@echo "Generating OdinSight documentation..."
	@cd docs && doxygen Doxyfile
	@echo "Documentation generated successfully."
endif

init:
	@sudo $(BUILD_DIR)/app/daemon/OdinSight_daemon
launch:
	$(BUILD_DIR)/app/launcher/OdinSight_launcher


debug:
	@sudo cat /sys/kernel/tracing/trace_pipe

test:
	@ctest --test-dir $(BUILD_DIR) --output-on-failure
