BUILD_DIR = build
MAKEFLAGS += --no-print-directory

.PHONY: build clean run debug

build:
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake .. && cmake --build .
	@ln -sf "build/compile_commands.json"

clean:
	@rm -rf $(BUILD_DIR)
	@echo "Build directory cleaned." 

init:
	@sudo $(BUILD_DIR)/app/daemon/TyrSecure_daemon
run:
	@sudo $(BUILD_DIR)/app/launcher/TyrSecure_launcher

run2:
	@sudo $(BUILD_DIR)/app/epoll_test/TyrSecure_epoll
	

debug:
	@sudo cat /sys/kernel/tracing/trace_pipe

test:
	@ctest --test-dir $(BUILD_DIR) --output-on-failure
