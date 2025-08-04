# Compiler settings
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -I.
LDFLAGS = -pthread

# Platform-specific settings
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    LDFLAGS += 
endif
ifeq ($(UNAME_S),Darwin)
    LDFLAGS += 
endif
ifneq (,$(findstring MINGW,$(UNAME_S)))
    LDFLAGS += -lws2_32
endif

# Build modes
DEBUG_FLAGS = -g -O0 -DDEBUG
RELEASE_FLAGS = -O3 -DNDEBUG

# Default to release mode
MODE ?= release
ifeq ($(MODE),debug)
    CXXFLAGS += $(DEBUG_FLAGS)
else
    CXXFLAGS += $(RELEASE_FLAGS)
endif

# Source files and targets
EXAMPLES = simple_test example_server example_client example_streaming integration_test
TARGETS = $(EXAMPLES)

# Default target
all: $(TARGETS)

# Individual targets
simple_test: simple_test.cpp cppi.hpp types.hpp errors.hpp helpers.hpp utils.hpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

example_server: example_server.cpp cppi.hpp types.hpp errors.hpp helpers.hpp utils.hpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

example_client: example_client.cpp cppi.hpp types.hpp errors.hpp helpers.hpp utils.hpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

example_streaming: example_streaming.cpp cppi.hpp types.hpp errors.hpp helpers.hpp utils.hpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

integration_test: integration_test.cpp cppi.hpp types.hpp errors.hpp helpers.hpp utils.hpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

# Test targets
test: simple_test
	./simple_test

test-client: example_client
	./example_client

test-integration: integration_test
	./integration_test

test-all: test test-client test-integration
	@echo "All tests completed!"

# Debug build
debug:
	$(MAKE) MODE=debug all

# Clean build artifacts
clean:
	rm -f $(TARGETS)
	rm -rf build/

# Install headers (requires sudo on most systems)
install:
	mkdir -p /usr/local/include/cppi
	cp cppi.hpp types.hpp errors.hpp helpers.hpp utils.hpp /usr/local/include/cppi/
	mkdir -p /usr/local/include/nlohmann
	cp external/json/single_include/nlohmann/json.hpp /usr/local/include/nlohmann/

# Uninstall
uninstall:
	rm -rf /usr/local/include/cppi
	rm -f /usr/local/include/nlohmann/json.hpp

# CMake build
cmake-build:
	mkdir -p build
	cd build && cmake .. && make

# Run static analysis (requires cppcheck)
static-analysis:
	cppcheck --enable=all --std=c++17 --suppress=missingIncludeSystem *.hpp *.cpp

# Format code (requires clang-format)
format:
	clang-format -i *.hpp *.cpp

# Generate documentation (requires doxygen)
docs:
	doxygen Doxyfile

# Package for distribution
package:
	tar -czf cppi.tar.gz *.hpp *.cpp CMakeLists.txt Makefile README.md LICENSE

# Help
help:
	@echo "CPPI Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all              - Build all examples (default)"
	@echo "  simple_test      - Build simple functionality test"
	@echo "  example_server   - Build HTTP server example"
	@echo "  example_client   - Build HTTP client example"
	@echo "  example_streaming- Build streaming examples"
	@echo "  test             - Run basic functionality test"
	@echo "  test-client      - Run client tests"
	@echo "  debug            - Build with debug flags"
	@echo "  clean            - Remove build artifacts"
	@echo "  install          - Install headers system-wide"
	@echo "  uninstall        - Remove installed headers"
	@echo "  cmake-build      - Build using CMake"
	@echo "  static-analysis  - Run static code analysis"
	@echo "  format           - Format code with clang-format"
	@echo "  docs             - Generate documentation"
	@echo "  package          - Create distribution package"
	@echo "  help             - Show this help message"
	@echo ""
	@echo "Options:"
	@echo "  MODE=debug       - Build with debug flags"
	@echo "  MODE=release     - Build with optimization (default)"

.PHONY: all test test-client debug clean install uninstall cmake-build static-analysis format docs package help
