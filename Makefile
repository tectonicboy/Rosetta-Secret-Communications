# -*- MakeFile -*-

# MAKEFILE ENTRIES COMMON TO ALL 3 PROJECT MAKEFILES: common-build-config.mk

include assets/common-build-config.mk

PRIMARY_TARGETS   = server client test_framework tools
SECONDARY_TARGETS = clean distclean
MISC_TARGETS      = client_asan server_asan

.PHONY: all build_dir
.PHONY: $(PRIMARY_TARGETS)
.PHONY: $(SECONDARY_TARGETS)
.PHONY: $(MISC_TARGETS)

ADDRESS_SANITIZER_FLAGS += -fsanitize=address -static-libasan -g -fstack-usage

# Ask GCC to tell us of any vectorization and loop optimizations it performed
# when building the server and client sources.
COMPILER_OPTIMIZATION_REPORT += -fopt-info-vec-optimized
COMPILER_OPTIMIZATION_REPORT += -fopt-info-loop-optimized

# For the wxWidgets C++ GUI user-facing client driver program.
WX_WIDGETS_SPECIFIC = `/usr/bin/wx-config --cxxflags --libs`

BIN_DIR                 =  ./bin
ROSETTA_SERVER_SRC      =  src/server/rosetta-server.c
ROSETTA_SERVER_BIN      =  rosetta-server
ROSETTA_SERVER_ASAN_BIN =  rosetta-server-asan
ROSETTA_CLIENT_SRC      += src/client/gui-code/cApp.cpp
ROSETTA_CLIENT_SRC      += src/client/gui-code/cMain.cpp
ROSETTA_CLIENT_BIN      =  rosetta-client
ROSETTA_CLIENT_ASAN_BIN =  rosetta-client-asan

GENERATED_ARTIFACTS += performance-analysis/last-measurements.dat
GENERATED_ARTIFACTS += performance-analysis/latest-stabilized-averages.dat

all: $(PRIMARY_TARGETS)

# INFO: mkdir -p will do nothing if the directory exists and will return code 0.
#
# INFO: the | syntax is an order-only dependency. Makefile dependencies normally
#       serve two different purposes simultaneously:
#
#          - Build ordering    - "this must happen first"
#          - Rebuild detection - "if this changed, rebuild me"
#
#       With an order-only dependency, it does not play a role in Make deciding
#       whether to rebuild the target that depends on it. The only requirement:
#       the filesystem artifacts produced by that target must exist at the time
#       the dependent recipe runs. That's why I use it for targets that depend
#       on build_dir - so they can have the directory wherein to place binaries.
#
#       With a regular dependency, rebuild detection is in the picture too:
#
#       If the dependency's filesystem state (specifically, the modification
#       timestamp of the filesystem artifacts it produces) is NEWER than the
#       target that depends on it, the target is considered out-of-date and
#       rebuilt. An order-only dependency is excluded from that check.

build_dir:
	@mkdir -p bin/manual-user-testing bin/automatic-user-testing bin/tools

test_framework: | build_dir
	$(MAKE) -C ./src/rosetta-test-framework

tools: | build_dir
	$(MAKE) -C ./src/tools

server: | build_dir
	$(CC) $(ROSETTA_SERVER_SRC) -o $(BIN_DIR)/$(ROSETTA_SERVER_BIN) \
	$(OPTIMIZATION_LEVEL) $(COMPILER_OPTIMIZATION_REPORT) $(CFLAGS) \
	$(CSTD) $(ARCHITECTURE_FLAGS) $(GNU_OPTIMIZATION_FLAGS) $(EXTRA_FLAGS) \
	$(LDFLAGS) $(LDLIBS)

client: | build_dir
	$(CXX) $(ROSETTA_CLIENT_SRC) -o $(BIN_DIR)/$(ROSETTA_CLIENT_BIN) \
	$(OPTIMIZATION_LEVEL) $(COMPILER_OPTIMIZATION_REPORT) \
	$(CXXFLAGS) $(CXXSTD) $(ARCHITECTURE_FLAGS) $(GNU_OPTIMIZATION_FLAGS) \
	$(EXTRA_FLAGS) $(WX_WIDGETS_SPECIFIC) $(LDFLAGS) $(LDLIBS)

server_asan: | build_dir
	$(CC) $(ROSETTA_SERVER_SRC) -o $(BIN_DIR)/$(ROSETTA_SERVER_ASAN_BIN) \
	$(OPTIMIZATION_LEVEL) $(COMPILER_OPTIMIZATION_REPORT) \
	$(CFLAGS) $(CSTD) $(ARCHITECTURE_FLAGS) \
	$(ADDRESS_SANITIZER_FLAGS) $(EXTRA_FLAGS) $(LDFLAGS) $(LDLIBS)

client_asan: | build_dir
	$(CXX) $(ROSETTA_CLIENT_SRC) -o $(BIN_DIR)/$(ROSETTA_CLIENT_ASAN_BIN) \
	$(OPTIMIZATION_LEVEL) $(COMPILER_OPTIMIZATION_REPORT) \
	$(CXXFLAGS) $(CXXSTD) $(ARCHITECTURE_FLAGS) $(ADDRESS_SANITIZER_FLAGS) \
	$(EXTRA_FLAGS) $(WX_WIDGETS_SPECIFIC) $(LDFLAGS) $(LDLIBS)

clean:
	rm -rf $(BIN_DIR)/$(ROSETTA_SERVER_BIN)      && \
	rm -rf $(BIN_DIR)/$(ROSETTA_SERVER_ASAN_BIN) && \
	rm -rf $(BIN_DIR)/$(ROSETTA_CLIENT_BIN)      && \
	rm -rf $(BIN_DIR)/$(ROSETTA_CLIENT_ASAN_BIN)
	$(MAKE) -C ./src/rosetta-test-framework clean
	$(MAKE) -C ./src/tools clean

distclean:
	rm -rf $(BIN_DIR)
	rm -rf $(GENERATED_ARTIFACTS)
