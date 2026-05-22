# -*- MakeFile -*-
.PHONY: build_dir all server server_asan client client_asan clean test_framework

CFLAGS += -D_GNU_SOURCE
CFLAGS += -Wall
CFLAGS += -Wextra
CFLAGS += -Wcast-align
CFLAGS += -Wcast-qual
CFLAGS += -Wfloat-equal
CFLAGS += -Wformat=2
CFLAGS += -Wlogical-op
CFLAGS += -Wmissing-include-dirs
CFLAGS += -Wpointer-arith
CFLAGS += -Wredundant-decls
CFLAGS += -Wsequence-point
CFLAGS += -Wshadow
CFLAGS += -Wswitch
CFLAGS += -Wundef
CFLAGS += -Wunreachable-code
CFLAGS += -Wunused-but-set-parameter
CFLAGS += -Wunused
CFLAGS += -Wstrict-aliasing
CFLAGS += -Wformat-security
CFLAGS += -Wno-stringop-truncation
CFLAGS += -Wno-unused-label
CFLAGS += -Wno-unused-result
CFLAGS += -Wno-aggregate-return
CFLAGS += -Wno-write-strings

#Some of the following GNU_OPTIMIZATION_FLAGS may not be available outside GCC.

# Use only the stack pointer for managing function-local variables.
# Do not waste an entire register for the unnecessary frame pointer.
# On x86-64, this frees up the rbp register.
GNU_OPTIMIZATION_FLAGS =
#GNU_OPTIMIZATION_FLAGS += -fomit-frame-pointer

#INFO: To check the segment sizes (like .data, .text) of an ELF binary:
#      size my_file
#
# Eliminate the code for functions that are never called.
# This includes inlined functions which the compiler emitted a non-inlined
# copy of, just in case an unpredictable external call to them happened.
# With this option turned on, we let the linker remove such functions,
# as long as it can see that they will, in fact, never be called.
# The data-sections one does the same but for unused globals.
#
# LDFLAGS += -Wl,--gc-sections is required to instruct the linker to
# perform the actual removal.
#GNU_OPTIMIZATION_FLAGS += -ffunction-sections
#GNU_OPTIMIZATION_FLAGS += -fdata-sections

#LDFLAGS += -Wl,--gc-sections
LDFLAGS += -lm
LDFLAGS += -pthread

CC   = cc
CXX  = g++
CSTD = -std=c17

OPTIMIZATION_LEVEL = -O3

ARCHITECTURE_FLAGS += -march=native

ADDRESS_SANITIZER_FLAGS += -fsanitize=address -static-libasan -g -fstack-usage

# INFO: -pipe
# Causes the build to use pipes between build stages, not temporary files.

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

all: build_dir server client test_framework

test_framework: build_dir
	$(MAKE) -C ./rosetta-test-framework


# INFO: -p will do nothing if the directory exists and will return code 0.

build_dir:
	@mkdir -p bin/manual-user-testing bin/automatic-user-testing bin/keygen

server: build_dir
	$(CC) $(ROSETTA_SERVER_SRC) -pipe -o $(BIN_DIR)/$(ROSETTA_SERVER_BIN) \
	$(OPTIMIZATION_LEVEL) $(COMPILER_OPTIMIZATION_REPORT) \
	$(LDFLAGS) $(CFLAGS) $(CSTD) $(ARCHITECTURE_FLAGS) $(GNU_OPTIMIZATION_FLAGS)

client: build_dir
	$(CXX) $(ROSETTA_CLIENT_SRC) -pipe -o $(BIN_DIR)/$(ROSETTA_CLIENT_BIN) \
	$(OPTIMIZATION_LEVEL) $(COMPILER_OPTIMIZATION_REPORT) $(CFLAGS) $(LDFLAGS) \
	$(ARCHITECTURE_FLAGS) $(GNU_OPTIMIZATION_FLAGS) $(WX_WIDGETS_SPECIFIC)

server_asan: build_dir
	$(CC) $(ROSETTA_SERVER_SRC) -pipe -o $(BIN_DIR)/$(ROSETTA_SERVER_ASAN_BIN) \
	$(OPTIMIZATION_LEVEL) $(COMPILER_OPTIMIZATION_REPORT) \
	$(LDFLAGS) $(CFLAGS) $(CSTD) $(ARCHITECTURE_FLAGS) \
	$(ADDRESS_SANITIZER_FLAGS)

client_asan: build_dir
	$(CXX) $(ROSETTA_CLIENT_SRC) -pipe -o $(BIN_DIR)/$(ROSETTA_CLIENT_ASAN_BIN) \
	$(OPTIMIZATION_LEVEL) $(COMPILER_OPTIMIZATION_REPORT) $(CFLAGS) $(LDFLAGS) \
	$(ARCHITECTURE_FLAGS) $(ADDRESS_SANITIZER_FLAGS) $(WX_WIDGETS_SPECIFIC)

clean:
	rm -rf $(BIN_DIR)/$(ROSETTA_SERVER_BIN)      && \
	rm -rf $(BIN_DIR)/$(ROSETTA_SERVER_ASAN_BIN) && \
	rm -rf $(BIN_DIR)/$(ROSETTA_CLIENT_BIN)      && \
	rm -rf $(BIN_DIR)/$(ROSETTA_CLIENT_ASAN_BIN)
