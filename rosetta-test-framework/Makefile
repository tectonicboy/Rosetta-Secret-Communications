# -*- MakeFile -*-

# INTENDED TO BE CALLED BY THE PRIMARY PROJECT MAKEFILE IN THE TOP-LEVEL DIR.
# IN A SEPARATE MAKEFILE HERE FOR READABILITY AND MODULARITY.

.PHONY: all clean

CFLAGS += -Wall
CFLAGS += -Wextra
CFLAGS += -Waggregate-return
CFLAGS += -Wcast-align
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
CFLAGS += -Wwrite-strings
CFLAGS += -Wno-unused-label
CFLAGS += -Wno-unused-result
CFLAGS += -Wstrict-aliasing
CFLAGS += -Wformat-security
CFLAGS += -Wno-stringop-truncation
CFLAGS += -Wno-cast-qual
CFLAGS += -Wno-discarded-qualifiers

# Some of these may not be available outside GCC.

# Use the stack pointer only for managing function-local storage.
# Do not waste an entire register for the unnecessary frame pointer.
# On x86-64, this frees up the rbp register.
GNU_OPTIMIZATION_FLAGS += -fomit-frame-pointer

#INFO: To check the segment sizes (like .data, .text) of an ELF binary:
#      size my_file

# Eliminate the code for functions that are never called.
# This includes inlined functions which the compiler emitted a non-inlined
# copy of, just in case an unpredictable external call to them happened.
# With this option turned on, we let the linker remove such functions.
# The data-sections ones does the same but for unused globals.
# LDFLAGS += -Wl,--gc-sections is required to instruct the linker to
# perform the actual removal.
GNU_OPTIMIZATION_FLAGS += -ffunction-sections
GNU_OPTIMIZATION_FLAGS += -fdata-sections

LDFLAGS += -Wl,--gc-sections
LDFLAGS += -pthread
LDFLAGS += -lm
CC = cc
OPTIMIZATION_LEVEL = -O3
ARCHITECTURE_FLAGS = -march=native

# INFO: -pipe
# Causes the build process to use pipes between build stages, not temp. files.

# Ask GCC to tell us of any vectorization and loop optimizations it performed.
COMPILER_OPTIMIZATION_REPORT += -fopt-info-vec-optimized
COMPILER_OPTIMIZATION_REPORT += -fopt-info-loop-optimized

BIN_DIR                    = ../bin
ROSETTA_TEST_FRAMEWORK_SRC = rosetta-test-framework.c
ROSETTA_TEST_FRAMEWORK_BIN = rosetta-test-framework
MANUAL_USER_SPAWNER_SRC    = manual-user-testing/manual-user-spawner.c
MANUAL_USER_SPAWNER_BIN    = manual-user-testing/manual-user-spawner
USER_SIMULATION_TEST_1_SRC = automatic-user-testing/auto-simulated-user-test-1.c
USER_SIMULATION_TEST_1_BIN = automatic-user-testing/auto-simulated-user-test-1
SIMULATION_1_SPAWNER_1_SRC = automatic-user-testing/auto-spawner1.c
SIMULATION_1_SPAWNER_1_BIN = automatic-user-testing/auto-spawner1
SIMULATION_1_SPAWNER_2_SRC = automatic-user-testing/auto-spawner2.c
SIMULATION_1_SPAWNER_2_BIN = automatic-user-testing/auto-spawner2
SIMULATION_1_SPAWNER_3_SRC = automatic-user-testing/auto-spawner3.c
SIMULATION_1_SPAWNER_3_BIN = automatic-user-testing/auto-spawner3

all:
	$(CC) $(ROSETTA_TEST_FRAMEWORK_SRC) \
	-o $(BIN_DIR)/$(ROSETTA_TEST_FRAMEWORK_BIN) \
	$(COMPILER_OPTIMIZATION_REPORT) $(GNU_OPTIMIZATION_FLAGS) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) $(LDFLAGS) \
	&& \
	$(CC) $(MANUAL_USER_SPAWNER_SRC) \
	-o $(BIN_DIR)/$(MANUAL_USER_SPAWNER_BIN) $(GNU_OPTIMIZATION_FLAGS) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) $(LDFLAGS) \
	&& \
	$(CC) $(USER_SIMULATION_TEST_1_SRC) \
	-o $(BIN_DIR)/$(USER_SIMULATION_TEST_1_BIN) $(GNU_OPTIMIZATION_FLAGS) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) $(LDFLAGS) \
	&& \
	$(CC) $(SIMULATION_1_SPAWNER_1_SRC) \
	-o $(BIN_DIR)/$(SIMULATION_1_SPAWNER_1_BIN)  $(GNU_OPTIMIZATION_FLAGS) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) $(LDFLAGS) \
	&& \
	$(CC) $(SIMULATION_1_SPAWNER_2_SRC) \
	-o $(BIN_DIR)/$(SIMULATION_1_SPAWNER_2_BIN) $(GNU_OPTIMIZATION_FLAGS) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) $(LDFLAGS) \
	&& \
	$(CC) $(SIMULATION_1_SPAWNER_3_SRC) \
	-o $(BIN_DIR)/$(SIMULATION_1_SPAWNER_3_BIN) $(GNU_OPTIMIZATION_FLAGS) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) $(LDFLAGS)

clean:
	rm -rf $(BIN_DIR)/$(ROSETTA_TEST_FRAMEWORK_BIN) && \
	rm -rf $(BIN_DIR)/$(MANUAL_USER_SPAWNER_BIN)    && \
	rm -rf $(BIN_DIR)/$(USER_SIMULATION_TEST_1_BIN) && \
	rm -rf $(BIN_DIR)/$(SIMULATION_1_SPAWNER_1_BIN) && \
	rm -rf $(BIN_DIR)/$(SIMULATION_1_SPAWNER_2_BIN) && \
	rm -rf $(BIN_DIR)/$(SIMULATION_1_SPAWNER_3_BIN)
