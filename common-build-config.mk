COMMON_CFLAGS += -D_GNU_SOURCE
COMMON_CFLAGS += -Wall
COMMON_CFLAGS += -Wextra
COMMON_CFLAGS += -Werror
COMMON_CFLAGS += -Wcast-align
COMMON_CFLAGS += -Wfloat-equal
COMMON_CFLAGS += -Wformat=2
COMMON_CFLAGS += -Wlogical-op
COMMON_CFLAGS += -Wmissing-include-dirs
COMMON_CFLAGS += -Wpointer-arith
COMMON_CFLAGS += -Wredundant-decls
COMMON_CFLAGS += -Wsequence-point
COMMON_CFLAGS += -Wshadow
COMMON_CFLAGS += -Wswitch
COMMON_CFLAGS += -Wundef
COMMON_CFLAGS += -Wunreachable-code
COMMON_CFLAGS += -Wunused-but-set-parameter
COMMON_CFLAGS += -Wunused
COMMON_CFLAGS += -Wstrict-aliasing
COMMON_CFLAGS += -Wformat-security
COMMON_CFLAGS += -Wno-stringop-truncation
COMMON_CFLAGS += -Wno-unused-label
COMMON_CFLAGS += -Wno-unused-result
COMMON_CFLAGS += -Wno-aggregate-return
#COMMON_CFLAGS += -Wno-write-strings

C_SPECIFIC_CFLAGS += -Wno-discarded-qualifiers

CFLAGS += $(COMMON_CFLAGS)
CFLAGS += $(C_SPECIFIC_CFLAGS)

CXXFLAGS += $(COMMON_CFLAGS)

# Ask GCC to tell us of any vectorization and loop optimizations it performed
# when building the server and client sources.
COMPILER_OPTIMIZATION_REPORT += -fopt-info-vec-optimized
COMPILER_OPTIMIZATION_REPORT += -fopt-info-loop-optimized

# INFO: -pipe
# Causes the build to use pipes between build stages, not temporary files.
EXTRA_FLAGS += -pipe

CC     = gcc
CXX    = g++
CSTD   = -std=c17
CXXSTD = -std=c++20

OPTIMIZATION_LEVEL = -O3
ARCHITECTURE_FLAGS += -march=native


#Some of the following GNU_OPTIMIZATION_FLAGS may not be available outside GCC.

# Use only the stack pointer for managing function-local variables.
# Do not waste an entire register for the unnecessary frame pointer.
# On x86-64, this frees up the rbp register.
# Disabled. Introduced a performance regression. May try in the future.

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
# Disabled. Introduced a performance regression. May try in the future.

#GNU_OPTIMIZATION_FLAGS += -ffunction-sections
#GNU_OPTIMIZATION_FLAGS += -fdata-sections
GNU_OPTIMIZATION_FLAGS +=

#LDFLAGS += -Wl,--gc-sections
LDFLAGS =

LDLIBS += -lm
LDLIBS += -pthread
