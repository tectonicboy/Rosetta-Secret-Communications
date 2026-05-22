# -*- MakeFile -*-

# INTENDED TO BE CALLED BY THE PRIMARY PROJECT MAKEFILE IN THE TOP-LEVEL DIR.
# IN A SEPARATE MAKEFILE HERE FOR READABILITY AND MODULARITY.
#
# MAKEFILE ENTRIES COMMON TO ALL 3 PROJECT MAKEFILES ARE IN config.mk

include ../config.mk

PRIMARY_TARGETS += test_framework
PRIMARY_TARGETS += manual_user_spawner
PRIMARY_TARGETS += auto_user_simulation_test_1
PRIMARY_TARGETS += simulation_1_auto_user_spawner_1
PRIMARY_TARGETS += simulation_1_auto_user_spawner_2
PRIMARY_TARGETS += simulation_1_auto_user_spawner_3

.PHONY: all clean $(PRIMARY_TARGETS)

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

all: $(PRIMARY_TARGETS)

test_framework:
	$(CC) $(ROSETTA_TEST_FRAMEWORK_SRC) \
	-o $(BIN_DIR)/$(ROSETTA_TEST_FRAMEWORK_BIN) \
	$(COMPILER_OPTIMIZATION_REPORT) $(GNU_OPTIMIZATION_FLAGS) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) $(CSTD) \
	$(EXTRA_FLAGS) $(LDFLAGS) $(LDLIBS)

manual_user_spawner:
	$(CC) $(MANUAL_USER_SPAWNER_SRC) \
	-o $(BIN_DIR)/$(MANUAL_USER_SPAWNER_BIN) \
	$(GNU_OPTIMIZATION_FLAGS) $(CSTD) $(EXTRA_FLAGS) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) \
	$(LDFLAGS) $(LDLIBS)

auto_user_simulation_test_1:
	$(CC) $(USER_SIMULATION_TEST_1_SRC) \
	-o $(BIN_DIR)/$(USER_SIMULATION_TEST_1_BIN) \
	$(GNU_OPTIMIZATION_FLAGS) $(CSTD) $(EXTRA_FLAGS) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) \
	$(LDFLAGS) $(LDLIBS)

simulation_1_auto_user_spawner_1:
	$(CC) $(SIMULATION_1_SPAWNER_1_SRC) \
	-o $(BIN_DIR)/$(SIMULATION_1_SPAWNER_1_BIN) \
	$(GNU_OPTIMIZATION_FLAGS) $(CSTD) $(EXTRA_FLAGS) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) \
	$(LDFLAGS) $(LDLIBS)

simulation_1_auto_user_spawner_2:
	$(CC) $(SIMULATION_1_SPAWNER_2_SRC) \
	-o $(BIN_DIR)/$(SIMULATION_1_SPAWNER_2_BIN) \
	$(GNU_OPTIMIZATION_FLAGS) $(CSTD) $(EXTRA_FLAGS) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) \
	$(LDFLAGS) $(LDLIBS)

simulation_1_auto_user_spawner_3:
	$(CC) $(SIMULATION_1_SPAWNER_3_SRC) \
	-o $(BIN_DIR)/$(SIMULATION_1_SPAWNER_3_BIN) \
	$(GNU_OPTIMIZATION_FLAGS) $(CSTD) $(EXTRA_FLAGS) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) \
	$(LDFLAGS) $(LDLIBS)

clean:
	rm -rf $(BIN_DIR)/$(ROSETTA_TEST_FRAMEWORK_BIN) && \
	rm -rf $(BIN_DIR)/$(MANUAL_USER_SPAWNER_BIN)    && \
	rm -rf $(BIN_DIR)/$(USER_SIMULATION_TEST_1_BIN) && \
	rm -rf $(BIN_DIR)/$(SIMULATION_1_SPAWNER_1_BIN) && \
	rm -rf $(BIN_DIR)/$(SIMULATION_1_SPAWNER_2_BIN) && \
	rm -rf $(BIN_DIR)/$(SIMULATION_1_SPAWNER_3_BIN)
