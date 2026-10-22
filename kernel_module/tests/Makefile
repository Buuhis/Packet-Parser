CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Werror -std=gnu11
CPPFLAGS += -I../src -I../include

.PHONY: check clean
check: weight_policy_test
	./weight_policy_test
	python3 routing_policy_test.py

weight_policy_test: weight_policy_test.c ../src/config/config_semantics.c ../kernel/per_packet/mwan_weighted_rr.h
	$(CC) $(CPPFLAGS) $(CFLAGS) weight_policy_test.c ../src/config/config_semantics.c -o $@

clean:
	$(RM) weight_policy_test
