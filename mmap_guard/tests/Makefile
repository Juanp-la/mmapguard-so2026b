# Makefile de los clientes de prueba en espacio de usuario (SO2026B - EAFIT)
CC     ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -g
BINS    = test_access test_readonly bench test_race

.PHONY: all clean
all: $(BINS)

test_access: test_access.c ../kernel/mmapguard_uapi.h
	$(CC) $(CFLAGS) -o $@ test_access.c

test_readonly: test_readonly.c
	$(CC) $(CFLAGS) -o $@ test_readonly.c

bench: bench.c
	$(CC) $(CFLAGS) -o $@ bench.c

test_race: test_race.c
	$(CC) $(CFLAGS) -o $@ test_race.c -lpthread

clean:
	rm -f $(BINS)
