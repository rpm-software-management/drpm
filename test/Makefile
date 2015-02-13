CFLAGS=-std=c99 -pedantic -Wall -Wextra -g
LDFLAGS=-ldrpm

all: drpm_test

drpm_test: drpm_test.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
