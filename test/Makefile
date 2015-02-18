CFLAGS=-std=c99 -pedantic -Wall -Wextra -g

all: drpm_test

drpm_test: drpm_test.c
	$(CC) $(CFLAGS) $^ -o $@ `pkg-config --cflags --libs drpm`
