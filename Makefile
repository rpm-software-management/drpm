CFLAGS=-std=c99 -pedantic -Wall -Wextra -fPIC

all: libdrpm.so

libdrpm.so: drpm.o drpm_read.o drpm_utils.o drpm_compstrm.o
	$(CC) $^ -o $@ -shared -Wl,-soname,libdrpm.so -lz -lbz2 -llzma -lrpm -lrpmio

clean:
	rm -f *.o
