all: tcprdr
CC=gcc
CFLAGS=-W -Wall -pedantic -std=gnu99

tcprdr: tcprdr.c
	$(CC) $(CFLAGS) tcprdr.c -o tcprdr

clean:
	rm -f tcprdr
