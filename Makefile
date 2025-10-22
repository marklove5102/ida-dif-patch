CC=gcc
CFLAGS=-ggdb -I../grepline -Wall -Wextra -pedantic -std=gnu99
#if you don't like or don't want gcc, feel free to change CC

all: idp

idp:
	$(CC) $(CFLAGS) ../grepline/grepline.c main.c -o idp

beta:
	$(CC) $(CFLAGS) ../grepline/grepline-1.0.2.c main.c -o idp-beta

clean:
	rm -f idp idp-beta
