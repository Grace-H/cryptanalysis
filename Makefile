#
# Makefile for Project1: Vigenere Cryptanalysis
# Author: Grace Hunter
#
CC = gcc
CFLAGS = -g -Wall -std=gnu99 -lm -O3

all: crypt findkey

crypt: crypt.c tools.o
	$(CC) $(CFLAGS) -o crypt crypt.c tools.o

findkey: findkey.c tools.o
	$(CC) $(CFLAGS) -o findkey findkey.c tools.o

tools.o: tools.c
	$(CC) $(CFLAGS) -c tools.c

clean:
	rm -f *.o
	rm -f crypt
	rm -f findkey
