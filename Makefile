#
# Makefile for Project1: Vigenere Cryptanalysis
# Author: Grace Hunter
#
CC = gcc
CFLAGS = -g -Wall -Werror -std=gnu99

all: crypt

crypt: crypt.c
	$(CC) $(CFLAGS) -o crypt crypt.c

clean:
	rm -f *.o
	rm -f crypt
