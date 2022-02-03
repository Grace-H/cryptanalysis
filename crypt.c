/* crypt.c
 * Encrypts and decrypts text using Vigenere cypher
 *
 * author: Grace Hunter
 * csci359 - Information Security
 * Wheaton College, IL
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char shift_char(char c, char shift);
char backshift_char(char c, char shift);

void main(int argc, char argv[]){
  if(!strcmp(argv[0], "-d")){
    printf("decrypting %s\n", argv[1]);
  }
  else{
    printf("encrypting %s\n", argv[0]);
}
