/* crypt.c
 * Enciphers and deciphers text using Vigenere cypher
 *
 * author: Grace Hunter
 * csci359 - Information Security
 * Wheaton College, IL
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_LINE_SIZE 10000000

char shift_char(char c, char shift);
char backshift_char(char c, char shift);
int decipher(char *buff, char *key);
int encipher(char *buff, char *key);

int main(int argc, char** argv){
  
  char* buff = calloc(sizeof(char), MAX_LINE_SIZE);

  fgets(buff, MAX_LINE_SIZE, stdin);

  //decipher
  if(!strcmp(argv[1], "-d")){
    decipher(buff, argv[2]);
  }
  //encrypt
  else{
    encipher(buff, argv[1]);
  }
  
  printf("%s", buff);
  free(buff);
  return 0;
}

char shift_char(char c, char shift){
  char c_prime = (int)c + (int)shift - 97;
  return c_prime > 90 ? c_prime - 26 : c_prime;
}

char backshift_char(char c, char shift){
  char c_prime = (int)c - (int)shift + 97;
  return c_prime < 65 ? c_prime + 26 : c_prime;
}

int decipher(char *buff, char *key){
  int shifts = 0; //number of shifts completed
  int key_size = strlen(key);
  int i;          //index in buff
  for(i = 0; i < strlen(buff); i++){
    if(isalpha(buff[i])){
      buff[i] = backshift_char(toupper(buff[i]), key[shifts++ % key_size]);
    }
  }
  return 0;
}

int encipher(char *buff, char *key){
  int shifts = 0; //number of shifts completed
  int key_size = strlen(key);
  int i;          //index in buff
  for(i = 0; i < strlen(buff); i++){
    if(isalpha(buff[i])){
      buff[i] = shift_char(toupper(buff[i]), key[shifts++ % key_size]);
    }
  }
  return 0;
}

