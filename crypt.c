/* crypt.c
 * Enciphers and deciphers text using Vigenere cypher
 * 
 * author: Grace Hunter
 * csci359 - Information Security
 * Wheaton College, IL
 * 
 * Date: 07 February 2022
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "tools.h"

int main(int argc, char** argv){
  //receive text
  char *ctext = calloc(sizeof(char), MAX_LINE_SIZE);
  char *buff = calloc(sizeof(char), 1000);
  //reads until NULL/^D received
  while((buff = fgets(buff, MAX_LINE_SIZE, stdin)) != NULL){
    strncat(ctext, buff, strlen(buff));
  }

  //decipher
  if(!strcmp(argv[1], "-d")){
    fprintf(stdout, "%s", decipher(ctext, argv[2]));
  }
  //encrypt
  else{
    fprintf(stdout, "%s", encipher(ctext, argv[1]));
  }

  free(ctext);
  free(buff);
  return 0;
}
