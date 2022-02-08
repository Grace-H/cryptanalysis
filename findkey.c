/* 
 * Finds key to decrypt Caesar & Vigenere ciphertext
 * Note: does not work on Vigenere Challege, hard took roughly 7" on my machine
 *
 * Author: Grace Hunter
 * CSCI 359 - Information Security
 * Wheaton College, IL
 * 
 * Date: 07 February 2022
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#include "tools.h"

char find_shift(int *freq);
int build_freq_table(char *text, int *freq);
int build_freq_tables(int **table, char *text, int keylen);

//frequency table of letters in English
int eng_freq[26] = {
  7984, 1511, 2504, 4260, 12452,
  2262, 2013, 6384, 7000, 131,
  741, 3961, 2629, 6876, 7691,
  1741, 107, 5912, 6333, 9058,
  2844, 1056, 2304, 159, 2028, 57 };

int main(int argc, char **argv){

  /* ---- retrieve text ---- */
  char *ctext = calloc(sizeof(char), MAX_LINE_SIZE);
  char* buff = calloc(sizeof(char), 1000);

  while((buff = fgets(buff, MAX_LINE_SIZE, stdin)) != NULL){
    strncat(ctext, buff, strlen(buff));
  }

  /* ---- cryptanalysis ---- */
  int keylen = 0;
  int err = 0; //set if skipping key length
  double r;
  char shift;
  char *key = calloc(sizeof(char), MAX_KEY_SIZE);
  char *ctext_aux = calloc(sizeof(char), MAX_LINE_SIZE);
  int *freq = calloc(sizeof(int), 26);
  int **frequencies;
  
  //allocate frequencies tables
  frequencies = malloc(sizeof(int *) * MAX_KEY_SIZE);
  int i;
  for(i = 0; i < MAX_KEY_SIZE; i++){
    frequencies[i] = malloc(sizeof(int) * 26);
  }

  //try a key size
  do{
    keylen++;
    err = 0;
    
    if(keylen > MAX_KEY_SIZE){
      fprintf(stdout, "No suitable key found.\n");
      break;
    }

    if(keylen % 20 == 0)
      fprintf(stderr, "Trying key length %d.\n", keylen);

    //build letter frequency tables for given key size
    build_freq_tables(frequencies, ctext, keylen);

    //find the best shift for each place in key
    //skip key lengths that for which one letter does not have a good shift
    for(i = 0; i < keylen; i++){
      shift = find_shift(frequencies[i]);
      if(isletter(shift)){
	key[i] = shift;
      }
      else{
	err = 1;
	break;
      }
    }
    
    if(!err){
      strncpy(ctext_aux, ctext, strlen(ctext));
      ctext_aux = decipher(ctext_aux, key);
      build_freq_table(ctext_aux, freq);
      r = fabs(correlation(freq, eng_freq, 26));
    }
    //if a decent caesar shift is found, return
    //otherwise look for a longer, better key
  } while((keylen == 1 && r < 0.85) || (keylen > 1 && r < 0.93));

  //print key
  if(keylen <= MAX_KEY_SIZE)
     fprintf(stdout, "%s\n", key);

  return 0;
}

//build letter frequency tables for given text with a given keylen
int build_freq_tables(int **table, char *text, int keylen){
  int i, j;
  //clear table
  for(i = 0; i < keylen; i++){
    for(j = 0; j < 26; j++){
      table[i][j] = 0;
    }
  }
  //populate table
  int index = 0;
  int counts[keylen];
  for(i = 0; i < keylen; i++){
    counts[i] = 0;
  }
  for(i = 0; i < strlen(text); i++){
    if(isletter(text[i])){
      table[index % keylen][toupper(text[i]) - 'A']++;
      counts[index % keylen]++;
      index++;
    }
  }
  
  return 0;
}

//build a letter frequency table for given text
//begin counting at start, and only count letters spaced by gap
int build_freq_table(char *text, int *table){
  int i, count = 0;
  for(i = 0; i < 26; i++) table[i] = 0;
  for(i = 0; i < strlen(text); i++){
    if(isletter(text[i])) {
      table[toupper(text[i]) - 'A']++;
      count++;
    }
  }
  return 0;
}

//find the shift for a letter frequency table
//returns best shift found
char find_shift(int *freq){
  int freq_aux[26];
  double r;
  double best_r = 0;
  int best_shift = 0;
  int i, shift = -1;
  do {
    shift++;

    for(i = 0; i < 26; i++){
      freq_aux[(i - shift) >= 0 ? (i - shift) : (i - shift + 26)] = freq[i];
    }

    r = fabs(correlation(freq_aux, eng_freq, 26));
    if(r > best_r){
      best_r = r;
      best_shift = shift;
    }
  } while(shift < 25);
  
  if(best_r < 0.6) return 0;
  return 'A' + best_shift;
}
