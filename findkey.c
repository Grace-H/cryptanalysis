/* 
 * Finds key to decrypt Vigenere ciphertext
 *
 * Author: Grace Hunter
 * CSCI 359 - Information Security
 * Wheaton College, IL
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#include "tools.h"

char find_shift(char *ctext, int start, int gap);
int build_freq_table(char *text, double *freq, int start, int gap);

double eng_freq[26] = {
  0.07984, 0.01511, 0.02504, 0.04260, 0.12452,
  0.02262, 0.02013, 0.06384, 0.07000, 0.00131,
  0.00741, 0.03961, 0.02629, 0.06876, 0.07691,
  0.01741, 0.00107, 0.05912, 0.06333, 0.09058,
  0.02844, 0.01056, 0.02304, 0.00159, 0.02028, 0.00057 };

int main(int argc, char **argv){
  char *ctext = calloc(sizeof(char), MAX_LINE_SIZE);

  char* buff = calloc(sizeof(char), 1000);

  while((buff = fgets(buff, MAX_LINE_SIZE, stdin)) != NULL){
    strncat(ctext, buff, strlen(buff));
  }

  int keylen = 0;
  int err = 0; //set if skipping key length
  double r;
  char shift;
  char *key = calloc(sizeof(char), MAX_KEY_SIZE);
  char *ctext_aux = calloc(sizeof(char), MAX_LINE_SIZE);
  //double *freq = calloc(sizeof(double), 26);
  double frequencies[keylen][26];
  do{
    keylen++;
    err = 0;
    if(keylen > MAX_KEY_SIZE){
      fprintf(stdout, "No suitable key found.\n");
      break;
    }

    if(keylen % 10 == 0)
      fprintf(stderr, "Trying key length %d.\n", keylen);

    build_freq_tables(frequencies, ctext, keylen);
    
    int i;
    for(i = 0; i < keylen; i++){
      
      shift = find_shift(frequencies[i]);
      if(isletter(shift)){
	key[i] = shift;
	//	fprintf(stderr, "%c", shift);
      }else{
	key[i] = 'A';
	fprintf(stderr, "Failed to find good key\n");
	/*      else{
	fprintf(stderr, "Skipping key length: %d\n", keylen);
	err = 1;
	break;*/
      }
    }
    if(!err){
      fprintf(stderr, "found key %s\n", key);
      
      strncpy(ctext_aux, ctext, strlen(ctext));
      

      //      fprintf(stderr, "ctext_aux %s\n", ctext_aux);
      ctext_aux = decipher(ctext_aux, key);

      
      // fprintf(stderr, "deciphered %s\n", ctext_aux);
      build_freq_table(ctext_aux, freq, 0, 1);
      /*    for(i = 0; i < 26; i++){
	    fprintf(stderr, "%lf, ", freq[i]);
	    }
      */
      //      fprintf(stderr, "built freq table");
      
      r = correlation(freq, eng_freq, 26);
      //fprintf(stderr, "got correlation\n");
      fprintf(stderr, "key correlation: %lf\n", fabs(r));
    }    
  } while(fabs(r) < 0.72);
  if(keylen <= 1000)
    fprintf(stdout, "%s\n", key);

  free(ctext);
  free(buff);
  free(freq);
  return 0;
}

//build letter frequency tables for given text with a given keylen
int build_freq_tables(double **table, char *text, int keylen){
  int i, j;
  //clear table
  for(i = 0; i < keylen; i++){
    for(j = 0; j < 26; j++){
      table[i][j] = 0;
    }
  }
  //populate table
  int count = 0;
  for(i = 0; i < strlen(text); i++){
    if(isletter(text[i])){
      table[count++ % keylen][toupper(text[i]) - 'A']++;
    }
  }
}

//build a letter frequency table for given text
//begin counting at start, and only count letters spaced by gap
int build_freq_table(char *text, double *table, int start, int gap){

  int i, count = 0;
  for(i = 0; i < 26; i++) table[i] = 0;
  for(i = start; i < strlen(text); i += gap){
    fprintf(stderr, "text[%d]: %c\n", i, text[i]);
    if(isletter(text[i])) {
      //fprintf(stderr, "%c -> %d\n", text[i], toupper(text[i] - 65));
      table[toupper(text[i]) - 65]++;
      count++;
    }
  }
  /*
  for(i = 0; i < 26; i++){
    fprintf(stderr, "%c: %lf\n", i + 65, table[i]);
    }*/
  if(count != 0)
    for(i = 0; i < 26; i++) table[i] /= count;

  return 0;
}

//find the shift for a set of letters gap distance apart in the ctext, 
//using a letter frequency table, gap is the length of the key
//returns 0 if no shift with r > 0.8 is found
char find_shift(char *ctext, int start, int gap){

  //build frequency table for ctext
  double *freq = calloc(sizeof(double), 26);
  build_freq_table(ctext, freq, start, gap);
  
  double freq_aux[26];
  double r;
  double best_r = 0;
  int best_shift = 0;
  int i, shift = -1;
  do {
    shift++;
    //fprintf(stderr, "shift: %d\n", shift);
    //if(shift > 25) return 0;
    for(i = 0; i < 26; i++){
      freq_aux[(i - shift) >= 0 ? (i - shift) : (i - shift + 26)] = freq[i];
    }
    /*
    for(i = 0; i < 26; i++){
      fprintf(stderr, "%lf, ", freq_aux[i]);
      }*/
    //fprintf(stderr, "\n");
    r = correlation(freq_aux, eng_freq, 26);
    if(fabs(r) > best_r){
      best_r = fabs(r);
      best_shift = shift;
    }
  
  } while(shift < 25);
  fprintf(stderr, "best_r: %lf at %d\n", best_r, best_shift);
  return 'A' + best_shift;
}
