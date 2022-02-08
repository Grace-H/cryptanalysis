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

char find_shift(int *freq);
int build_freq_table(char *text, int *freq);
int build_freq_tables(int **table, char *text, int keylen);

int eng_freq[26] = {
  7984, 1511, 2504, 4260, 12452,
  2262, 2013, 6384, 7000, 131,
  741, 3961, 2629, 6876, 7691,
  1741, 107, 5912, 6333, 9058,
  2844, 1056, 2304, 159, 2028, 57 };

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
  int *freq = calloc(sizeof(int), 26);
  int **frequencies;
  
  
  frequencies = malloc(sizeof(int *) * MAX_KEY_SIZE);
  int i;
  for(i = 0; i < MAX_KEY_SIZE; i++){
    frequencies[i] = malloc(sizeof(int) * 26);
  }
  
  do{
    keylen++;
    err = 0;
    if(keylen > MAX_KEY_SIZE){
      fprintf(stdout, "No suitable key found.\n");
      break;
    }

    if(keylen % 20 == 0)
      fprintf(stderr, "Trying key length %d.\n", keylen);
   
    build_freq_tables(frequencies, ctext, keylen);
    
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
      //printf("C\n");

      //      fprintf(stderr, "ctext_aux %s\n", ctext_aux);
      ctext_aux = decipher(ctext_aux, key);

      // fprintf(stderr, "deciphered %s\n", ctext_aux);
      build_freq_table(ctext_aux, freq);
      /*    for(i = 0; i < 26; i++){
	    fprintf(stderr, "%lf, ", freq[i]);
	    }
      */
      //      fprintf(stderr, "built freq table");
      
      r = fabs(correlation(freq, eng_freq, 26));
      //fprintf(stderr, "got correlation\n");
      //fprintf(stderr, "key correlation: %lf\n", r);
    }
    /*
    for(i = 0; i < keylen; i++){
      free(frequencies[i]);
    }
    free(frequencies);*/
  } while((keylen == 1 && r < 0.85) || (keylen > 1 && r < 0.93));
  if(keylen <= MAX_KEY_SIZE)
     fprintf(stdout, "%s\n", key);
  /*
  free(ctext);
  free(buff);
  free(freq);
  */
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

  //divide by count for each row
  /*for(i = 0; i < keylen; i++){
    if(counts[i] != 0){
      for(j = 0; j < 26; j++){
       
	table[i][j] /= counts[i];
      }
    }
    }*/
  /*
  for(i = 0; i < keylen; i++){
    for(j = 0; j < 26; j++){
      fprintf(stderr, "[%d][%d]%lf, ", i, j, table[i][j]);
    }
    fprintf(stderr, "\n");
    }*/
  //  fprintf(stderr, "finished building tables.\n");
  
  return 0;
}

//build a letter frequency table for given text
//begin counting at start, and only count letters spaced by gap
int build_freq_table(char *text, int *table){

  int i, count = 0;
  for(i = 0; i < 26; i++) table[i] = 0;
  for(i = 0; i < strlen(text); i++){
    //    fprintf(stderr, "text[%d]: %c\n", i, text[i]);
    if(isletter(text[i])) {
      //fprintf(stderr, "%c -> %d\n", text[i], toupper(text[i] - 65));
      table[toupper(text[i]) - 'A']++;
      count++;
    }
  }
  /*
  for(i = 0; i < 26; i++){
    fprintf(stderr, "%c: %lf\n", i + 65, table[i]);
    }*//*
  if(count != 0)
    for(i = 0; i < 26; i++) table[i] /= count;
       */
  return 0;
}

//find the shift for a letter frequency table
//returns best shift found
char find_shift(int *freq){
  //printf("find_shift\n");
  //build frequency table for ctext
  //  double *freq = calloc(sizeof(double), 26);
  //build_freq_table(ctext, freq, start, gap);
  
  int freq_aux[26];
  double r;
  double best_r = 0;
  int best_shift = 0;
  int i, shift = -1;
  do {
    shift++;
    //fprintf(stderr, "shift: %d\n", shift);
    //if(shift > 25) return 0;
    //    printf("BA\n");
    for(i = 0; i < 26; i++){
      freq_aux[(i - shift) >= 0 ? (i - shift) : (i - shift + 26)] = freq[i];
    }

    /*
    for(i = 0; i < 26; i++){
      fprintf(stderr, "%lf, ", freq_aux[i]);
      }*/
    //fprintf(stderr, "\n");
    r = fabs(correlation(freq_aux, eng_freq, 26));
    if(r > best_r){
      best_r = r;
      best_shift = shift;
    }
    //    printf("BB\n");
  } while(shift < 25);
  //  fprintf(stderr, "best_r: %lf at %d\n", best_r, best_shift);
  if(best_r < 0.6) return 0;
  return 'A' + best_shift;
}
