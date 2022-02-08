/*
 * Tools & other useful helper functions for cryptanalysis project
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

double mean(int *data, int n){
  int sum = 0;
  int i;
  for(i = 0; i < n; i++) sum += data[i];
  return sum / n;
}

double std_deviation(int *data, double mean, int n){
  double sum = 0;
  int i;
  for(i = 0; i < n; i++) sum += pow(data[i] - mean, 2);
  return sqrt(sum / (n - 1));
}

double correlation(int *x, int *y, int n){
  double meanx = mean(x, n), meany = mean(y, n);
  double sx = std_deviation(x, meanx, n), sy = std_deviation(y, meany, n);
  double zx, zy, sum = 0;
  int i;
  for(i = 0; i < n; i++){
    zx = (x[i] - meanx) / sx;
    zy = (y[i] - meany) / sy;
    sum += zx * zy;
  }
  return sum / (n - 1);
}

int isletter(char c){
  return (64 < c && c < 91 ) || (96 < c && c < 123);
}

char shift_char(char c, char shift){
  char c_prime = (int)toupper(c) + (int)tolower(shift) - 97;
  return c_prime > 90 ? c_prime - 26 : c_prime;
}

char backshift_char(char c, char shift){
  char c_prime = (int)toupper(c) - (int)tolower(shift) + 97;
  return c_prime < 65 ? c_prime + 26 : c_prime;
}

char *decipher(char *buff, char *key){
  int shifts = 0; //number of shifts completed
  int key_size = strlen(key);
  
  //  fprintf(stderr, "strlen(key) = %d\n", key_size);
  int i;          //index in buff
  for(i = 0; i < strlen(buff); i++){
    if(isletter(buff[i])){
      buff[i] = backshift_char(toupper(buff[i]), key[shifts % key_size]);
      shifts++;
    }
  }
  //  fprintf(stderr, "finished decrypting");
  return buff;
}

char *encipher(char *buff, char *key){
  int shifts = 0; //number of shifts completed
  int key_size = strlen(key);
  int i;          //index in buff
  for(i = 0; i < strlen(buff); i++){
    if(isletter(buff[i])){
      buff[i] = shift_char(toupper(buff[i]), key[shifts++ % key_size]);
    }
  }
  return buff;
}
