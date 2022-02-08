/*
 * tools.h - prototypes for cryptanalysis project
 */

#ifndef TOOLS_H
#define TOOLS_H

#define MAX_LINE_SIZE 300000
#define MAX_KEY_SIZE 1000
//calculate mean of the dataset
double mean(int *data, int n);

//calculate the standard deviation of the dataset
//parameters: data (the dataset), mean (mean of dataset), n (length)
double std_deviation(int *data, double mean, int n);

//calculate correlation coefficient, r, for 2 datasets of length n
double correlation(int *x, int *y, int n);

//return nonzero if c is in the range a-z or A-Z
int isletter(char c);

//shift char forward by shift given
char shift_char(char c, char shift);

//shift char backward by shift given
char backshift_char(char c, char shift);

//decipher ciphertext in buff using key
char *decipher(char *buff, char *key);

//encipher plaintext in buff using key
char *encipher(char *buff, char *key);

#endif
