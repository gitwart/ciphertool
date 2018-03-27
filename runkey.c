#include <stdio.h>
#include "languages.h"
#include "trigram.h"

int
main(int argc, char **argv)
{
    char *ct;
    char pt[8];
    char key[8];
    char maxPt[8];
    char maxKey[8];
    long  maxVal=0;
    int  i;

    if (argc != 2) {
	fprintf(stderr, "Usage:  %s ct\n", argv[0]);
	exit(1);
    }
    if (strlen(argv[1]) != 7) {
	fprintf(stderr, "ciphertext must be 7 letters long\n");
	exit(1);
    }

    ct = argv[1];

    for(i=0; i < 7; i++) {
	pt[i] = ' ';
	key[i] = ' ';
	maxKey[i] = ' ';
	maxPt[i] = ' ';
    }
    pt[i] = (char)NULL;
    key[i] = (char)NULL;
    maxPt[i] = (char)NULL;
    maxKey[i] = (char)NULL;

    for(pt[0]='a'; pt[0] <= 'z'; pt[0]++) {
	// Vigenere
	//key[0] = (ct[0] - pt[0] + 26)%26+'a';
	// Variant
	key[0] = (pt[0] - ct[0] + 26)%26+'a';
    for(pt[1]='a'; pt[1] <= 'z'; pt[1]++) {
	fprintf(stdout, "%c%c....\n", pt[0], pt[1]);
	fflush(stdout);
	// Vigenere
	key[1] = (ct[1] - pt[1] + 26)%26+'a';
	// Variant
	//key[1] = (ct[1] - pt[1] + 26)%26+'a';
    for(pt[2]='a'; pt[2] <= 'z'; pt[2]++) {
	// Vigenere
	key[2] = (ct[2] - pt[2] + 26)%26+'a';
	// Variant
	//key[2] = (pt[2] - ct[2] + 26)%26+'a';
    for(pt[3]='a'; pt[3] <= 'z'; pt[3]++) {
	// Vigenere
	key[3] = (ct[3] - pt[3] + 26)%26+'a';
	// Variant
	//key[3] = (pt[3] - ct[3] + 26)%26+'a';
    for(pt[4]='a'; pt[4] <= 'z'; pt[4]++) {
	// Vigenere
	key[4] = (ct[4] - pt[4] + 26)%26+'a';
	// Variant
	//key[4] = (pt[4] - ct[4] + 26)%26+'a';
    for(pt[5]='a'; pt[5] <= 'z'; pt[5]++) {
	// Vigenere
	key[5] = (ct[5] - pt[5] + 26)%26+'a';
	// Variant
	//key[5] = (pt[5] - ct[5] + 26)%26+'a';
    for(pt[6]='a'; pt[6] <= 'z'; pt[6]++) {
	long val;
	// Vigenere
	key[6] = (ct[6] - pt[6] + 26)%26+'a';
	// Variant
	//key[6] = (pt[6] - ct[6] + 26)%26+'a';

	val = get_trigram_string_value(key, ENGLISH_ALPHABET)
	    * get_trigram_string_value(pt, ENGLISH_ALPHABET);

	if (val > maxVal) {
	    maxVal = val;
	    strcpy(maxPt, pt);
	    strcpy(maxKey, key);

	    fprintf(stdout, "%ld:\t%s %s\n", val, key, pt);
	    fflush(stdout);
	}
    }
    }
    }
    }
    }
    }
    }

    fprintf(stdout, "Solution:  %ld\n", maxVal);
    fprintf(stdout, "\t%s\n\t%s\n\t%s\n", key, pt, ct);
}
