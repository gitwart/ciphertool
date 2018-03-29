/*
 * solver.c --
 *
 *	This file implements an automatic solver for aristocrat ciphers.
 *	The program uses a brute force pattern word search.
 *
 * Copyright (c) 1993-2000 Michael Thomas <wart@kobold.org>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

/* This program will solve cryptograms using the database of words
** in DICT_DIR.
**
** NOTE:  The dictionary must be formatted in a specific way.  The words
** be separated into different files based on length.  One letter words
** would go in "len01", 11-letter words in "len11", etc.  Each line in
** the file should contain a word.  This is so that the program doesn't 
** have to read in the entire (potentially huge) dictionary; only the word 
** lengths appearing in the cipher need be read in.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <solver.h>

#define DICT_DIR   "/home/wart/share/dict"

/* Global variables */

FILE *ofptr;
Word wordlist[MAXWORDS];
Key keylist[MAXKEYS];
char cipher[MAXCIPHERLENGTH];
char plaintext[MAXCIPHERLENGTH];
char *common_words[MAX_COMMON_WORDS];
int lines_in_cipher = 0, lhist[26], num_ulets=0;
int num_words, num_keys=0, vflag=FALSE, Dflag = FALSE, rflag = FALSE;
int threshhold=0, vlevel=0;
int min_badwords=1, num_common_words=0;
void locate_keyword(char *word);
char temp_word[MAXLENGTH];
char *outputFilename = "-";
int update_dictionary = FALSE;

int
main(int argc, char **argv)
{
    FILE *fptr, *dfptr;
    Word *tword;
    char filename[MAXLENGTH];
    int i, j;
    int aflag, pflag, dflag, qflag, sflag, kflag;
    int pword_index = 0;
    Key key;

    aflag = pflag = dflag = qflag = sflag = kflag = FALSE;

    threshhold = DEF_THRESH;

    /* Make sure that we have a dictionary.
    */
    get_dfname("test", filename);
    dfptr = fopen(filename, "r");
    if(dfptr == NULL){
	printf("I'm sorry, but I can't find the dictionary.  Please\n");
	printf("check that it is online and in the proper location:\n");
	printf("%s\n", DICT_DIR);
	exit(0);
    }
	
    *filename = '\0';

    /* Deal with the arguments.
    */

    ++argv, --argc;
    while(argc){
	if(**argv != '-'){
	    printf("Unknown option %s\n", *argv);
	    exit(1);
	}
	else{
	    switch(*++*argv){
		/* Set the threshhold for the number of "bad" words allowed.
		*/
		case 't':
		    ++argv, --argc;
		    strcpy(temp_word, *argv);
		    --argc, ++argv;
		    sscanf(temp_word, "%d", &threshhold);
		    break;
		/* What file is the cipher being held captive in?
		*/
		case 'f':
		    ++argv, --argc;
		    strcpy(filename, *argv);
		    ++argv, --argc;
		    break;
		/* Show the depth of the recursion during the solving.  This has
		** only been handy for determing effective sorting criteria.
		*/
		case 'D':
		    ++argv, --argc;
		    Dflag = TRUE;
		    break;
		/* Don't solve, just check if the word is in the dictionary.
		*/
		case 'q':
		    ++argv, --argc;
		    query_word(*argv);
		    ++argv, --argc;
		    qflag = TRUE;
		    break;
		/* Add the word to the dictionary
		*/
		case 'a':
		    ++argv, --argc;
		    add_word(*argv);
		    ++argv, --argc;
		    aflag = TRUE;
		    break;
		/* Show statistics of the cipher.  word order, number of
		** dictionary matches, etc.
		*/
		case 's':
		    ++argv, --argc;
		    sflag = TRUE;
		    break;
		/* Verbose flag.  This way you can see how quickly it is solving
		** the cipher.
		*/
		case 'v':
		    ++argv, --argc;
		    if (argc <= 0) {
			fprintf(stderr, "-v flag must be followed by an integer\n");
			exit(1);
		    }
		    strcpy(temp_word, *argv);
		    --argc, ++argv;
		    sscanf(temp_word, "%d", &vlevel);
		    vflag = TRUE;
		    break;
		/* Remove a word from the dictionary
		*/
		case 'd':
		    ++argv, --argc;
		    delete_word(*argv);
		    ++argv, --argc;
		    dflag = TRUE;
		    break;
		/* Print all possible keywords that can be formed from the 
		** string of letters/numbers
		*/
		case 'k':
		    ++argv, --argc;
		    locate_keyword(*argv);
		    ++argv, --argc;
		    kflag = TRUE;
		    break;
		/* Print all dictionary matches to a given word.  Use with the
		** 's' flag to determine the number for that word.
		*/
		case 'r':
		    ++argv, --argc;
		    rflag = TRUE;
		    break;
		    case 'p':
		    ++argv, --argc;
		    strcpy(temp_word, *argv);
		    ++argv, --argc;
		    sscanf(temp_word, "%d", &pword_index);
		    pflag = TRUE;
		    break;
		case 'o':
		    ++argv, --argc;
		    outputFilename = *argv;
		    ++argv, --argc;
		    break;
		case 'u':
		    ++argv, --argc;
		    update_dictionary = TRUE;
		    break;
	    }
	}
    }

    /* Make sure that we have a cipher.
    */
    if(!(*filename)){
	if(!aflag && !dflag && !qflag && !kflag){
	    printf("What file would you like to use? ");
	    scanf("%s", filename);
	}
	else{
	    /* Exit silently...
	    */
	    exit(0);
	}
    }

    /* Remove the output file if it exists.
    */

    if (strcmp(outputFilename, "-") != 0) {
	(void) remove(outputFilename);
    }

    fptr = fopen(filename, "r");
    if(!fptr){
	printf("Bad cipher filename.\n");
	exit(1);
    }

    /*Initialize the variables
    */

    num_words = 0;

    for(i = 0; i < 128; i++){
	key.ct[i] = '\0';
	key.pt[i] = '\0';
	key.hist[i] = 0;
    }

    for(i = 0; i < MAXWORDS; i++){
	tword = wordlist+i;
	tword->word[0] = '\0';
	tword->length = 0;
	tword->mult = 0;
	tword->dict = NULL;
	tword->dictsize = 0;
	tword->hvalue = 0;
	tword->valid = 0;
    }

    /* Read in the cipher as an array of lines.  We'll use this later
    ** on when we print the cipher.
    */

    i = 0;
    while(!feof(fptr)){
	cipher[i++] = (char)fgetc(fptr);
	/*
	 * fgets(cipher[i], MAXLENGTH, fptr);
	 */
    }
    cipher[i-1] = '\0';

    rewind(fptr);

    /* Read in the cipher as an array of word structures.  Ignore words
    ** that are one letter long, and those over the max word length.
    */

    while(!feof(fptr)){
	/* Get the next word in the cipher
	*/

	get_next_word(fptr, temp_word);

	/* If the word isn't in the array, then add it, otherwise increase
	** the multiplicity of the word in the array.
	*/

	if(*temp_word && strlen(temp_word) > 1 && 
	    strlen(temp_word) <= MAXWORDLEN){
	    for(i = 0; 
		i < num_words && (strcmp(temp_word, wordlist[i].word) != 0); 
		i++);

	    if(i == num_words){
		tword = wordlist+num_words;
		strcpy(tword->word, temp_word);
		tword->mult++;
		tword->length = (int)strlen(temp_word);
		for(j=0; j < tword->length; j++) {
		    /* Add the letters to the histogram
		    */

		    key.hist[(int)(temp_word[j])]++;
		}
		num_words++;
	} else
	    /* Otherwise just increase the multiplicity of the word.
	    */
	    wordlist[i].mult++;
	}
    }
    (void) fclose(fptr);

    /*
     * Set the current number of bad words to the number of words
     * in the cipher
     */

    min_badwords = num_words;

    /* count the number of unique letters in the histogram
    */

    for(i = 'a'; i <= 'z'; i++)
	if(key.hist[i])
	    num_ulets++;

    /* Check for a non-valid threshhold
    */
    if((threshhold > num_words) ) {
	threshhold = DEF_THRESH;
    }

    /* Loop through the wordlist.  For each word, find the length of the list
    ** and read in the valid words.
    ** Get the histogram value for each word, too.
    */

    /*
    printf("Reading dictionary..."), fflush(stdout);
    */
    for(i = 0; i < num_words; i++){

	/* Set the hash values for the words
	*/

	wordlist[i].hvalue = get_hvalue(wordlist+i, key.hist);

	/* Open the correct dictionary file
	*/

	get_dfname(wordlist[i].word, filename);
	dfptr = fopen(filename, "r");
	if(!dfptr){
	    fprintf(stderr, "Could not open dictionary file %s.\n", filename);
	    exit(1);
	}

	/* Count the number of words in the dictionary and malloc an array
	** that's large enough to hold the whole thing.  We won't actually
	** use all of it, but this way we won't be caught shorthanded.
	*/

	while(!feof(dfptr)){
	    fgets(temp_word, MAXLENGTH, dfptr);
	    if(!feof(dfptr))
		wordlist[i].dictsize++;
	}
	rewind(dfptr);

	/* Read in the valid words now and put them into the previous
	** array.
	*/

	wordlist[i].dict = (char **)malloc(sizeof(char *) * wordlist[i].dictsize);
	wordlist[i].dictsize = 0;
	if(wordlist[i].dict == NULL){
	    /* Oops!
	    */
	    fprintf(stderr, "Error in allocating memory for the wordlist.\n");
	    exit(1);
	}

	while(!feof(dfptr)){
	    fgets(temp_word, MAXLENGTH, dfptr);
	    if(!feof(dfptr)){
		*strrchr(temp_word, '\n') = '\0';
		lowerchar(temp_word);
		if(validate_mapping(temp_word, wordlist[i].word))
		    if(validate_mapping(wordlist[i].word, temp_word))
			wordlist[i].dict[wordlist[i].dictsize++] = strdup(temp_word);
	    }
	}
	(void) fclose(dfptr);
    }
    putchar('\n');

    /* Sort the list according to the hash value for each word
    */
    qsort((void *)wordlist, (size_t)num_words, sizeof(Word), compare);

    /* Sort it according to the convoluted criteria in the wordsort 
    ** function, but only if we have a threshhold of zero.  This sorting
    ** method works slowly for a threshhold of > 0.
    */
    /*
    if(threshhold < 0)
	wordsort();
    */

    /* Now start solving.
    */
    if(sflag){
	printf("Total words:  %d\n", num_words);
	for(i = 0; i < num_words; i++){
	printf("  word %2d = %-13s  d.length = %5d \tmult. = %d \thvalue = %d\n", 
		i+1, wordlist[i].word, wordlist[i].dictsize, 
		wordlist[i].mult, wordlist[i].hvalue);
	}
    }

    if(pflag){
	if(pword_index != 0)
	    for(i = 0; i < wordlist[pword_index-1].dictsize; i++)
		printf("%s\n", wordlist[pword_index-1].dict[i]);
	else
	    for(pword_index = 0; pword_index < num_words; pword_index++)
		for(i = 0; i < wordlist[pword_index].dictsize; i++)
		printf("%s\n", wordlist[pword_index].dict[i]);
	exit(0);
    }
    /*
    printf("threshhold = %d\n", threshhold);
    printf("Solving"), fflush(stdout);
    */
    solve_cipher(&key, 0, 0);
    putchar('\n');
    if (update_dictionary) {
	/*
	printf("Updating dictionary...\n"),  fflush(stdout);
	*/
	/*
	printf("first common word = %s\n", common_words[0]);
	*/
	for(i=0; i < num_common_words; i++) {
	    move_to_end(common_words[i]);
	}
    }

    exit(0);
}

int
get_hvalue(Word *word, int *hist) {
    int value=0, i;
    int ulets[128];
    char *c;

    for(i = 0; i < 128; i++)
	ulets[i] = FALSE;

    c = word->word;
    while(*c){
	if (isalpha(*c)) {
	    if (ulets[(int)*c] == FALSE) {
		value += hist[(int)*c];
		ulets[(int)*c] = TRUE;
	    }
	}
	c++;
    }

    /*
    while(*word++){
	if(isalpha(*word)){
	    if(ulets[*word - 'a'] == FALSE){
		value += alph[*word - 'a']hist[*word - 'a'];
		ulets[*word - 'a'] = TRUE;
	    }
	}
	word++;
    }
    */

    return value;
}
  
char *
decode_word(Key *key, char *cword, char *dword)
{
    int i=0;

    while(*cword){
	if(isalpha(*cword)) {
	    dword[i] = key->ct[(int)*cword];
	    if (key->ct[(int)*cword] == '\0') {
	    dword[i] = ' ';
	    }
	} else {
	    dword[i] = *cword;
	}
	cword++, i++;
    }
    dword[i] = '\0';

    return dword;
}

void
get_next_word(FILE *fptr, char *word){
    char c=0;

    /* Find the next string of letters, not excluding ' and -
    */

    while(!isalpha(c) && !feof(fptr) && c != '\'' && c != '-')
	c = getc(fptr);
	if(isalpha(c))
	    c |= ' ';

    /* Copy the string of letters into the word
    */

    while(( (isalpha(c)) || c == '\'' || c == '-') && !feof(fptr)){
	*word++ = c;
	c = getc(fptr);
	if(isalpha(c))
	    c |= ' ';
    }
    
    *word = '\0';
    lowerchar(word);
}

void
lowerchar(char *word){
    while(*word){
	if(isalpha(*word))
	    *word |= ' ';
	word++;
    }
}

int
compare(const void *word1, const void *word2){

    if(((Word *)word1)->hvalue < ((Word *)word2)->hvalue)
	return 1;
    else if(((Word *)word1)->hvalue > ((Word *)word2)->hvalue)
	return -1;
    if(((Word *)word1)->length > ((Word *)word2)->length)
	return -1;
    else if(((Word *)word1)->length < ((Word *)word2)->length)
	return 1;
    else
	return 0;

    /*  Commented out because I'm still trying various sorting
    ** criteria.  I don't want to delete this because I might want to 
    ** put it back in later.

    value1 = (double) word1->hvalue / word1->dictsize;
    value2 = (double) word2->hvalue / word2->dictsize;

    if(value1 < value2)
	return 1;
    else if(value1 > value2)
	return -1;
    else
	return 0;
    */
}

int
charcomp(const void *c, const void *d){
    if(*(char *)c < *(char *)d)
	return 1;
    else if(*(char *)c > *(char *)d)
	return -1;
    else return 0;
}

int
validate_mapping(char *word1, char *word2){
    char key[26];
    int mapping = TRUE, i;

    for(i = 0; i < 26; i++)
	key[i] = ' ';

    if(strlen(word1) == strlen(word2)){
	while(*word1 && *word2 && mapping == TRUE){
	    if(*word1 == *word2 && rflag == FALSE){
		if(isalpha(*word1))
		    mapping = FALSE;
	    }
	    else if(key[*word1 - 'a'] == ' ')
		key[*word1 - 'a'] = *word2;
	    else if(key[*word1 - 'a'] != *word2)
		mapping = FALSE;
	    word1++, word2++;
	}
    }
    else
	mapping = FALSE;

    return mapping;
}

char *
get_dfname(char *word, char *string)
{
    int length;

    if (word) {
	length = strlen(word);
	sprintf(string, "%s/len%02d", DICT_DIR, length);
    } else
	string[0] = '\0';

    return string;
}

void
delete_word(char *word){
    FILE *tfptr, *dfptr;
    char tmpfname[MAXLENGTH], filename[MAXLENGTH];
    char tmp_word[MAXLENGTH];

    /* Get the name of the dictionary file where the word should reside
    */

    get_dfname(word, filename);

    strcpy(tmpfname, filename);
    strcat(tmpfname, ".tmp");

    dfptr = fopen(filename, "r");
    tfptr = fopen(tmpfname, "w");

    /* Loop through the old dictionary and copy it to the tmp file
    ** sans the word to be deleted.
    */

    lowerchar(word);
    while(!feof(dfptr)){
	fgets(tmp_word, MAXLENGTH, dfptr);
	if(!feof(dfptr)){
	    lowerchar(tmp_word);
	    *strrchr(tmp_word, '\n') = '\0';
	    if(strcmp(tmp_word, word) == 0);
	    else{
		/* The word didn't match.  Copy it.
		*/
		fprintf(tfptr, "%s\n", tmp_word);
	    }
	}
    }

    (void) rename(tmpfname, filename);
    (void) fclose(dfptr);
    (void) fclose(tfptr);
}

void
query_word(char *word){
  FILE *dfptr;
  int word_found = FALSE;
  char filename[MAXLENGTH], temp_word[MAXLENGTH];

  get_dfname(word, filename);

  dfptr = fopen(filename, "r");
  if(!dfptr){
    printf("Error opening dictionary file %s.\n", filename);
  }
  while(!feof(dfptr)){
    fgets(temp_word, MAXLENGTH, dfptr);
    if(!feof(dfptr)){
      *strrchr(temp_word, '\n') = '\0';
      if(strcmp(temp_word, word) == 0){
	word_found = TRUE;
	printf("%s is in the dictionary.\n", temp_word);
      }
      *temp_word = (isupper(*temp_word))?(*temp_word | ' '):toupper(*temp_word);
      if(strcmp(temp_word, word) == 0){
	word_found = TRUE;
	printf("%s is in the dictionary.\n", temp_word);
      }
    }
  }
  if(!word_found)
    printf("%s not found.\n", word);
  
  (void) fclose(dfptr);
}

void
move_to_end(char *word) {
    char filename[MAXLENGTH];
    char tfname[MAXLENGTH];
    char tmp_word[MAXLENGTH];
    FILE *dfptr, *tfptr;

    get_dfname(word, filename);
    strcpy(tfname, filename);
    strcat(tfname, ".tmp");

    dfptr = fopen(filename, "r");
    tfptr = fopen(tfname, "w");

    if(dfptr == NULL || tfptr == NULL){
	printf("Error opening dictionary files.\n");
    }
    else{
	while(!feof(dfptr)){
	    fgets(tmp_word, MAXLENGTH, dfptr);
	    if(!feof(dfptr)){
		*strrchr(tmp_word, '\n') = '\0';
		lowerchar(tmp_word);
		lowerchar(word);
		if(strcmp(word, tmp_word)){
		    fprintf(tfptr, "%s\n", tmp_word);
		}
	    }
	}
	fprintf(tfptr, "%s\n", word);
    }

    (void) rename(tfname, filename);

    (void) fclose(tfptr);
    (void) fclose(dfptr);
}


void
add_word(char *word){
  char word1[MAXLENGTH];
  char filename[MAXLENGTH], temp_word[MAXLENGTH];
  int i, valid = TRUE;
  FILE *dfptr;

  strcpy(temp_word, word);
  get_dfname(temp_word, filename);

  /* Check that the word is valid.
  ** Is it made up of valid characters?
  ** Is it already in the dictionary?
  */

  for(i = 0; i < strlen(temp_word); i++)
    if(!isalpha(temp_word[i]) && temp_word[i] != '\'' && temp_word[i] != '-')
      valid = FALSE;

  if(valid){
    dfptr = fopen(filename, "r");
    if(!dfptr){
      printf("Error opening dicitonary file %s\n", filename);
    }
    else{
      while(!feof(dfptr)){
	fgets(word1, MAXLENGTH, dfptr);
	if(!feof(dfptr)){
	  *strrchr(word1, '\n') = '\0';
	  if(strcmp(word1, temp_word) == 0){
	    printf("Word %s already exists in dictionary.\n", temp_word);
	    valid = FALSE;
	  }
	}
      }
      (void) fclose(dfptr);
    }
  }

  if(valid){
    fprintf(stderr, "Can't update dictionary.  Inform wart to fix this routine to add words to the front of the dictionary files.");
    return;

    /*
    dfptr = fopen(filename, "a");
    if(!dfptr){
      printf("Error opening dicitonary file %s\n", filename);
    }
    else{
      fprintf(dfptr, "%s\n", temp_word);
      (void) fclose(dfptr);
    }
    */
  }
}


int
update_key(Key *key, char *ct, char *pt)
{
    int valid = TRUE;
    char *c=ct, *p=pt;

    while (*c && *p && valid) {
	if (isalpha(*c)) {
	    if (key->ct[(int)*c] && key->ct[(int)*c] != *p)
		valid = FALSE;

	    if (key->pt[(int)*p] && key->pt[(int)*p] != *c)
		valid = FALSE;

	    if (*c == *p)
		valid = FALSE;
	}

	c++, p++;
    }

    if (valid) {
	while (*ct && *pt) {
	    key->ct[(int)*ct] = *pt;
	    key->pt[(int)*pt] = *ct;
	    ct++, pt++;
	}
    }

    return TRUE;
}

void
locate_keyword(char *word){
    register int i, j, pos, wordlen;
    char *c=word, *d, filename[10], tmp_word[MAXWORDLEN];
    FILE *dfptr;
    int let_used[26], valid;

    for(i = 0; i < 26; i++) 
	let_used[i] = FALSE;

    /* First check that the word is made up entirely of either letters
    ** or digits
    */
    while(*c && *(c+1)){
	if( (isalpha(*c) && isalpha(*(c+1))) || (isdigit(*c) && isdigit(*(c+1))))
	    c++;
	else{
	    printf("Invalid word: %s\n", word);
	    exit(0);
	}
    }
    c = word;
    if(isalpha(*c)){
	while(*c) (*(c++) |= ' ');
    }

    /* Is this a valid keyword?  Check that there are no repeated digits.
    ** Later we will remove this restriction for the digit-keywords.
    */
    for(c = word,i=1; *c; c++){
	if(strchr(c+1, *c) != 0){
	    printf("Invalid keyword: %s.  Character %c repeated.\n", word, *c);
	    i = 0;
	}
	if(i==0) exit(1);
    }

    /* Is this a numerical key?  
    */

    wordlen = strlen(word);
    if(isdigit(*word)){
	/* Only one dictionary file needs to be opened
	*/
	get_dfname(word, filename);
	dfptr = fopen(filename, "r");
	if(!dfptr){
	    printf("Could not open dictionary file %s.\n", filename);
	    exit(1);
	}
	/* Loop through every word in the dictionary file
	*/
	while(!feof(dfptr)){
	    fgets(tmp_word, MAXLENGTH, dfptr);
	    tmp_word[wordlen] = '\0';
	    /* Check to see if the current word is a valid keyword.
	    ** Print it if it is.
	    */
	    for(pos=0, valid=TRUE, i = 'a'; valid && (i <= 'z'); i++){
		for(j = 0; valid && (j < wordlen); j++){
		    if(tmp_word[j] == (char) i){ 
			pos++;
			if((char) pos != word[j]-'0'){
			    valid = FALSE;
			}
		    }
		}
	    }
	    if(valid == TRUE){
		printf("%s\n", tmp_word);
	    }
	}
    }

    /* ...or is it a word with repeated letters removed?
    */

    else{
	for(i = wordlen; i < MAXWORDLEN; i++){
	    sprintf(filename, "%s/len%02d", DICT_DIR,i);
	    /*
	    printf("Searching keywords of length %d\n", i);
	    */
	    dfptr = fopen(filename, "r");
	    if(!dfptr){
		printf("Could not open dictionary file %s.\n", filename);
		exit(1);
	    }
	    while(!feof(dfptr)){
		fgets(tmp_word, MAXLENGTH, dfptr);
		tmp_word[i] = '\0';
		for(j = 0; j < 26; j++)
		    let_used[j] = FALSE;
		for(valid=TRUE,d=tmp_word,c = word; (*c) && (*d) && valid;){
		    /* Skip this letter if it's already been used.
		    ** If it hasn't been used, then add it to the used list and
		    ** check that it's the same as the next letter in the keyword.
		    */
		    if((*c) != (*d)){
			valid = FALSE;
		    }
		    else{
			let_used[(*d)-'a'] = TRUE;
			if(*c) c++;
			    while(isalpha(*d) && let_used[(*d)-'a']) (d++);
		    }
		}
		/* If this was a valid keyword then print it.
		*/
		if(valid == TRUE && (*c == *d)){
		    printf("%s\n", tmp_word);
		}
	    }
	}
    }
}


void
solve_cipher(Key *key, int word_index, int real_words){
    register int valid_key=TRUE;
    register int i, j;
    char *c=NULL, *p=NULL;
    Key nkey;

    /* Can we make enough real words with the remaining words in the
    ** list?  If not, then don't bother trying.  Also, if we have
    ** reached our limit for the number of solutions (MAXKEYS), then
    ** don't bother going on.
    */

    /*
    if((threshhold < 0) && ((min_badwords + real_words) < word_index));
	printf("%d - %d < %d\n", num_words, real_words, min_badwords);
	printf("%d / %d\n", word_index, num_words);
    */
    if((threshhold >=0) && ((threshhold + real_words) < word_index));
    else if (num_keys >= MAXKEYS);

    /* Are we at the end of the list now?
    */

    else if(word_index >= num_words){
	/* Now that we're at the end of the list, have we made enough real
	** words?
	*/

	if( (threshhold >=0 && ((num_words - real_words) <= threshhold))) {

	    /*
	    * min_badwords = num_words - real_words;
	    * printf("num_words = %d, real_words = %d\n", num_words, real_words);
	    * printf("word_index = %d\n", word_index);
	    * printf("min_badwords = %d\n", min_badwords);
	    */

	    /* Has this key been used before?
	    */

	    valid_key = TRUE;
	    for(i = 0; i < num_keys; i++) {
		for(i=0; i < 128; i++) {
		    if (keylist[i].ct[i] != key->ct[i]) {
			valid_key = FALSE;
		    }
		}
	    }

	    /*
	    if(strcmp(keylist[i], key) == 0)
		valid_key = FALSE;
	    */
	    /* If not, then print it.
	    */

	    if(valid_key && num_keys < MAXKEYS){
		if(num_keys < MAXKEYS) {
		    for(i=0; i < 128; i++) {
			keylist[num_keys].ct[i] = key->ct[i];
		    }
		}

		/*
		 * putchar('.'), fflush(stdout);
		 * printf(".%d", num_words - real_words) , fflush(stdout);
		 */

		if(num_keys == MAXKEYS) {
		    printf("MAXKEYS reached.  No more solutions will be printed.\n");
		}
		    
		/* Print the solution to the output file
		*/

		if (strcmp(outputFilename, "-") != 0) {
		    ofptr = fopen(outputFilename, "a");
		} else {
		    ofptr = stdout;
		}
		fprintf(ofptr, "\n# Valid words:  %d/%d", real_words, num_words);

		/* If the threshhold is zero, then we want to move the word
		** to the top of the list so that eventually the most
		** common words are analyzed first.
		*/
		if (real_words != num_words && wordlist[i].valid == 0) {
		    fprintf(ofptr, "\n# Invalid words:  ");
		}

		for(i = 0; i < num_words && num_common_words < MAX_COMMON_WORDS; i++){
		    decode_word(key, wordlist[i].word, temp_word);
		    if (real_words != num_words && wordlist[i].valid == 0) {
			fprintf(ofptr, " '%s'", temp_word);
		    }
		    if(threshhold == 0 || min_badwords == 0){
			common_words[num_common_words++] = strdup(temp_word);
		    }
		}

		/*
		 * Print the K1 keyed alphabet
		 */

		fprintf(ofptr, "\nk1key=");
		for(i='a'; i <= 'z'; i++)
		    if (key->ct[i])
			fputc(key->ct[i], ofptr);
		    else
			fputc(' ', ofptr);

		/*
		 * Print the alphabet
		 */
		fprintf(ofptr, "\nalfbt=");
		for(i='a'; i <= 'z'; i++)
		    fputc(i, ofptr);

		/*
		 * Print the K2 keyed alphabet
		 */

		fprintf(ofptr, "\nk2key=");
		for(i='a'; i <= 'z'; i++)
		    if (key->pt[i])
			fputc(key->pt[i], ofptr);
		    else
			fputc(' ', ofptr);

		/*
		 * Print important information about the cipher
		 */

		fprintf(ofptr, "\ntype=aristocrat");
		fprintf(ofptr, "\nperiod=0");

		/*
		 * Print the key in the cipher save format
		 */

		fprintf(ofptr, "\nkey=abcdefghijklmnopqrstuvwxyz \"");
		for(i='a'; i <= 'z'; i++) {
		    if (key->ct[i]) {
			fputc(key->ct[i], ofptr);
		    } else {
			fputc(' ', ofptr);
		    }
		}
		fprintf(ofptr, "\"");
		fflush(ofptr);

		/*
		 * Print the plaintext solution
		 */

		/*
		fprintf(ofptr, "\nplaintext\t{");
		fflush(ofptr);
		*/
		for(i=0; cipher[i]; i++) {
		    if (cipher[i] == '\n' || cipher[i] == '\r') {
			plaintext[i] = ' ';
			/*
			fputc(' ', ofptr);
			*/
		    } else if(isalpha(cipher[i]) && key->ct[(int)cipher[i]]) {
			plaintext[i] = key->ct[(int)cipher[i]];
			/*
			fputc(key->ct[(int)cipher[i]], ofptr);
			*/
		    }
		    else if(isalpha(cipher[i])) {
			plaintext[i] = ' ';
			/*
			fputc(' ', ofptr);
			*/
		    }
		    else {
			plaintext[i] = cipher[i];
			/*
			fputc(cipher[i], ofptr);
			*/
		    }
		}
		plaintext[i] = '\0';
		fprintf(ofptr, "\nplaintext=%s\n", plaintext);
		/*
		fputc('}', ofptr);
		fputc('\n', ofptr);
		*/
		fflush(ofptr);

		/*
		 * Print the cipher
		 */

		fprintf(ofptr, "ciphertext=");
		for(i=0; cipher[i]; i++) {
		    if (cipher[i] == '\n' || cipher[i] == '\r') {
			fputc(' ', ofptr);
		    }
		    else {
			fputc(cipher[i], ofptr);
		    }
		}
		fputc('\n', ofptr);
		fflush(ofptr);

		if (strcmp(outputFilename, "-") != 0) {
		    (void) fclose(ofptr);
		}
	    }
	}
    }

    /* Since we're not at the end of the wordlist, try the next word 
    ** in the list
    */

    else{
	for(i = wordlist[word_index].dictsize-1; i >= 0; i--){

	    for(j='a'; j <= 'z'; j++) {
		nkey.ct[j] = key->ct[j];
		nkey.pt[j] = key->pt[j];
	    }

	    /*
	     * Find out if this word makes a good substitution
	     */

	    c = wordlist[word_index].word;
	    p = wordlist[word_index].dict[i];
	    valid_key = TRUE;
	    while (*c && *p && valid_key) {
		if (isalpha(*c)) {
		    if (nkey.ct[(int)*c] && nkey.ct[(int)*c] != *p)
			valid_key = FALSE;

		    if (nkey.pt[(int)*p] && nkey.pt[(int)*p] != *c)
			valid_key = FALSE;

		    if (*c == *p)
			valid_key = FALSE;
		}

		c++, p++;
	    }

	    if (valid_key) {
		c = wordlist[word_index].word;
		p = wordlist[word_index].dict[i];
		while (*c && *p) {
		    nkey.ct[(int)*c] = *p;
		    nkey.pt[(int)*p] = *c;
		    c++, p++;
		}
	    }
	    /*
	    valid_key = update_key(&nkey, wordlist[word_index].word, 
		    wordlist[word_index].dict[i]);
	    */

	    if(valid_key){

		/* Are we running in verbose mode?
		*/

		if(vflag){
		    if(word_index <= vlevel){
			printf("index = %2d,   dict index = %5d,  %s -> %s\n",
				word_index, i, wordlist[word_index].word, 
				wordlist[word_index].dict[i]);
			}
		}

		wordlist[word_index].valid = 1;
		solve_cipher(&nkey, word_index+1, real_words+1);
	    }
	}
	for(j='a'; j <= 'z'; j++) {
	    nkey.ct[j] = key->ct[j];
	    nkey.pt[j] = key->pt[j];
	}

	if(vflag)
	    if(word_index <= vlevel)
		printf("index = %2d,   dict_index = (nil),  dict_word = (null)\n", word_index);
	wordlist[word_index].valid = 0;
	solve_cipher(&nkey, word_index+1, real_words);
    }

    if(Dflag){
	printf("Current depth = %d\n", word_index);
    }
}
