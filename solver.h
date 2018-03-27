/* This is the header file for the solver program.
*/


#define OFILE      "output"
/*
 * This should be defined in the Makefile
 *
#define DICT_DIR   "/home/wart/lib/dict"
 */
#define MAXKEYS      50
#define MAXWORDS     256
#define MAXLINES     10
#define MAXLENGTH    80
#define MAXCIPHERLENGTH    2048
#define MAXWORDLEN   25
#define LINELENGTH  100
#define FALSE         0
#define TRUE          1
#define DEF_THRESH    0
#define MAX_COMMON_WORDS	1024

typedef struct word_structure{
    char word[MAXLENGTH];
    int length;
    int mult;
    char **dict;
    int dictsize;
    int hvalue;
    int valid;
} Word;

typedef struct Key{
    char ct[128];
    char pt[128];
    int  hist[128];
} Key;

/* Decodes the encoded word with the key.  */
char *decode_word(Key *key, char *word, char *newword);

/* Get the dictionary filename where 'word' can be found.  */
char *get_dfname(char *word, char *string);

/* Compare two items. Used for qsort() */
int charcomp(const void  *c, const void  *d);
int compare(const void *element1, const void *element2);

/* Update the key with the mapping used in cword goes to dword.     */
/* Returns FALSE if the mapping was not valid or otherwise failed.  */
int update_key(Key *key, char *cword, char *dword);

/* Finds out if the mapping of word1 to word2 is valid.  Returns  */
/* TRUE if it is, FALSE otherwise.                                */
int validate_mapping(char *word1, char *word2);

/* Add the word to the dictionary  */
void add_word(char *word);

/* Move a word to the end of the dictionary */
void move_to_end(char *word);

/* Remove a word from the dictionary   */
void delete_word(char *word);

/* Read in another word from the cipher file  */
void get_next_word(FILE *file, char *word);

/* change 'word' to all lowercase letters.  */
void lowerchar(char *word);

/* Check to see if 'word' is in the dictionary  */
void query_word(char *word);

/* Main recursive routine for solving the cipher.  */
void solve_cipher(Key *key, int wordindex, int real_words);

int get_hvalue(Word *word, int *hist);
