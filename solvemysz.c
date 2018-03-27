/*
 * solvemysz.c --
 *
 *	This file implements a brute force search for solving myszcowski
 *	ciphers.  
 *	Very approximate solving times for a single 2.4GHz processor:
 *
 *	Key length	Time (333MHz)	Time(2.4GHz)
 *	7		1 second 	< 1 second
 *	8		10 seconds	  1 second
 *	9		3 minutes	 22 seconds
 *	10		30 minutes 	  5 minutes
 *	11		20 hours	  2 hours
 *	12		1 week
 *	13		3 months
 *
 * Copyright (c) 1999-2003 Michael Thomas <wart@kobold.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <englishFrequencies.h>

#define STEPINTERVAL 1000000

typedef struct Myszcowski {
    int period;
    int length;
    int maxColCount;
    char *ct;
    char *result;
    char *maxresult;
    char *tip;

    int *key;
    int *foundArr;
    int *maxKey;
    int *colArr;
    int *colLength;
    int *orderArr;
    int *startPos;
    int *orderCount;
    int *invalidArr;

    int maxVal;
    int minReportVal;
    unsigned long solCount;
} Myszcowski;

Myszcowski myszItem;

void
print_usage()
{
    fprintf(stderr, "Usage:  solvemysz -file cipher.txt -period n ?-tip string? ?-keyprefix x,y,z...? ?-minsolval n? ?-maxcolcount n?\n");
}

int
RecSolveMyszcowski(int depth)
{
    register int i, j, col, pos;

    if (depth >= myszItem.period) {
	register int value=0;
	register int numCols, row, newCol;

	myszItem.solCount++;

	/*
	 * Find the plaintext for this key.  This used to be a call to
	 * GetMyszcowski()
	 */

	for(i=0; i < myszItem.period; i++) {
	    myszItem.orderArr[i] = 0;
	}

	for(col=0, pos=0; col < myszItem.period; col++) {
	    register int temp_pos;

	    /*
	    * Locate the col'th column(s) in the key
	    */
	    for(i=0, numCols=0; i < myszItem.period; i++) {
		if (myszItem.key[i] == col) {
		    myszItem.colArr[numCols++] = i;
		}
	    }

	    temp_pos = pos;
	    for(i=0; i < numCols; i++) {
		myszItem.startPos[myszItem.colArr[i]] = pos;
		temp_pos += myszItem.colLength[myszItem.colArr[i]];
	    }
	    pos = temp_pos;
	}

	/*
	 * Generate the plaintext for this key
	 */

	for(col=0; col < myszItem.period; col++) {
	    newCol = myszItem.key[col];

	    for(row=0; row < myszItem.colLength[col]; row++) {
		/*
		int oldIndex = myszItem.startPos[col] + row * myszItem.foundArr[newCol] + myszItem.orderArr[newCol];
		int newIndex = col + row * myszItem.period;
		*/

		myszItem.result[col + row * myszItem.period] = myszItem.ct[myszItem.startPos[col] + row * myszItem.foundArr[myszItem.key[col]] + myszItem.orderArr[myszItem.key[col]]];

		/*
		myszItem.result[newIndex] = myszItem.ct[oldIndex];
		*/
	    }
	    myszItem.orderArr[newCol]++;
	}

	myszItem.result[myszItem.length] = (char)NULL;

	/*
	 * Print the current key/plaintext to the screen to provide
	 * simple feedback to the user.
	 */

	if (myszItem.solCount % STEPINTERVAL == 0) {
	    fprintf(stdout, "#Key: ");
	    for(i=0; i < myszItem.period; i++) {
		fprintf(stdout, "%d ", myszItem.key[i]);
	    }
	    fprintf(stdout, "\n#Iter %lu: %s\n\n", myszItem.solCount, myszItem.result);
	    fflush(stdout);
	}

	for(i=1; i < myszItem.length; value += get_english_digram_value(myszItem.result[i-1], myszItem.result[i]), i++);
	/*
	for(i=1, value=0; i < myszItem.length; i++) {
	    int tvalue = digram_freq[myszItem.result[i]-'a'][myszItem.result[i-1]-'a'];
	    if (myszItem.result[i] >= 'a' && myszItem.result[i-1] >= 'a' && tvalue) {
		value += (int) (log10(tvalue) * 100);
	    }
	}
	*/

	/*
	 * Store this key if it gives the best digram frequency count.
	 */

	if (myszItem.tip) {
	    if (strstr(myszItem.result, myszItem.tip)) {
		fprintf(stdout, "#Key: ");
		for(i=0; i < myszItem.period; i++) {
		    fprintf(stdout, "%d ", myszItem.key[i]);
		}
		fprintf(stdout, "\tTip: %d\n#Iter %ld: %s\n\n", value, myszItem.solCount, myszItem.result);
		fflush(stdout);
	    }
	}

	if (value > myszItem.maxVal) {
	    fprintf(stdout, "#Key: ");
	    for(i=0; i < myszItem.period; i++) {
		fprintf(stdout, "%d ", myszItem.key[i]);
	    }
	    fprintf(stdout, "\tFit: %d\n#Iter %ld: %s\n\n", value, myszItem.solCount, myszItem.result);
	    fflush(stdout);

	    myszItem.maxVal = value;
	    for(i=0; i < myszItem.period; i++)
		myszItem.maxKey[i] = myszItem.key[i];
	    for(i=0; i < myszItem.length; i++)
		myszItem.maxresult[i] = myszItem.result[i];
	    myszItem.maxresult[i] = (char)NULL;
	}
    } else {
	register int valid=1;

	for(i=0; i < myszItem.period; i++) {
	    valid=1;

	    myszItem.foundArr[i]++;

	    /*
	     * Special check for redefence ciphers.  Limit the number
	     * of times that a given column can be repeated to 2.
	     */
	    if (myszItem.maxColCount && 
		    (myszItem.foundArr[i] > myszItem.maxColCount)) {
		valid = 0;
	    }
	    if (myszItem.invalidArr[i]) {
		valid = 0;
	    }
	    if (myszItem.foundArr[i] + i > myszItem.period) {
		valid = 0;
	    }

	    for(j=1; j < myszItem.foundArr[i] && valid; j++) {
		/*
		 * Check that we're not inserting too many of one number
		 * beneath another:
		 *
		 * 5,4 -> 5,4,4
		 *
		 * or
		 *
		 * 0,0 -> 0,0,1
		 */
		if (myszItem.foundArr[i+j]) {
		    valid=0;
		} else {
		    myszItem.invalidArr[i+j] = 1;
		}
	    }

	    if (valid) {
		myszItem.key[depth] = i;
		RecSolveMyszcowski(depth+1);
		myszItem.invalidArr[myszItem.foundArr[i]-1 + i] = 0;
	    }
	    myszItem.foundArr[i]--;
	}
    }

    return 1;
}

int
main(int argc, char **argv)
{
    int i;
    char s[81], *c, *e;
    char ct[1024];
    int maxColLen=0;
    int maxColCount=0;
    int minReportVal = 0;
    char *keyPrefix = (char *)NULL;
    int keyPrefixLength = 0;
    char *tip=(char *)NULL;
    char *infile=(char *)NULL;
    FILE *inFptr = (FILE *)NULL;

    /*
     * Process the command line arguments
     */

    argc--, argv++;

    if (argc < 2 || argc%2 != 0) {
	print_usage();
	exit(1);
    }

    while (argc > 0) {
	char *option = argv[0];
	char *value = argv[1];

	if (strcmp(option, "-file") == 0) {
	    infile = value;
	} else if (strcmp(option, "-period") == 0) {
	    if (sscanf(value, "%d", &i) != 1) {
		print_usage();
		exit(1);
	    }
	    myszItem.period = i;
	} else if (strcmp(option, "-keyprefix") == 0) {
	    keyPrefix = value;
	} else if (strcmp(option, "-maxcolcount") == 0) {
	    if (sscanf(value, "%d", &i) != 1) {
		print_usage();
		exit(1);
	    }
	    maxColCount = i;
	} else if (strcmp(option, "-tip") == 0) {
	    tip = (char *)strdup(value);
	} else if (strcmp(option, "-minsolval") == 0) {
	    fprintf(stderr, "-minsolval option not yet supported\n");
	    exit(1);

	    if (sscanf(value, "%d", &i) != 1) {
		print_usage();
		exit(1);
	    }
	    minReportVal = i;
	} else {
	    print_usage();
	    exit(1);
	}

	argv = argv + 2;
	argc = argc - 2;
    }

    /*
     * Check that the required values have been set.
     */

    if (myszItem.period <= 1) {
	fprintf(stderr, "Invalid period setting:  %d.  Must be > 2\n",
		myszItem.period);
	exit(1);
    }

    /*
     * Read the cipher
     */

    inFptr = fopen(infile, "r");
    if (inFptr == NULL) {
	fprintf(stderr, "Could not open %s for reading.\n", infile);
	exit(1);
    }
    e = ct;
    while(! feof(inFptr)) {
	fgets(s, 80, inFptr);
	if (!feof(inFptr)) {
	    for(c = s; *c; c++) {
		/*
		 * Accept both numbers and letters (so2002:e08)
		 */
		if ((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9')) {
		    *e = *c;
		    e++;
		}
	    }
	}
    }
    fclose(inFptr);
    *e = (char)NULL;

    myszItem.length = strlen(ct);

    /*
     * Initialize the data needed to solve.
     */

    myszItem.solCount = 0;
    myszItem.maxVal = 0;
    myszItem.maxColCount = maxColCount;
    myszItem.minReportVal = minReportVal;
    myszItem.tip = tip;
    myszItem.ct = (char *)malloc(sizeof(char) * (myszItem.length + 1));
    myszItem.key = (int *)malloc(sizeof(int) * myszItem.period);
    myszItem.result = (char *)malloc(sizeof(char) * (myszItem.length + 1));
    myszItem.maxresult = (char *)malloc(sizeof(char) * (myszItem.length + 1));
    myszItem.maxKey = (int *)malloc(sizeof(int) * myszItem.period);
    myszItem.colArr = (int *)malloc(sizeof(int) * myszItem.period);
    myszItem.colLength = (int *)malloc(sizeof(int) * myszItem.period);
    myszItem.orderArr = (int *)malloc(sizeof(int) * myszItem.period);
    myszItem.startPos = (int *)malloc(sizeof(int) * myszItem.period);
    myszItem.orderCount = (int *)malloc(sizeof(int) * myszItem.period);
    myszItem.invalidArr = (int *)malloc(sizeof(int) * myszItem.period);
    myszItem.foundArr = (int *)malloc(sizeof(int) * myszItem.period);

    maxColLen = (myszItem.length%myszItem.period == 0)?(myszItem.length / myszItem.period):(myszItem.length/myszItem.period + 1);

    for(i=0; i < myszItem.period; i++) {
	myszItem.key[i] = myszItem.maxKey[i] = myszItem.colArr[i] = myszItem.orderArr[i] = myszItem.startPos[i] = myszItem.orderCount[i] = myszItem.invalidArr[i] = myszItem.foundArr[i] = 0;
	if ((unsigned int)(myszItem.period*(maxColLen-1)+i) < myszItem.length) {
	    myszItem.colLength[i] = maxColLen;
	} else {
	    myszItem.colLength[i] = maxColLen - 1;
	}
    }

    for (i=0; i < myszItem.length; i++) {
	myszItem.ct[i] = ct[i];
    }
    myszItem.ct[i] = (char)NULL;

    /*
     * If the user wants to start the search partway through (ie, they used
     * the -keyprefix option), then we need to set up the key.
     */

    if (keyPrefix != NULL) {
	char *sepPos;
	char tempKeyString[4];
	int tempKeyVal;

	while (keyPrefix != (char *)NULL) {
	    sepPos = strchr(keyPrefix, (int) ',');
	    if (sepPos == (char *)NULL) {
		sepPos = keyPrefix + strlen(keyPrefix);
	    }

	    if (sepPos - keyPrefix > 3) {
		fprintf(stderr, "Key values > 999 are not permitted\n");
		exit(1);
	    }
	    strncpy(tempKeyString, keyPrefix, (sepPos - keyPrefix));
	    tempKeyString[sepPos - keyPrefix] = (char)NULL;

	    if (sscanf(tempKeyString, "%d", &tempKeyVal) != 1) {
		fprintf(stderr, "Key values > 999 are not permitted\n");
		exit(1);
	    } else {
		if (tempKeyVal > myszItem.period) {
		    fprintf(stderr, "Key values must be less than the period\n");
		    exit(1);
		} else {
		    int j;
		    int valid=1;

		    keyPrefixLength++;
		    myszItem.foundArr[tempKeyVal]++;

		    if (myszItem.invalidArr[tempKeyVal]) {
			valid = 0;
		    } else if (myszItem.foundArr[tempKeyVal] + tempKeyVal
			    > myszItem.period) {
			valid = 0;
		    }

		    for(j=1; j < myszItem.foundArr[tempKeyVal] && valid; j++) {
			/*
			* Check that we're not inserting too many of one number
			* beneath another:
			*
			* 5,4 -> 5,4,4
			*
			* or
			*
			* 0,0 -> 0,0,1
			*/
			if (myszItem.foundArr[tempKeyVal+j]) {
			    valid=0;
			} else {
			    myszItem.invalidArr[tempKeyVal+j] = 1;
			}
		    }

		    if (!valid) {
			fprintf(stderr, "Invalid key produced from prefix position %d\n", keyPrefixLength);
			exit(1);
		    } else {
			myszItem.key[keyPrefixLength-1] = tempKeyVal;
		    }
		}
	    }

	    if (*sepPos == (char)NULL) {
		keyPrefix = (char *)NULL;
	    } else {
		keyPrefix = sepPos + 1;
	    }
	}

	/*
	 * There will be one value left after we have exhausted the separators
	 */

	
    }

    /*
     * Gentlemen start your engines!  Unless the user specified a starting
     * position with -keyprefix, keyPrefixLength will be zero.
     */

    RecSolveMyszcowski(keyPrefixLength);

    fprintf(stdout, "#%ld possible keys\n", myszItem.solCount);
    fprintf(stdout, "type=myszcowski\n");
    fprintf(stdout, "period=%d\n", myszItem.period);
    fprintf(stdout, "key=");
    for(i=0; i < myszItem.period; i++) {
	myszItem.key[i] = myszItem.maxKey[i];
	fprintf(stdout, "%c", myszItem.key[i]+'a');
    }
    fprintf(stdout, "\n");
    fprintf(stdout, "#Digram value:  %d\n", myszItem.maxVal);
    fprintf(stdout, "plaintext=%s\n", myszItem.maxresult);
    fprintf(stdout, "ciphertext=%s\n", myszItem.ct);

    fflush(stdout);
}
