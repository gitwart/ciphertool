/*
 * morse.c --
 *
 *	This file contains utility functions for dealing with morse
 *	code ciphers.
 *
 * Copyright (c) 1995-2000 Michael Thomas <wart@kobold.org>
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

#include <stdlib.h>
#include <string.h>
#include <morse.h>

#include <cipherDebug.h>

#define NUM_MORSE_CHARS 128

static char *toMorse[NUM_MORSE_CHARS] = {"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",		/* Not needed */
	"",		/* ! */
	"",		/* " */
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"--..--",	/* , (comma) */
	"-....-",	/* - (dash) */
	".-.-.-",	/* . (period) */
	"-..-.",		/* / (slash) */
	"-----",	/* 0 */
	".----",	/* 1 */
	"..---",	/* 2 */
	"...--",	/* 3 */
	"....-",	/* 4 */
	".....",	/* 5 */
	"-....",	/* 6 */
	"--...",	/* 7 */
	"---..",	/* 8 */
	"----.",	/* 9 */
	"--...",	/* : */
	"-.-.-.",	/* ; */
	"",
	"",
	"",
	".-.-.-",	/* ? (question mark) */
	"",		/* Not needed */
	".-",		/* A */
    	"-...",		/* B */
	"-.-.",		/* C */
	"-..",		/* D */
	".",		/* E */
    	"..-.", 	/* F */
    	"--.", 		/* G */
	"....",		/* H */
	"..",		/* I */
	".---",		/* J */
	"-.-",		/* K */
	".-..",		/* L */
	"--",		/* M */
	"-.",		/* N */
	"---",		/* O */
	".--.",		/* P */
	"--.-",		/* Q */
	".-.",		/* R */
	"...",		/* S */
	"-",		/* T */
	"..-",		/* U */
	"...-",		/* V */
	".--",		/* W */
	"-..-",		/* X */
	"-.--",		/* Y */
	"--..",		/* Z */
	"",
	"",
	"",
	"",
	"",
	"",
	".-",		/* a */
    	"-...",		/* b */
	"-.-.",		/* c */
	"-..",		/* d */
	".",		/* e */
    	"..-.", 	/* f */
    	"--.",	 	/* g */
	"....",		/* h */
	"..",		/* i */
	".---",		/* j */
	"-.-",		/* k */
	".-..",		/* l */
	"--",		/* m */
	"-.",		/* n */
	"---",		/* o */
	".--.",		/* p */
	"--.-",		/* q */
	".-.",		/* r */
	"...",		/* s */
	"-",		/* t */
	"..-",		/* u */
	"...-",		/* v */
	".--",		/* w */
	"-..-",		/* x */
	"-.--",		/* y */
	"--..",		/* z */
	"",
	"",
	"",
	"",
	"" /* Not needed */};

/*
 * This routine just takes a morse string and returns the character
 * it represents.  The null character is returned if no match is found.
 */

char
MorseStringToChar(char *mString)
{
    int i, len;

    len = strlen(mString);

    if (len < 1 || len > 6) {
	return (char)NULL;
    }

    for(i=0; i < len; i++) {
	if (mString[i] != DOT && mString[i] != DASH) {
	    return (char)NULL;
	}
    }

    /*
     * Loop in reverse so that lowercase letters are found before uppercase
     * letters.
     */
    for(i=NUM_MORSE_CHARS-1; i >= 0; i--) {
	if (strcmp(mString, toMorse[i]) == 0) {
	    return (char)i;
	}
    }

    return (char)NULL;
}

char *
MorseStringToString(char *mString, char *result)
{
    int i, len, numChars, rIndex, tIndex;
    char tResult;
    char *tempStr;

    len = strlen(mString);
    result[0] = (char)NULL;

    for(i=0; i < len; i++) {
	if (mString[i] != DOT && mString[i] != DASH && mString[i] != SPACE && mString[i]!= BLANK) {
	    return (char *)NULL;
	}
    }

    /*
     * Count the number of characters.  We can simply count the number
     * of spaces for this.
     */

    for(i=0; i < len; i++) {
	if (mString[i] == SPACE) numChars++;
    }

    /*
     * Loop through the morse string and start stuffing with the translation
     */

    tempStr = (char *)malloc(sizeof(char) * (strlen(mString) + 1));

    for(i=0, rIndex=0, tIndex=0; i <= len; i++) {
	if (mString[i] == SPACE || mString[i] == (char)NULL) {
	    tempStr[tIndex] = (char)NULL;
	    tResult = MorseStringToChar(tempStr);
	    if (!tResult) {
		/*
		 * Check if this is the last character.  If so, then don't
		 * append the extra space at the end.
		 */
		if (i != len) {
		    result[rIndex++] = ' ';
		} else {
		    result[rIndex++] = (char)NULL;
		}
	    } else {
		result[rIndex++] = tResult;
	    }
	    tIndex = 0;
	} else {
	    tempStr[tIndex++] = mString[i];
	}
    }
    result[rIndex] = (char)NULL;

    free(tempStr);

    return result;
}

char *
MorseStringToSpaceyString(char *mString, char *result)
{
    int i, len, numChars, rIndex, tIndex;
    char tResult;
    char *tempStr;

    len = strlen(mString);
    result[0] = (char)NULL;

    for(i=0; i < len; i++) {
	if (mString[i] != DOT && mString[i] != DASH && mString[i] != SPACE && mString[i]!= BLANK) {
	    return (char *)NULL;
	}
    }

    /*
     * Count the number of characters.  We can simply count the number
     * of spaces for this.
     */

    for(i=0; i < len; i++) {
	if (mString[i] == SPACE) numChars++;
    }

    /*
     * Loop through the morse string and start stuffing with the translation
     */

    tempStr = (char *)malloc(sizeof(char) * (strlen(mString) + 1));

    for(i=0, rIndex=0, tIndex=0; i <= len; i++) {
	if (mString[i] == SPACE || mString[i] == (char)NULL) {
	    tempStr[tIndex] = (char)NULL;
	    tResult = MorseStringToChar(tempStr);
	    if (!tResult) {
		/*
		 * Check if this is the last character.  If so, then don't
		 * append the extra space at the end.
		 */
		if (i != len) {
		    result[rIndex++] = ' ';
		} else {
		    result[rIndex++] = (char)NULL;
		}
	    } else if (tResult == BLANK) {
		result[rIndex++] = '_';
	    } else {
		result[rIndex++] = tResult;
	    }
	    tIndex = 0;
	} else {
	    tempStr[tIndex++] = mString[i];
	    result[rIndex++] = ' ';
	}
    }
    /*
    printf("rIndex = %d\n", rIndex);
    */
    result[rIndex] = (char)NULL;

    free(tempStr);

    return result;
}

char *
CharToMorse(char l)
{
    if ((int)l < 0 || (int)l >= NUM_MORSE_CHARS) {
	return (char *)NULL;
    }

    return toMorse[(int)l];
}


/*
 * StringToMorse returns a newly allocated string containing the morse code
 * translation of the plaintext.
 *
 * Memory is allocated within the function.  Since the amount of memory 
 * is not known beforehand, it will use an upper bound on the amount of 
 * memory required, which could be strlen(in)*6 + strlen(in) + 2 + 1 == up 
 * to six morse marks per letter + a separation mark for each letter + the 
 * maximum number of padding bytes required by any calling function (e.g. 
 * fmorse, morbit) + a byte for null termination.  This memory would be 
 * freed by the caller.
 */

char *
StringToMorse(char *text) {
    int i;
    int index_out = 0;
    int n = strlen(text);
    char *ml; /* morse letter */
    char *mt; /* morse text */
    int maxcount = n*7 + 2 + 1;
    if (!text) {
	return ((char *) NULL);
    }
    mt = (char *)malloc(sizeof(char) * maxcount);
    for (i=0; i<n; i++) {
	if (i > 0) {
	    mt[index_out++] = SPACE;
	}
	ml = CharToMorse(text[i]);
	strcpy(mt+index_out, ml);
	index_out += strlen(ml);
    }
    mt[index_out] = (char)NULL;
    return mt;
}

/*
 * Check 'mt' for strings longer than 6 characters, or 3 x's in a row.
 */

int
MorseValid(char *mt)
{

    int spaces_in_a_row = 0;
    int marks_in_a_row = 0;
    int i;
    int n = strlen(mt);

    /* Make sure all characters are either SPACE, DOT, or DASH. */
    for(i=0; i<n; i++) {
	switch(mt[i]) {
	case SPACE: case DOT: case DASH:
	    break;
	default:
	    return 0;
	}
    }
    
    /* Check for strings longer than 6 characters. */
    for(i=0; i<n; i++) {
	if (mt[i] == DOT || mt[i] == DASH) {
	    if (++marks_in_a_row > 6) {
		return 0;
	    }
	} else {
	    marks_in_a_row = 0;
	}
    }

    /* Check for 3 x's in a row. */
    for(i=0; i<n; i++) {
	if (mt[i] == SPACE) {
	    if (++spaces_in_a_row >= 3) {
		return 0;
	    }
	} else {
	    spaces_in_a_row = 0;
	}
    }

    return 1;
}
