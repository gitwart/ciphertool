/*
 * cipherUtil.c --
 *
 *	This file contains various utility functions available to all
 *	cipher types.  Most of these are for scanning aned extracting
 *	valid characters for a particular cipher.
 *
 * Copyright (c) 1995-2008 Michael Thomas <wart@kobold.org>
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

#include <cipher.h>
#include <string.h>
#include <ctype.h>

#include <cipherDebug.h>

/*
 * Use the valid_characters field of the cipher item to count the number
 * of valid characters in the ciphertext
 */

int
CountValidChars(CipherItem *itemPtr, const char *ct, int *invalidCount)
{
    int		count=0;
    int		invalid=0;
    char	*c;

    while(*ct) {
	for(c = itemPtr->typePtr->valid_chars; *c && *c != *ct && *c != tolower(*ct); c++);
	if (*c) {
            count++;
        } else {
            invalid++;
        }
	ct++;
    }

    if (invalidCount) {
        *invalidCount = invalid;
    }

    return count;
}

/*
 * Use the valid_characters field of the cipher item to extract the
 * valid characters from the ciphertext.
 */

char *
ExtractValidChars(CipherItem *itemPtr, const char *ct)
{
    int		length=0;
    int		index=0;
    int         invalid=0;
    char	*newct=(char *)NULL;
    char	*c;

    length = CountValidChars(itemPtr, ct, &invalid);

    /*
     * This is a holdover from the homophonic cipher.  This should really
     * be moved elsewhere.
     */

    if (length != 0) {
	newct = (char *)ckalloc(sizeof(char) * length + 1);

	while(*ct) {
	    for(c = itemPtr->typePtr->valid_chars; *c && *c != *ct && *c != tolower(*ct); c++);
	    if (*c) newct[index++] = *c;

	    /*
	     * double check that we have counted the length of the cipher
	     * correctly
	     */
	    if (index > length) {
		ckfree(newct);
		return (char *)NULL;
	    }
		
	    ct++;
	}
	newct[index] = '\0';
    }

    return newct;
}

/*
 * Extract the valid characters from the ciphertext, but convert 'j' to 'i'
 * as is common with keysquare-based ciphers.
 */

char *
ExtractValidCharsJtoI(CipherItem *itemPtr, const char *ct)
{
    char	*c,
                *d;

    c = ExtractValidChars(itemPtr, ct);

    if (c) {
        for (d=c; *d; d++) {
            if (*d == 'j') {
                *d = 'i';
            }
        }
    }

    return c;
}

/*
 * Take a string of numbers and convert to an array of integers.
 */
int *
TextToInt(Tcl_Interp *interp, CipherItem *itemPtr, const char *intstring, int *count, const char *format, int fmt_length)
{
    int		intval;
    int		*newarr=(int *)NULL;
    char	numints[32];
    int		length=0;
    int		i;
    char	*e=(char *)NULL;
    char	*new_ct=(char *)NULL;

    *count=0;
    length = CountValidChars(itemPtr, intstring, (int *)NULL);

    if (length % fmt_length != 0 || length == 0) {
	Tcl_SetResult(interp, "Invalid number of valid characters (possibly none) found in text string", TCL_STATIC);
	return (int *)NULL;
    }

    new_ct = (char *)ckalloc(sizeof(char) * length + 1);
    newarr = (int *)ckalloc(sizeof(int) * length / fmt_length);

    for(i=0; i < length/fmt_length; i++) {
	newarr[i] = 0;
    }

    /*
     * Scan every pair of characters and try to convert the pair
     * to an integer.
     */

    e = ExtractValidChars(itemPtr, intstring);
    if (!e) {
	Tcl_SetResult(interp, "Error extracting numbers.  An even number of digits must be specified.", TCL_STATIC);
	ckfree((char *)new_ct);
	ckfree((char *)newarr);
	return (int *)NULL;
    }

    length = strlen(e);

    for(i=0; i < length; i+=fmt_length) {
	if (sscanf(e+i, format, &intval) != 1)
	    i=length;

	if (intval == 0)
	    intval = 100;

	if (*count > length/2)
	    abort();

	if (*count > length/2) {
	    Tcl_SetResult(interp, "Error converting text to integer array",
		    TCL_STATIC);
	    ckfree((char *)newarr);
	    ckfree((char *)new_ct);
	    return (int *)NULL;
	}
	newarr[(*count)++] = intval;
    }

    sprintf(numints, "%d", *count);
    Tcl_SetResult(interp, numints, TCL_VOLATILE);

    if (e) ckfree((char *)e);
    if (new_ct) ckfree((char *)new_ct);

    return newarr;
}

/*
 * Locate a single character in an item's valid character list.
 * Is this code cryptic enough?
 */
int
IsValidChar(CipherItem *itemPtr, char ct)
{
    char *c=itemPtr->typePtr->valid_chars;

    for(; *c && *c != ct; c++);

    return *c;
}

/*
 * Returns the first character in a string that is a duplicate, or
 * the NULL character if no duplicates were found.
 */

char FindFirstDuplicate(const char *inputString, const char *ignoreVals) {
    const char *indexPtr;
    unsigned char ignoreMask[32] = {0};
    unsigned char foundMask[32] = {0};

    if (! inputString) {
        return (char) '\0';
    }
    /*
     * Intialize the ignore bitmask
     */
    indexPtr=ignoreVals;
    while (indexPtr) {
        ignoreMask[(*indexPtr)/8] |= 1<<((*indexPtr)%8);
    }

    indexPtr=inputString;
    while (*indexPtr) {
        /*
         * Skip characters in the ignore list
         */
        if (! (ignoreMask[(*indexPtr)/8] & 1<<((*indexPtr)%8))) {
            if (foundMask[(*indexPtr)/8] & 1<<((*indexPtr)%8)) {
                return *indexPtr;
            } else {
                foundMask[(*indexPtr)/8] |= 1<<((*indexPtr)%8);
            }
        }
        indexPtr++;
    }

    return *indexPtr;
}

int
cipherSelectLanguage(const char *language)
{
    return 1;
}

char *
cipherGetLanguage(int language)
{
    return "english";
}
