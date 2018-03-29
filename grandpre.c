/*
 * grandpre.c --
 *
 *	This file implements the grandpre cipher type.
 *
 * Copyright (c) 1999-2004 Michael Thomas <wart@kobold.org>
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

#include <tcl.h>
#include <string.h>
#include <cipher.h>

#include <cipherDebug.h>

static int  CreateGrandpre	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
void DeleteGrandpre		_ANSI_ARGS_((ClientData));
static char *GetGrandpre	_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetGrandpre	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestoreGrandpre	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolveGrandpre	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
int GrandpreCmd		_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));
static int GrandpreUndo	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int GrandpreSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int GrandpreLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int EncodeGrandpre _ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));

typedef struct GrandpreItem {
    CipherItem header;

    int *int_ct;
    int int_ct_length;
    char *prv_ciphertext;   /* Ciphertext with invalid characters removed */

    char key[8][8];
    int histogram[8][8];
} GrandpreItem;

CipherType GrandpreType = {
    "grandpre",
    "12345678",
    sizeof(GrandpreItem),
    CreateGrandpre,	/* create proc */
    DeleteGrandpre,	/* delete proc */
    GrandpreCmd,	/* cipher command proc */
    GetGrandpre,	/* get ciphertext proc */
    SetGrandpre,	/* set ciphertext proc */
    SolveGrandpre,	/* solve cipher proc */
    RestoreGrandpre,	/* restore proc */
    GrandpreLocateTip,	/* locate proc */
    GrandpreSubstitute,	/* sub proc */
    GrandpreUndo,	/* undo proc */
    EncodeGrandpre,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

static int
CreateGrandpre(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    GrandpreItem *grandPtr = (GrandpreItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString dsPtr;
    int		i, j;

    grandPtr->header.period=0;
    grandPtr->int_ct_length=0;
    grandPtr->prv_ciphertext=(char *)NULL;
    grandPtr->int_ct = (int *)NULL;
    for(i=0; i < 8; i++) {
	for(j=0; j < 8; j++) {
	    grandPtr->key[i][j] = '\0';
	    grandPtr->histogram[i][j] = 0;
	}
    }

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, GrandpreCmd, itemPtr,
	    itemPtr->typePtr->deleteProc);
    if (argc) {
	if (Tcl_Eval(interp, Tcl_DStringValue(&dsPtr)) != TCL_OK) {
	    Tcl_DeleteCommand(interp, temp_ptr);
	    Tcl_DStringFree(&dsPtr);
	    return TCL_ERROR;
	}
    }
    Tcl_SetResult(interp, temp_ptr, TCL_VOLATILE);
    Tcl_DStringFree(&dsPtr);
    return TCL_OK;
}

void
DeleteGrandpre(ClientData clientData)
{
    GrandpreItem *grandPtr = (GrandpreItem *)clientData;

    if (grandPtr->prv_ciphertext != NULL) {
	ckfree(grandPtr->prv_ciphertext);
    }

    if (grandPtr->int_ct != NULL) {
	ckfree((char *)(grandPtr->int_ct));
    }

    DeleteCipher(clientData);
}

static int
SetGrandpre(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
{
    GrandpreItem *grandPtr = (GrandpreItem *)itemPtr;
    const char	*c=(char *)NULL;
    int		valid = TCL_OK,
    		length=0;
    int		count=0;
    int		i, j,
    		row, col;

    c = ctext;

    /*
     * Count the number of valid characters
     */

    length = CountValidChars(itemPtr, ctext);
    if (!length) {
	Tcl_SetResult(interp, "No valid characters found in ciphertext", TCL_VOLATILE);
	return TCL_ERROR;
    }
    if (length%2) {
	Tcl_SetResult(interp, "Odd number of valid characters found in ciphertext.", TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (itemPtr->ciphertext) {
	ckfree(itemPtr->ciphertext);
    }
    itemPtr->ciphertext = (char *)NULL;

    if (grandPtr->prv_ciphertext) {
	ckfree(grandPtr->prv_ciphertext);
    }
    grandPtr->prv_ciphertext = '\0';

    if (grandPtr->int_ct) {
	ckfree((char *)(grandPtr->int_ct));
    }
    grandPtr->prv_ciphertext = '\0';

    grandPtr->prv_ciphertext = ExtractValidChars(itemPtr, ctext);
    grandPtr->int_ct = TextToInt(interp, itemPtr, ctext, &count, "%2d", 2);
    grandPtr->int_ct_length = count;

    /*
     * Generate the histogram
     */

    for(i=0; i < 8; i++) {
	for(j=0; j < 8; j++) {
	    grandPtr->histogram[i][j] = 0;
	}
    }

    for(i=0; i < grandPtr->int_ct_length; i++) {
	col = grandPtr->int_ct[i]/10 - 1;
	row = grandPtr->int_ct[i]%10 - 1;

	/*
	 * The utility function TextToInt doesn't screen for 9's or 0's.
	 * Do that here.
	 */

	if (col < 0 || col > 7 || row < 0 || row > 7) {
	    Tcl_SetResult(interp, "Invalid characters in ciphertext.", 
		    TCL_STATIC);
	    return TCL_ERROR;
	}

	grandPtr->histogram[col][row]++;
    }

    /*
     * Ick!  The length should match what we see when we use cget -ct.
     * itemPtr->length = strlen(ctext);
     * itemPtr->length = strlen(grandPtr->prv_ciphertext);
     */
    itemPtr->length = strlen(ctext);

    c = (char *)ckalloc(sizeof(char) * itemPtr->length + 1);
    strcpy(c, ctext);

    itemPtr->ciphertext = c;

    return valid;
}

static int
GrandpreLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, const char *tip, const char *start)
{
    GrandpreItem *grandPtr = (GrandpreItem *)itemPtr;
    int		valid_tip=0, valid_start=0, start_location=0,
    		startCount;
    int		*startPtr;
    int		i, j, k, m;
    char	key[8][8];
    int		row, col;

    for(i=0; i < 8; i++) {
	for(j=0; j < 8; j++) {
	    key[i][j] = '\0';
	}
    }

    /*
     * Find the starting location
     */

    if (start) {
	startPtr = TextToInt(interp, itemPtr, start, &startCount, "%2d", 2);

	valid_start=0;
	for(i=0; i < grandPtr->int_ct_length - startCount && !valid_start; i++) {
	    start_location = i;
	    valid_start=1;
	    for(j=0; j < startCount; j++) {
		if (grandPtr->int_ct[i+j] != startPtr[j]) {
		    valid_start=0;
		}
	    }
	}

	if (startPtr) {
	    ckfree((char *)startPtr);
	}
	if (!valid_start) {
	    Tcl_SetResult(interp, "Invalid starting position", TCL_VOLATILE);
	    return TCL_ERROR;
	}
    } else {
	/*
	 * No start position was specified so start at the beginning
	 */
	valid_start=0;
    }

    /*
     * start_location is the offset from the start of the ciphertext where
     * the starting location was found.
     *
     * Start at this starting location and try to match the tip.
     */

    valid_tip=0;
    for(i=start_location; i < grandPtr->int_ct_length - strlen(tip) && !valid_tip; i++) {

	/*
	 * Reset the key for the next possible tip location
	 */

	for(k=0; k < 8; k++) {
	    for(m=0; m < 8; m++) {
		key[k][m] = '\0';
	    }
	}

	/*
	 * See if this tip gives valid substitutions
	 */

	valid_tip=1;
	for(j=0; j < strlen(tip); j++) {
	    col = grandPtr->int_ct[i+j]/10 - 1;
	    row = grandPtr->int_ct[i+j]%10 - 1;

	    if ((grandPtr->key[col][row] && grandPtr->key[col][row] != tip[j])
		||
		(key[col][row] && key[col][row] != tip[j]) ) {
		valid_tip=0;
	    } else {
		key[col][row] = tip[j];
	    }
	}
    }

    if (valid_tip) {
	/*
	 * key[][] now holds the proper key substitutions
	 */
	for(i=0; i < 8; i++) {
	    for(j=0; j < 8; j++) {
		if (key[i][j]) {
		    grandPtr->key[i][j] = key[i][j];
		}
	    }
	}
    } else {
	Tcl_SetResult(interp, "No valid tip locations found.", TCL_VOLATILE);
	return TCL_ERROR;
    }

    Tcl_SetResult(interp, tip, TCL_VOLATILE);
    return TCL_OK;
}

static int
GrandpreSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, const char *pt, int dummy)
{
    GrandpreItem *grandPtr = (GrandpreItem *)itemPtr;
    char key[8][8];
    char *p;
    int *c;
    int i, j;
    int count;
    int	*ctIntarr=(int *)NULL;
    int valid_sub=NEW_SUB, col, row;

    for(i=0;i<8;i++) {
	for(j=0;j<8;j++) {
	    key[i][j] = '\0';
	}
    }

    /*
     * Convert the ciphertext into an integer array
     */

    ctIntarr = TextToInt(interp, itemPtr, ct, &count, "%2d", 2);
    if (!ctIntarr) {
	return BAD_SUB;
    }

    /*
     * Store the substitution in the temporary key.  Look for bad
     * substitutions.
     */ 
    
    c = ctIntarr, p = pt;
    for(i=0, p=pt; i < count && *p && valid_sub != BAD_SUB; i++, p++) {
	col = c[i]/10 - 1;
	row = c[i]%10 - 1;

	if (col < 0 || col > 7 || row < 0 || row > 7) {
	    Tcl_SetResult(interp, 
		"Invalid characters in substitution.", TCL_STATIC);
	}

	if (key[col][row] && key[col][row] != *p) {
	    valid_sub = BAD_SUB;
	} else {
	    key[col][row] = *p;
	}
    }
    ckfree((char *)ctIntarr);

    if (valid_sub == BAD_SUB) {
	Tcl_SetResult(interp, "Bad Substitution", TCL_STATIC);
	return BAD_SUB;
    }

    /*
     * Look for "alternate" substitutions
     */

    for(i=0; i < 8; i++) {
	for(j=0; j < 8; j++) {
	    if (key[i][j] &&
		grandPtr->key[i][j] &&
		key[i][j]!=grandPtr->key[i][j]) {

		valid_sub=ALT_SUB;
	    }
	}
    }

    if (valid_sub == BAD_SUB) {
	Tcl_SetResult(interp, "Bad Substitution", TCL_STATIC);
	return BAD_SUB;
    }

    for(i=0; i < 8; i++) {
	for(j=0; j < 8; j++) {
	    if (key[i][j]) {
		grandPtr->key[i][j] = key[i][j];
	    }
	}
    }

    /*
     * Store the ciphertext and the plaintext in the interpreter result
     */

    Tcl_ResetResult(interp);
    Tcl_AppendElement(interp, ct);
    Tcl_AppendElement(interp, pt);

    return valid_sub;
}

static int
GrandpreUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int dummy)
{
    GrandpreItem *grandPtr = (GrandpreItem *)itemPtr;
    int	*ctIntarr=(int *)NULL;
    int count;
    int i, row, col;

    ctIntarr = TextToInt(interp, itemPtr, ct, &count, "%2d", 2);
    if (!ctIntarr) {
	return TCL_ERROR;
    }

    for(i=0; i < count; i++) {
	col = (ctIntarr[i] / 10) - 1;
	row = (ctIntarr[i] % 10) - 1;

	if (col < 0 || col > 7 || row < 0 || row > 7) {
	    Tcl_SetResult(interp, "Invalid characters in undo.", TCL_STATIC);
	}

	grandPtr->key[col][row] = '\0';
    }
    ckfree((char *)ctIntarr);

    return TCL_OK;
}

static char *
GetGrandpre(Tcl_Interp *interp, CipherItem *itemPtr)
{
    GrandpreItem *grandPtr = (GrandpreItem *)itemPtr;
    int *c, i;
    char	*pt=(char *)ckalloc(sizeof(char) * grandPtr->int_ct_length + 1);

    c = grandPtr->int_ct;

    for(i=0; i < grandPtr->int_ct_length; i++) {
	int col, row;
	/*
	 * No need to verify the values of the ciphertext here.  That was
	 * done when the ciphertext was set.
	 */

	col = grandPtr->int_ct[i]/10 - 1;
	row = grandPtr->int_ct[i]%10 - 1;

	if (grandPtr->key[col][row]) {
	    pt[i] = grandPtr->key[col][row];
	} else {
	    pt[i] = ' ';
	}
    }
    pt[i] = '\0';

    return pt;
}

static int
SolveGrandpre(Tcl_Interp *interp, CipherItem *itemPtr, char *maxkey)
{
    Tcl_SetResult(interp, "No solve method defined for grandpre types",
	    TCL_VOLATILE);
    return TCL_ERROR;
}

char *
GrandpreKeyToString(Tcl_Interp *interp, CipherItem *itemPtr)
{
    GrandpreItem *grandPtr = (GrandpreItem *)itemPtr;
    int i, j;
    Tcl_DString dsPtr;
    char *tPtr=(char *)NULL;
    char temp_word[9];
    char temp_word2[65];

    Tcl_DStringInit(&dsPtr);
    /*
    Tcl_DStringStartSublist(&dsPtr);
    */

    for(i=0; i < 8; i++) {
	for(j=0; j < 8; j++) {
	    if (grandPtr->key[i][j]) {
		temp_word[j] = grandPtr->key[i][j];
		temp_word2[8*i+j] = grandPtr->key[i][j];
	    } else {
		temp_word[j] = ' ';
		temp_word2[8*i+j] = ' ';
	    }
	}
	temp_word[j] = '\0';
	/*
	Tcl_DStringAppendElement(&dsPtr, temp_word);
	*/
    }
    temp_word2[64]='\0';
    /*
    Tcl_DStringEndSublist(&dsPtr);
    */

    tPtr = (char *)ckalloc(sizeof(char) * 65);
    strcpy(tPtr, temp_word2);
    return tPtr;
}

int
GrandpreKeyToList(Tcl_Interp *interp, CipherItem *itemPtr)
{
    GrandpreItem *grandPtr = (GrandpreItem *)itemPtr;
    int i, j;
    Tcl_DString dsPtr;
    char temp_word[9];

    Tcl_DStringInit(&dsPtr);
    /*
    Tcl_DStringStartSublist(&dsPtr);
    */

    for(i=0; i < 8; i++) {
	for(j=0; j < 8; j++) {
	    if (grandPtr->key[i][j]) {
		temp_word[j] = grandPtr->key[i][j];
	    } else {
		temp_word[j] = ' ';
	    }
	}
	temp_word[j] = '\0';
	Tcl_DStringAppendElement(&dsPtr, temp_word);
    }
    /*
    Tcl_DStringEndSublist(&dsPtr);
    */

    Tcl_DStringResult(interp, &dsPtr);

    return TCL_OK;
}

static int
RestoreGrandpre(Tcl_Interp *interp, CipherItem *itemPtr, const char *part1, const char *part2)
{
    GrandpreItem *grandPtr = (GrandpreItem *)itemPtr;
    int i, j;

    if (strlen(part1) != 64) {
	Tcl_Obj *intObj = Tcl_NewIntObj(strlen(part1));
	Tcl_AppendResult(interp,
		"Restoration key must be 64 letters long.  Found ",
		Tcl_GetString(intObj), ".", (char *)NULL);
	Tcl_DecrRefCount(intObj);
	return TCL_ERROR;
    }

    for(i=0; i < 8; i++) {
	for(j=0; j < 8; j++) {
	    int charIndex = i*8 + j;
	    if (part1[charIndex] == ' ') {
		grandPtr->key[i][j]='\0';
	    } else if (part1[charIndex] >= 'a' && part1[charIndex] <= 'z') {
		grandPtr->key[i][j]=part1[charIndex];
	    } else {
		char temp_str[2];
		temp_str[0] = part1[charIndex];
		temp_str[1] = '\0';
		Tcl_AppendResult(interp, "Invalid character found in key: '",
			temp_str, "'.", (char *)NULL);
		return TCL_ERROR;
	    }
	}
    }
	    
    return TCL_OK;
}

static int
EncodeGrandpre(Tcl_Interp *interp, CipherItem *itemPtr, const char *pt, const char *key)
{
    int i, row, col;
    char *ct;
    int nct=0;
    char indexPool[26][64];
    char c;
    int nPool[26];
    int n = strlen(pt);
    char errstr[1000];

    /*
     * Restore the key.
     * This checks for basic key errors.
     */
    if (RestoreGrandpre(interp, itemPtr, key, (char *)0) != TCL_OK) {
	return TCL_ERROR;
    }

    /* Get the pool of possible translations for each letter. */
    for (i=0; i<26; i++) {
	nPool[i] = 0;
    }
    for (row=0; row<8; row++) {
	for (col=0; col<8; col++) {
	    c = key[row*8 + col];
	    indexPool[c-'a'][nPool[c-'a']++] = (row+1)*10 + (col+1);
	}
    }

    /* Make sure that all letters are represented. */
    for (i=0; i<26; i++) {
	if (!nPool[i]) {
	    sprintf(errstr, "Letter '%c' was not found in the key.", i+'a');
	    Tcl_SetResult(interp, errstr, TCL_VOLATILE);
	    return TCL_ERROR;
	}
    }

    /* Randomize the timer.  Maybe there's a better solution. */
    srand(time(0));

    /* Convert the lowercase letters of the plaintext to ciphertext numbers. */
    ct = (char *) ckalloc(sizeof(char) * 2*n + 1);
    for (i=0; i<n; i++) {
	c = pt[i];
	/* Only look at lowercase letters. */
	if (!islower(c)) {
	    continue;
	}
	/* Pick a random translation from the pool. */
	sprintf(ct+nct, "%d", indexPool[c-'a'][rand()%nPool[c-'a']]);
	nct += 2;
    }

    /* Set the ciphertext. */
    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, ct) != TCL_OK) {
	ckfree(ct);
	return TCL_ERROR;
    }
    
    Tcl_SetResult(interp, ct, TCL_VOLATILE);
    
    ckfree(ct);
	    
    return TCL_OK;
}

int
GrandpreCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    GrandpreItem *grandPtr = (GrandpreItem *)clientData;
    CipherItem	*itemPtr = (CipherItem *)clientData;
    char	temp_str[1024];
    const char	*cmd;
    char	*tPtr=(char *)NULL;
    Tcl_DString dsPtr;

    cmd = *argv;

    argv++, argc--;

    if (argc == 0) {
	Tcl_AppendResult(interp, "Usage:  ", cmd, " ?option?", (char *)NULL);
	return TCL_ERROR;
    }

    if (**argv == 'c' && (strncmp(*argv, "cget", 2) == 0)) {
	if (argc != 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " cget option", (char *)NULL);
	    return TCL_ERROR;
	} else if (strncmp(argv[1], "-length", 6) == 0) {
	    sprintf(temp_str, "%d", grandPtr->int_ct_length*2);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "0");
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-intlength", 6) == 0) {
	    sprintf(temp_str, "%d", grandPtr->int_ct_length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!grandPtr->prv_ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_VOLATILE);
	    } else {
		Tcl_SetResult(interp, grandPtr->prv_ciphertext, TCL_VOLATILE);
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-histogram", 5) == 0) {
	    /*
	     * Store the histogram in interp->result
	     */

	    return TCL_OK;
	} else if (strncmp(argv[1], "-plaintext", 9) == 0 ||
		   strncmp(argv[1], "-ptext", 3) == 0) {
	    tPtr = ((itemPtr->typePtr->decipherProc)(interp, itemPtr));

	    if (!tPtr) {
		return TCL_ERROR;
	    }

	    Tcl_SetResult(interp, tPtr, TCL_DYNAMIC);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-keylist", 5) == 0) {
	    GrandpreKeyToList(interp, itemPtr);

	    return TCL_OK;
	} else if (strncmp(argv[1], "-key", 4) == 0) {
	    Tcl_DStringInit(&dsPtr);
	    /*
	    Tcl_DStringAppendElement(&dsPtr, "11 12 13 14 15 16 17 18");
	    Tcl_DStringAppendElement(&dsPtr, "21 22 23 24 25 26 27 28");
	    Tcl_DStringAppendElement(&dsPtr, "31 32 33 34 35 36 37 38");
	    Tcl_DStringAppendElement(&dsPtr, "41 42 43 44 45 46 47 48");
	    Tcl_DStringAppendElement(&dsPtr, "51 52 53 54 55 56 57 58");
	    Tcl_DStringAppendElement(&dsPtr, "61 62 63 64 65 66 67 68");
	    Tcl_DStringAppendElement(&dsPtr, "71 72 73 74 75 76 77 78");
	    Tcl_DStringAppendElement(&dsPtr, "81 82 83 84 85 86 87 88");
	    Tcl_AppendElement(interp, Tcl_DStringValue(&dsPtr));
	    Tcl_AppendElement(interp, "11 12 13 14 15 16 17 18 21 22 23 24 25 26 27 28 31 32 33 34 35 36 37 38 41 42 43 44 45 46 47 48 51 52 53 54 55 56 57 58 61 62 63 64 65 66 67 68 71 72 73 74 75 76 77 78 81 82 83 84 85 86 87 88");
	    */

	    Tcl_ValidateAllMemory(__FILE__, __LINE__);
	    tPtr = GrandpreKeyToString(interp, itemPtr);
	    Tcl_SetResult(interp, tPtr, TCL_DYNAMIC);

	    return TCL_OK;
	} else if (strncmp(argv[1], "-type", 5) == 0) {
	    Tcl_SetResult(interp, itemPtr->typePtr->type, TCL_STATIC);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-language", 8) == 0) {
	    Tcl_SetResult(interp, cipherGetLanguage(itemPtr->language),
		    TCL_VOLATILE);
	    return TCL_OK;
	} else {
	    sprintf(temp_str, "Unknown option %s", argv[1]);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_ERROR;
	}
	return TCL_OK;
    } else if (**argv == 'c' && (strncmp(*argv, "configure", 2) == 0)) {
	if (argc < 3 || (argc%2 != 1)) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " configure ?option value?", (char *)NULL);
	    return TCL_ERROR;
	}
	argc--, argv++;
	while(argc > 0) {
	    if (strncmp(*argv, "-ciphertext", 10) == 0 ||
		strncmp(*argv, "-ctext", 3) == 0) {
		if ((itemPtr->typePtr->setctProc)(interp, itemPtr, argv[1]) != TCL_OK) {
		    return TCL_ERROR;
		}
	    } else if (strncmp(*argv, "-language", 8) == 0) {
		itemPtr->language = cipherSelectLanguage(argv[1]);
		Tcl_SetResult(interp, cipherGetLanguage(itemPtr->language),
			TCL_VOLATILE);
	    } else {
		sprintf(temp_str, "Unknown option %s", *argv);
		Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
		return TCL_ERROR;
	    }
	    argc-=2, argv+=2;
	}
	return TCL_OK;
    } else if (**argv == 'r' && (strncmp(*argv, "restore", 1) == 0)) {
	if (argc != 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " restore key", (char *)NULL);
	    return TCL_ERROR;
	}
	return (itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1], (char *) NULL);
    } else if (**argv == 's' && (strncmp(*argv, "substitute", 2) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " substitute ct pt", (char *)NULL);
	    return TCL_ERROR;
	}
	if ((itemPtr->typePtr->subProc)(interp, itemPtr, argv[1], argv[2], 0) == BAD_SUB) {
	    return TCL_ERROR;
	} else {
	    return TCL_OK;
	}
    } else if (**argv == 's' && (strncmp(*argv, "solve", 2) == 0)) {
	if ( (itemPtr->typePtr->solveProc)(interp, itemPtr, temp_str) != TCL_OK)
	    return TCL_ERROR;

	Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	return TCL_OK;
    } else if (**argv == 'u' && (strncmp(*argv, "undo", 1) == 0)) {
	if (argc != 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " undo ct", (char *)NULL);
	    return TCL_ERROR;
	}
	(itemPtr->typePtr->undoProc)(interp, itemPtr, argv[1], 0);
	Tcl_SetResult(interp, "", TCL_VOLATILE);
	return TCL_OK;
    } else if (**argv == 'l' && (strncmp(*argv, "locate", 1) == 0)) {
	if (argc < 2 || argc > 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " locate pt ct", (char *)NULL);
	    return TCL_ERROR;
	}
	if (argc == 2)
	    return (itemPtr->typePtr->locateProc)(interp, itemPtr, argv[1], (char *)NULL);
	else 
	    return (itemPtr->typePtr->locateProc)(interp, itemPtr, argv[1], argv[2]);
    } else if (**argv == 'e' && (strncmp(*argv, "encode", 1) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " encode pt key", (char *)NULL);
	    return TCL_ERROR;
	}	
	return (itemPtr->typePtr->encodeProc)(interp, itemPtr, argv[1], argv[2]);
    } else {
	Tcl_AppendResult(interp, "Unknown option ", *argv, (char *)NULL);
	Tcl_AppendResult(interp, "\nMust be one of:  ", cmd,
			" cget ?option?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" configure ?option value?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" substitute ct pt", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" restore key", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" locate pt", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" undo ct", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" encode pt key", (char *)NULL);
	return TCL_ERROR;
    }
}
