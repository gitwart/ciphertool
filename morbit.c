/*
 * morbit.c --
 *
 *	This file implements the morbit cipher type.
 *	The morbit cipher has 9!, or 362880 possible combinations.
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

#include <tcl.h>
#include <string.h>
#include <morse.h>
#include <cipher.h>
#include <score.h>
#include <perm.h>

#include <cipherDebug.h>

static int  CreateMorbit	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
static char *GetMorbit		_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetMorbit		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestoreMorbit	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolveMorbit		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
int MorbitCmd			_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));
static int MorbitUndo		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int MorbitSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int MorbitLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static char *MorbitToMorse 	_ANSI_ARGS_((CipherItem *, const char *));
static int MorbitStringToKeyElem _ANSI_ARGS_((const char *));
static char *MorbitKeyElemToString _ANSI_ARGS_((int));
int MorbitSolveValue		_ANSI_ARGS_((Tcl_Interp *, ClientData,
	    			int *, int));
static int EncodeMorbit		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));

static char morbit_key_elems[10][3] = {"  ", "..", ".-", ".x", "-.", "--", "-x", "x.", "x-", "xx"};

typedef struct MorbitItem {
    CipherItem header;

    char key[9];
    int	histogram[9];

    char maxSolKey[10];
    double maxSolVal;
    long solValidCount;
    char *solPt;
} MorbitItem;

CipherType MorbitType = {
    "morbit",
    ONETONINE,
    sizeof(MorbitItem),
    CreateMorbit,	/* create proc */
    DeleteCipher,	/* delete proc */
    MorbitCmd,		/* cipher command proc */
    GetMorbit,		/* get ciphertext proc */
    SetMorbit,		/* set ciphertext proc */
    SolveMorbit,	/* solve cipher proc */
    RestoreMorbit,	/* restore proc */
    MorbitLocateTip,	/* locate proc */
    MorbitSubstitute,	/* sub proc */
    MorbitUndo,		/* undo proc */
    EncodeMorbit,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

static int
CreateMorbit(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    MorbitItem *morPtr = (MorbitItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    morPtr->header.period = 0;
    morPtr->solPt = (char *)NULL;
    for(i=0; i < 9; i++) {
	morPtr->key[i] = '\0';
	morPtr->histogram[i] = 0;
	morPtr->maxSolKey[i] = '\0';
    }

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, MorbitCmd, itemPtr,
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

static int
SetMorbit(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
{
    MorbitItem *morPtr = (MorbitItem *)itemPtr;
    char	*c=(char *)NULL;
    int		length=0;
    int		i,
    		val;

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    /*
     * Count the number of valid characters
     */

    length = CountValidChars(itemPtr, ctext, (int *)NULL);
    if (!length) {
	Tcl_SetResult(interp, "No valid characters found in the ciphertext",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (itemPtr->ciphertext) {
	ckfree(itemPtr->ciphertext);
    }

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    /*
     * Generate the histogram
     */

    for(i=0; i < 9; i++) {
	morPtr->histogram[i] = 0;
    }

    c = ExtractValidChars(itemPtr, ctext);

    if (!c) {
	Tcl_SetResult(interp, "Could not extract ciphertext from string",
		TCL_STATIC);
	return TCL_ERROR;
    }

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    itemPtr->ciphertext = c;
    itemPtr->length = strlen(c);

    for(i=0; i < itemPtr->length; i++) {
	val = itemPtr->ciphertext[i] - '1';

	if (val < 0 || val > 9) {
	    fprintf(stderr, "Bad character in ciphertext:  %c\n", 
		    itemPtr->ciphertext[i]);
	    abort();
	}
	morPtr->histogram[val]++;
    }

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    Tcl_SetResult(interp, itemPtr->ciphertext, TCL_VOLATILE);

    return TCL_OK;
}

/*
 * Fix me
 */

static int
MorbitLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, const char *tip, const char *start)
{
    Tcl_SetResult(interp, "No locate tip function defined for morbit ciphers.",
	    TCL_STATIC);
    return TCL_ERROR;
}

static int
MorbitUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int dummy)
{
    MorbitItem *morPtr = (MorbitItem *)itemPtr;
    int		i;

    if (ct == (char *)NULL) {
	for(i=0; i < 9; i++) {
	    morPtr->key[i] = '\0';
	}

	return TCL_OK;
    }

    for(i=0; i < strlen(ct); i++) {
	if (IsValidChar(itemPtr, ct[i])) {
	    morPtr->key[ct[i]-'1'] = '\0';
	}
    }

    return TCL_OK;
}

/*
 * Fix me
 * Add check to make sure the same morse pattern isn't used twice
 */

static int
MorbitSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, const char *pt, int dummy)
{
    MorbitItem *morPtr = (MorbitItem *)itemPtr;
    const char	*p;
    char	q[30];
    int		e;
    char	f;
    char	key[10];
    int		valid_sub = NEW_SUB;
    int		i;
    int		qcount=0;
    int		index_used[10];
    int		keyval_used[10];


    for(i=0;i<10;i++) {
	key[i] = '\0';
	index_used[i] = 0;
	keyval_used[i] = 0;
    }

    /*
     * Store the substitution in the temporary key.  Look for bad
     * substitutions.
     */ 

    for(p=pt; *p; p++) {
	if (*p != SPACE && *p != DASH && *p != DOT && *p != BLANK) {
	    Tcl_SetResult(interp, "Bad character in substitution morsetext",
		    TCL_STATIC);
	    return BAD_SUB;
	}
    }
    for(p=ct; *p; p++) {
	if ((*p - '1' < 0 || *p - '1' > 8) && *p != ' ' ) {
	    Tcl_SetResult(interp, "Bad character in substitution ciphertext",
		    TCL_STATIC);
	    return BAD_SUB;
	}
    }
    if (strlen(pt) %2 != 0) {
	Tcl_SetResult(interp, "Plaintext length must be an even number of characters", TCL_STATIC);
	return BAD_SUB;
    }
    if (strlen(pt) /2 != strlen(ct)) {
	Tcl_SetResult(interp, "Plaintext and ciphertext don't match in length (pt = 2 * ct)", TCL_STATIC);
	return BAD_SUB;
    }
    
    p = pt;
    for(i=0, p=pt; i < strlen(ct) && *p && valid_sub != BAD_SUB; i++, p+=2) {
	if (ct[i] != ' ') {
	    e = ct[i] - '1';
	    f = MorbitStringToKeyElem(p);

	    if (key[e] && key[e] != f) {
		/* This ciphertext character already has a value.
		 */
		valid_sub = BAD_SUB;
	    } else if (keyval_used[(int)f] && key[e] != f) {
		/* This value already belongs to a different ciphertext letter.
		 */
		valid_sub = BAD_SUB;
	    } else {
		key[e] = f;
		index_used[e] = 1;
		keyval_used[(int)f] = 1;
	    }
	}
    }

    if (valid_sub == BAD_SUB) {
	Tcl_SetResult(interp, "Bad substitution", TCL_STATIC);
	return BAD_SUB;
    }

    /*
     * Look for "alternate" substitutions
     */

    q[0] = '\0';
    p = pt;
    for(i=0, p=pt; i < strlen(ct) && *p && valid_sub != BAD_SUB; i++, p+=2) {
	if (ct[i] != ' ') {
	    e = ct[i]-'1';

	    if (morPtr->key[e] && morPtr->key[e] != key[e]) {
		valid_sub = ALT_SUB;
		if (! index_used[e]) {
		    sprintf(q+qcount*3, "%2d ", (int)e);
		    q[qcount*3 + 1] = '\0';
		    qcount++;
		}
	    }

	    index_used[e] = 1;
	}
    }

    /*
     * Store the ciphertext and the plaintext in the interpreter result
     */

    for(i=0; i < 9; i++) {
	if (index_used[i]) {
	    morPtr->key[i] = key[i];
	}
    }

    Tcl_ResetResult(interp);
    Tcl_AppendElement(interp, ct);
    Tcl_AppendElement(interp, pt);

    return valid_sub;
}

static char *
MorbitToMorse(CipherItem *itemPtr, const char *key)
{
    MorbitItem *morPtr = (MorbitItem *)itemPtr;
    char	*mt=(char *)ckalloc(sizeof(char) * itemPtr->length * 2 + 1);
    char	*t;
    int		i, j;

    if (!key) {
	key = morPtr->key;
    }

    for(i=0; i < itemPtr->length; i++) {
	j = itemPtr->ciphertext[i] - '1';
	t = MorbitKeyElemToString(key[j]);

	if (t) {
	    mt[i*2] = t[0];
	    mt[i*2+1] = t[1];
	} else {
	    mt[i*2] = ' ';
	    mt[i*2+1] = ' ';
	}
    }

    mt[i*2] = '\0';

    return mt;
}

static char *
GetMorbit(Tcl_Interp *interp, CipherItem *itemPtr)
{
    char	*mt;
    char	*pt=(char *)NULL;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp, "Can't do anything until ciphertext has been set",
		TCL_STATIC);
	return (char *)NULL;
    }
    
    pt = (char *)ckalloc(sizeof(char) * itemPtr->length + 1);
    mt = MorbitToMorse(itemPtr, (char *)NULL);

    if (MorseStringToString(mt, pt) == NULL) {
	Tcl_SetResult(interp, "Error converting morse string", TCL_STATIC);
	ckfree(mt);
	ckfree(pt);
	return (char *)NULL;
    }

    ckfree(mt);

    return pt;
}

static char *
GetSpaceyMorbit(Tcl_Interp *interp, CipherItem *itemPtr)
{
    char	*mt;
    char	*pt=(char *)ckalloc(sizeof(char) * itemPtr->length * 2 + 2);

    mt = MorbitToMorse(itemPtr, (char *)NULL);

    if (MorseStringToSpaceyString(mt, pt) == NULL) {
	ckfree(mt);
	ckfree(pt);
	Tcl_SetResult(interp, "Error converting morse string", TCL_STATIC);
	return (char *)NULL;
    }

    ckfree(mt);

    return pt;
}

static int
RestoreMorbit(Tcl_Interp *interp, CipherItem *itemPtr, const char *part1, const char *part2)
{
    if( (itemPtr->typePtr->subProc)(interp, itemPtr, part1, part2, 0) == BAD_SUB) {
	return TCL_ERROR;
    }

    return TCL_OK;
}


/*
 * Solve a Morbit cipher by stepping through all 9! possible keys
 * and looking for the best digram values.
 */

static int
SolveMorbit(Tcl_Interp *interp, CipherItem *itemPtr, char *maxkey)
{
    MorbitItem *morPtr = (MorbitItem *)itemPtr;
    int		i;
    int		result;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp, "Can't do anything until ciphertext has been set",
		TCL_STATIC);
	return TCL_ERROR;
    }

    morPtr->maxSolVal = 0.0;
    itemPtr->curIteration = 0;
    morPtr->solValidCount = 0;
    for(i=0; i < 9; i++) {
	morPtr->maxSolKey[i] = '\0';
    }
    if (morPtr->solPt) {
	ckfree(morPtr->solPt);
    }

    morPtr->solPt = (char *)ckalloc(sizeof(char) * itemPtr->length+2);

    result = _internalDoPermCmd((ClientData)itemPtr, interp, 9, MorbitSolveValue);

    if (result == TCL_OK) {
	for(i=0; i < 9; i++) {
	    morPtr->key[i] = morPtr->maxSolKey[i];
	    maxkey[i] = morPtr->maxSolKey[i];
	}
    }

    ckfree(morPtr->solPt);
    morPtr->solPt = (char *)NULL;

    return result;
}

int
MorbitSolveValue(Tcl_Interp *interp, ClientData clientData, int *key, int length)
{
    MorbitItem *morPtr = (MorbitItem *)clientData;
    CipherItem *itemPtr = (CipherItem *)clientData;
    int i;
    double val;
    char mKey[9];
    char *mt=(char *)NULL;
    Tcl_DString dsPtr;

    for(i=0; i < 9; i++) {
	mKey[i] = key[i]+1;
    }

    mt = MorbitToMorse(itemPtr, mKey);

    itemPtr->curIteration++;
    if (mt && itemPtr->stepInterval && itemPtr->stepCommand && itemPtr->curIteration%itemPtr->stepInterval == 0) {
	/*
	fprintf(stderr, "Iteration %ld/%ld (%ld)\n",
		itemPtr->curIteration,
		9*8*7*6*5*4*3*2,
		morPtr->solValidCount);
	*/
	char temp_str[128];

	Tcl_DStringInit(&dsPtr);

	Tcl_DStringAppendElement(&dsPtr, itemPtr->stepCommand);

	sprintf(temp_str, "%ld", itemPtr->curIteration);
	Tcl_DStringAppendElement(&dsPtr, temp_str);

	Tcl_DStringStartSublist(&dsPtr);
	for(i=0; i < 9; i++) {
	    sprintf(temp_str, "%d", key[i]);
	    Tcl_DStringAppendElement(&dsPtr, temp_str);
	}
	Tcl_DStringEndSublist(&dsPtr);

	Tcl_DStringAppendElement(&dsPtr, mt);

	if (Tcl_Eval(interp, Tcl_DStringValue(&dsPtr)) != TCL_OK) {
	    Tcl_ResetResult(interp);
	    Tcl_AppendResult(interp, "Bad command usage:  ", Tcl_DStringValue(&dsPtr), (char *)NULL);
	    Tcl_DStringFree(&dsPtr);
	    return TCL_ERROR;
	}
	Tcl_DStringFree(&dsPtr);
    }

    if (mt && MorseValid(mt)) {
	morPtr->solValidCount++;
	if (MorseStringToString(mt, morPtr->solPt) != NULL) {
	    if (DefaultScoreValue(interp, morPtr->solPt, &val) != TCL_OK) {
		return TCL_ERROR;
	    }
	    if (val > morPtr->maxSolVal) {
		char temp_str[128];

		Tcl_DStringInit(&dsPtr);

		if (itemPtr->bestFitCommand) {
		    Tcl_DStringAppendElement(&dsPtr, itemPtr->bestFitCommand);
		}

		sprintf(temp_str, "%ld", itemPtr->curIteration);
		Tcl_DStringAppendElement(&dsPtr, temp_str);

		morPtr->maxSolVal = val;
		for(i=0; i < 9; i++) {
		    morPtr->maxSolKey[i] = mKey[i];
		}

		/*
		printf("Key:  ");
		for(i=0; i < 9; i++)
		    printf("%s ", morbit_key_elems[mKey[i]]);
		printf("\n      ");
		for(i=0; i < 9; i++)
		    printf("%2d ", i);
		printf("%s\n\n", morPtr->solPt);
		fflush(stdout);
		*/

		Tcl_DStringStartSublist(&dsPtr);
		for(i=0; i < 9; i++) {
		    sprintf(temp_str, "%d", key[i]+1);
		    Tcl_DStringAppendElement(&dsPtr, temp_str);
		}
		Tcl_DStringEndSublist(&dsPtr);

		sprintf(temp_str, "%g", val);
		Tcl_DStringAppendElement(&dsPtr, temp_str);

		Tcl_DStringAppendElement(&dsPtr, morPtr->solPt);

		if (itemPtr->bestFitCommand) {
		    if (Tcl_Eval(interp, Tcl_DStringValue(&dsPtr)) != TCL_OK) {
			Tcl_ResetResult(interp);
			Tcl_AppendResult(interp, "Bad command usage:  ",
				Tcl_DStringValue(&dsPtr), (char *)NULL);

			Tcl_DStringFree(&dsPtr);
			return TCL_ERROR;
		    }
		}

		Tcl_DStringFree(&dsPtr);
	    }
	}
    }
    if (mt) {
	ckfree(mt);
    }

    return TCL_OK;
}

static int
MorbitStringToKeyElem(const char *string)
{
    char c1, c2;
    int value=0;

    c1 = string[0];
    c2 = string[1];

    if (c1 == DOT) {
	value += 0;
    } else if (c1 == DASH) {
	value += 3;
    } else if (c1 == SPACE) {
	value += 6;
    } else {
	return 0;
    }

    if (c2 == DOT) {
	value += 1;
    } else if (c2 == DASH) {
	value += 2;
    } else if (c2 == SPACE) {
	value += 3;
    } else {
	return 0;
    }

    return value;
}

static char *
MorbitKeyElemToString(int val) {
    if (val < 1 || val > 9) {
	return (char *)NULL;
    }

    return morbit_key_elems[val];
}

/*
 * The key should be a permutation of the digits between 1 to 9.
 * Plaintext should be a string that is convertible to morse code.
 * Output ciphertext will be a string of digits between 1 and 9.
 */

static int
EncodeMorbit (Tcl_Interp *interp, CipherItem *itemPtr, const char *pt, const char *key) {

    int ct_length;
    char *mt = (char *) NULL;
    char *ct = (char *) NULL;
    char spacestring[] = {SPACE, '\0'};

    char morbit_key[19]; /* 2*9+1 == 19 */
    char permutation[9];
    char inverse[9];
    int i;
#define KEY_COMPLAINT "The key should be a permutation of the digits between 1 and 9."

    if (!pt) {
	Tcl_SetResult(interp, "Bad pt pointer.", TCL_STATIC);
	return TCL_ERROR;
    }
    if (!key) {
	Tcl_SetResult(interp, "Bad key pointer.", TCL_STATIC);
	return TCL_ERROR;
    }
    if (!strlen(pt)) {
	Tcl_SetResult(interp, "Can't encode empty plaintext.", TCL_STATIC);
	return TCL_ERROR;
    }
    if (strlen(key) != 9) {
	Tcl_SetResult(interp, KEY_COMPLAINT, TCL_STATIC);
	return TCL_ERROR;
    }

    for (i=0; i<9; i++) {
	inverse[i] = -1;
    }
    for (i=0; i<9; i++) {
	if (key[i] < '1' || key[i] > '9') {
	    Tcl_SetResult(interp, KEY_COMPLAINT, TCL_STATIC);
	    return TCL_ERROR;
	}
	if (inverse[key[i] - '1'] != -1) {
	    Tcl_SetResult(interp, KEY_COMPLAINT, TCL_STATIC);
	    return TCL_ERROR;
	}
	inverse[key[i] - '1'] = i;
	permutation[i] = key[i] - '1';
    }

    /* 
     * Set up the internal key.
     * the format for morbit_key was determined by looking at the test cases.
     */
    for (i=0; i<9; i++) {
	strcpy(morbit_key + i*2, morbit_key_elems[inverse[i] + 1]);
    }
    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, "123456789", morbit_key)) {
	return TCL_ERROR;
    }

    /* 
     * Make the morse string.
     * Enough space is allocated by StringToMorse that we don't have to worry.
     * We do need to free it though.
     * Pad it with SPACEs until it is a multiple of 2.
     * Make sure the morse text is valid.
     */
    mt = StringToMorse(pt);
    while (strlen(mt) % 2) {
	strcat(mt, spacestring);
    }
    if (!MorseValid(mt)) {
	Tcl_SetResult(interp, "Invalid morse text.", TCL_STATIC);
	free(mt);
	return TCL_ERROR;
    }

    /*
     * The ciphertext is 1/2 the length of the morse text.
     * Do the encryption using the 9 element permutation and the morse text.
     * Free the morse text.
     */
    ct_length = strlen(mt) / 2;
    ct = (char *)ckalloc(sizeof(char) * ct_length + 1);
    for (i=0; i<ct_length; i++) {
	ct[i] = permutation[MorbitStringToKeyElem(mt + i*2) - 1] + '1';
    }
    ct[ct_length] = 0;
    free(mt);

    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, ct) != TCL_OK) {
	ckfree(ct);
	return TCL_ERROR;
    }
    
    Tcl_SetResult(interp, ct, TCL_VOLATILE);
    
    ckfree(ct);

    return TCL_OK;
    
}

int
MorbitCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    MorbitItem *morPtr = (MorbitItem *)clientData;
    CipherItem	*itemPtr = (CipherItem *)clientData;
    char	temp_str[1024];
    const char	*cmd;
    char	*tPtr=(char *)NULL;
    int		i;

    cmd = *argv;

    argv++, argc--;

    if (argc == 0) {
	Tcl_AppendResult(interp, "Usage:  ", cmd, " ?option?", (char *)NULL);
	return TCL_ERROR;
    }

    if (**argv == 'c' && (strncmp(*argv, "cget", 2) == 0)) {
	if (argc != 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " cget option",
		    (char *)NULL);
	    return TCL_ERROR;
	} else if (strncmp(argv[1], "-length", 6) == 0) {
	    sprintf(temp_str, "%d", morPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", morPtr->header.period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (itemPtr->ciphertext) {
		Tcl_SetResult(interp, itemPtr->ciphertext, TCL_VOLATILE);
	    } else {
		Tcl_SetResult(interp, "{}", TCL_STATIC);
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-plaintext", 9) == 0 ||
		   strncmp(argv[1], "-ptext", 3) == 0) {
	    tPtr = ((itemPtr->typePtr->decipherProc)(interp, itemPtr));

	    if (!tPtr) {
		return TCL_ERROR;
	    }

	    Tcl_SetResult(interp, tPtr, TCL_DYNAMIC);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-morsetext", 9) == 0 ||
		   strncmp(argv[1], "-mtext", 3) == 0) {
	    tPtr = MorbitToMorse(itemPtr, (char *)NULL);

	    if (!tPtr) {
		return TCL_ERROR;
	    }

	    Tcl_SetResult(interp, tPtr, TCL_VOLATILE);
	    ckfree(tPtr);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-fullplaintext", 13) == 0 ||
		   strncmp(argv[1], "-fullptext", 7) == 0) {
	    tPtr = GetSpaceyMorbit(interp, itemPtr);
	    Tcl_SetResult(interp, tPtr, TCL_DYNAMIC);

	    return TCL_OK;
	} else if (strncmp(argv[1], "-keyword", 8) == 0) {
	    int j;

	    for(i=0; i < 9; i++) {
		temp_str[i] = ' ';
		for (j=1 ; j <= 9; j++) {
		    if (morPtr->key[i] == j) {
			temp_str[i] = j + '0';
		    }
		}
	    }
	    temp_str[i] = '\0';

	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-key", 4) == 0) {
	    for(i=0; i < 9; i++) {
		if (morPtr->key[i]) {
		    temp_str[i*2] = morbit_key_elems[(int)(morPtr->key[i])][0];
		    temp_str[i*2+1] = morbit_key_elems[(int)(morPtr->key[i])][1];
		} else {
		    temp_str[i*2] = temp_str[i*2+1] = ' ';
		}
	    }
	    temp_str[i*2] = '\0';

	    Tcl_AppendElement(interp, "123456789");
	    Tcl_AppendElement(interp, temp_str);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-stepinterval", 6) == 0) {
	    sprintf(temp_str, "%ld", itemPtr->stepInterval);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-stepcommand", 6) == 0) {
	    if (itemPtr->stepCommand) {
		Tcl_SetResult(interp, itemPtr->stepCommand, TCL_VOLATILE);
	    } else {
		Tcl_SetResult(interp, "", TCL_STATIC);
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-bestfitcommand", 6) == 0) {
	    if (itemPtr->bestFitCommand) {
		Tcl_SetResult(interp, itemPtr->bestFitCommand, TCL_VOLATILE);
	    } else {
		Tcl_SetResult(interp, "", TCL_STATIC);
	    }
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
	    Tcl_AppendResult(interp, "Usage:  ", cmd,
		    " configure ?option value?", (char *)NULL);
	    return TCL_ERROR;
	}
	argc--, argv++;
	while(argc > 0) {
	    if (strncmp(*argv, "-stepinterval", 12) == 0) {
		if (argc < 2) {
		    Tcl_AppendResult(interp, "Usage:  ", cmd,
			    " configure -stepinterval val", (char *)NULL);
		    return TCL_ERROR;
		}

		if (sscanf(argv[1], "%d", &i) != 1) {
		    Tcl_SetResult(interp, "Invalid interval.", TCL_STATIC);
		    return TCL_ERROR;
		}

		if (i < 0 ) {
		    Tcl_SetResult(interp, "Invalid interval.", TCL_STATIC);
		    return TCL_ERROR;
		}

		itemPtr->stepInterval = i;
	    } else if (strncmp(*argv, "-ciphertext", 10) == 0 ||
		strncmp(*argv, "-ctext", 3) == 0) {
		if ((itemPtr->typePtr->setctProc)(interp, itemPtr, argv[1]) != TCL_OK) {
		    return TCL_ERROR;
		}
	    } else if (strncmp(*argv, "-bestfitcommand", 14) == 0) {
		if (argc < 2) {
		    Tcl_AppendResult(interp, "Usage:  ", cmd,
			    " configure -bestfitcommand cmd", (char *)NULL);
		    return TCL_ERROR;
		}

		if (CipherSetBestFitCmd(itemPtr, argv[1]) != TCL_OK) {
		    return TCL_ERROR;
		}
	    } else if (strncmp(*argv, "-stepcommand", 14) == 0) {
		if (argc < 2) {
		    Tcl_AppendResult(interp, "Usage:  ", cmd,
			    " configure -stepcommand cmd", (char *)NULL);
		    return TCL_ERROR;
		}

		if (CipherSetStepCmd(itemPtr, argv[1]) != TCL_OK) {
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
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " restore ct mt",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	return (itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1],
	       	argv[2]);
    } else if (**argv == 's' && (strncmp(*argv, "substitute", 2) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " substitute ct mt",
		    (char *)NULL);
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
	if (argc == 1) {
	    (itemPtr->typePtr->undoProc)(interp, itemPtr, (char *)NULL, 0);
	} else if (argc == 2) {
	    (itemPtr->typePtr->undoProc)(interp, itemPtr, argv[1], 0);
	    Tcl_SetResult(interp, "", TCL_STATIC);
	    return TCL_OK;
	} else {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " undo ?ct?",
		    (char *)NULL);
	    return TCL_ERROR;
	}
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
			" solve", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" substitute ct mt", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" restore ct mt", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" locate pt", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" undo ?ct?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" encode pt key", (char *)NULL);
	return TCL_ERROR;
    }

    return TCL_OK;
}
