/*
 * pollux.c --
 *
 *	This file implements the pollux cipher type.
 *	The pollux cipher has 3^10, or 59049 possible
 *	combinations for the key
 *
 * Copyright (c) 1995-2004 Michael Thomas <wart@kobold.org>
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

#include <cipherDebug.h>

static int  CreatePollux	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
static char *GetPollux		_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetPollux		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestorePollux	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolvePollux		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
int PolluxCmd			_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));
static int PolluxUndo		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int PolluxSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int PolluxLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static char *PolluxToMorse 	_ANSI_ARGS_((CipherItem *itemPtr, const char *));
static int RecSolvePollux	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
	    			char *, int));
static int EncodePollux		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));


typedef struct PolluxItem {
    CipherItem header;

    char key[10];
    char maxSolKey[10];
    double maxSolVal;
    char *solPt;
    int	histogram[10];
} PolluxItem;

CipherType PolluxType = {
    "pollux",
    ZEROTONINE,
    sizeof(PolluxItem),
    CreatePollux,	/* create proc */
    DeleteCipher,	/* delete proc */
    PolluxCmd,		/* cipher command proc */
    GetPollux,		/* get ciphertext proc */
    SetPollux,		/* set ciphertext proc */
    SolvePollux,	/* solve cipher proc */
    RestorePollux,	/* restore proc */
    PolluxLocateTip,	/* locate proc */
    PolluxSubstitute,	/* sub proc */
    PolluxUndo,		/* undo proc */
    EncodePollux,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

static int
CreatePollux(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    PolluxItem *polPtr = (PolluxItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    polPtr->header.period = 0;
    polPtr->solPt = (char *)NULL;
    for(i=0; i < 10; i++) {
	polPtr->key[i] = '\0';
	polPtr->histogram[i] = 0;
    }

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++)
	Tcl_DStringAppendElement(&dsPtr, argv[i]);

    Tcl_CreateCommand(interp, temp_ptr, PolluxCmd, itemPtr,
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

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    return TCL_OK;
}

static int
SetPollux(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
{
    PolluxItem *polPtr = (PolluxItem *)itemPtr;
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
	Tcl_SetResult(interp, "No valid characters found in ciphertext", TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (itemPtr->ciphertext)
	ckfree(itemPtr->ciphertext);

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    /*
     * Generate the histogram
     */

    for(i=0; i < 10; i++)
	polPtr->histogram[i] = 0;

    c = ExtractValidChars(itemPtr, ctext);

    if (!c) {
	Tcl_SetResult(interp, "Bad ciphertext", TCL_VOLATILE);
	return TCL_ERROR;
    }

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    itemPtr->ciphertext = c;
    itemPtr->length = strlen(c);

    for(i=0; i < itemPtr->length; i++) {
	val = itemPtr->ciphertext[i] - '0';

	if (val < 0 || val > 9) {
	    fprintf(stderr, "Bad character in ciphertext:  %c\n", 
		    itemPtr->ciphertext[i]);
	    abort();
	}
	polPtr->histogram[val]++;
    }

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    Tcl_SetResult(interp, itemPtr->ciphertext, TCL_VOLATILE);

    return TCL_OK;
}

/*
 * Fix me
 */

static int
PolluxLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, const char *tip, const char *start)
{
    Tcl_SetResult(interp, "No locate tip function defined for pollux ciphers.", TCL_VOLATILE);
    return TCL_ERROR;
}

static int
PolluxUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int dummy)
{
    PolluxItem *polPtr = (PolluxItem *)itemPtr;
    int		i;

    if (ct == (char *)NULL) {
	for(i=0; i < 10; i++) {
	    polPtr->key[i] = '\0';
	}

	return TCL_OK;
    }

    for(i=0; i < strlen(ct); i++) {
	if (IsValidChar(itemPtr, ct[i])) {
	    polPtr->key[ct[i]-'0'] = '\0';
	}
    }

    return TCL_OK;
}

static int
PolluxSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, const char *pt, int dummy)
{
    PolluxItem *polPtr = (PolluxItem *)itemPtr;
    const char	*p;
    char	q[13],
		r[13];
    int		e;
    char	key[10];
    int		valid_sub = NEW_SUB;
    int		olap_sub=0, i;
    int		count=0;
    int		qcount=0,
    		rcount=0;
    int		col=0;
    int		index_used[10];

    if (strlen(pt) != strlen(ct)) {
	Tcl_SetResult(interp, "Plaintext and ciphertext must be the same length.", TCL_VOLATILE);
	return BAD_SUB;
    }

    for(i=0;i<10;i++) {
	key[i] = '\0';
	index_used[i] = 0;
    }

    /*
     * Store the substitution in the temporary key.  Look for bad
     * substitutions.
     */ 

    for(p=pt; *p; p++) {
	if (*p != SPACE && *p != DASH && *p != DOT && *p != BLANK) {
	    Tcl_SetResult(interp, "Bad character in substitution morsetext",
		    TCL_VOLATILE);
	    return BAD_SUB;
	}
    }
    for(p=ct; *p; p++) {
	if ((*p < '0' || *p > '9') && *p != ' ') {
	    Tcl_SetResult(interp, "Bad character in substitution ciphertext",
		    TCL_VOLATILE);
	    return BAD_SUB;
	}
    }
    
    p = pt;
    for(i=0, p=pt; i < strlen(ct) && *p && valid_sub != BAD_SUB; i++, p++) {
	if (ct[i] != ' ') {
	    e = ct[i] - '0';
	    if (key[e] && key[e] != *p)
		valid_sub = BAD_SUB;
	    else {
		if (*p == BLANK) {
		    key[e] = ' ';
		} else {
		    key[e] = *p;
		}
		index_used[e] = 1;
	    }
	}
    }

    if (valid_sub == BAD_SUB) {
	Tcl_SetResult(interp, "Bad substitution", TCL_VOLATILE);
	return BAD_SUB;
    }

    /*
     * Look for "alternate" substitutions
     */

    p = pt;
    for(i=0, p=pt; i < count && *p && valid_sub != BAD_SUB; i++, p++) {
	if (ct[i] != ' ') {
	    e = ct[i]-'0';

	    if (col > 3) {
		fprintf(stderr, "Ciphertext corruption error\n");
		abort();
	    }

	    if (polPtr->key[e] && polPtr->key[e] != key[e]) {
		valid_sub = ALT_SUB;
		sprintf(q+qcount*3, "%2d ", ct[i]);
		qcount++;
	    }

	    if (key[e]) {
		sprintf(r+rcount*3, "%2d ", e);
		rcount++;
	    }

	    index_used[e] = 1;
	}
    }

    if (valid_sub == BAD_SUB) {
	Tcl_SetResult(interp, "Bad Substitution", TCL_VOLATILE);
	return BAD_SUB;
    }

    /*
     * Store the ciphertext and the plaintext in the interpreter result
     */

    for(i=0; i < 10; i++) {
	if (index_used[i]) {
	    polPtr->key[i] = key[i];
	}
    }

    Tcl_ResetResult(interp);
    Tcl_AppendElement(interp, ct);
    Tcl_AppendElement(interp, pt);
    if (olap_sub) {
	Tcl_AppendElement(interp, q);
	valid_sub = ALT_SUB;
    }

    return valid_sub;
}

static char *
PolluxToMorse(CipherItem *itemPtr, const char *key)
{
    PolluxItem *polPtr = (PolluxItem *)itemPtr;
    char	*mt=(char *)ckalloc(sizeof(char) * itemPtr->length + 1);
    int		i, j;

    if (!key)
	key = polPtr->key;

    for(i=0; i < itemPtr->length; i++) {
	j = itemPtr->ciphertext[i] - '0';
	if (key[j])
	    mt[i] = key[j];
	else
	    mt[i] = ' ';
    }

    mt[i] = '\0';

    return mt;
}

static char *
GetPollux(Tcl_Interp *interp, CipherItem *itemPtr)
{
    char	*mt;
    char	*pt=(char *)NULL;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp, "Can't do anything until ciphertext has been set",
		TCL_STATIC);
	return (char *)NULL;
    }

    pt=(char *)ckalloc(sizeof(char) * itemPtr->length + 1);

    mt = PolluxToMorse(itemPtr, (const char *)NULL);
    if (MorseStringToString(mt, pt) == NULL) {
	Tcl_SetResult(interp, "Error converting morse string", TCL_STATIC);
	ckfree(pt);
	return (char *)NULL;
    }

    ckfree(mt);

    return pt;
}

static char *
GetSpaceyPollux(Tcl_Interp *interp, CipherItem *itemPtr)
{
    char	*mt;
    char	*pt=(char *)ckalloc(sizeof(char) * itemPtr->length + 2);

    mt = PolluxToMorse(itemPtr, (char *)NULL);

    if (MorseStringToSpaceyString(mt, pt) == NULL) {
	ckfree(pt);
	ckfree(mt);
	Tcl_SetResult(interp, "Error converting morse string", TCL_STATIC);
	return (char *)NULL;
    }

    ckfree(mt);

    return pt;
}

static int
RestorePollux(Tcl_Interp *interp, CipherItem *itemPtr, const char *part1, const char *part2)
{
    if ( (itemPtr->typePtr->subProc)(interp, itemPtr, part1, part2, 0) == NEW_SUB) {
	return TCL_OK;
    } else {
	return TCL_ERROR;
    }
}

/*
 * Solve a Pollux cipher by stepping through all 3^10 possible keys
 * and looking for the best digram values.
 */

static int
SolvePollux(Tcl_Interp *interp, CipherItem *itemPtr, char *maxkey)
{
    PolluxItem *polPtr = (PolluxItem *)itemPtr;
    int		i;
    char	key[10];

    for(i=0; i < 10; i++) {
	polPtr->maxSolKey[i] = '\0';
    }
    polPtr->maxSolVal=0.0;
    itemPtr->curIteration=0;
    if (polPtr->solPt) {
	ckfree(polPtr->solPt);
    }

    polPtr->solPt = (char *)ckalloc(sizeof(char)*itemPtr->length+2);

    if (RecSolvePollux(interp, itemPtr, key, 0) != TCL_OK) {
	ckfree(polPtr->solPt);
	polPtr->solPt = (char *)NULL;
	return TCL_ERROR;
    }

    for(i=0; i < 10; i++) {
	polPtr->key[i] = polPtr->maxSolKey[i];
    }

    ckfree(polPtr->solPt);
    polPtr->solPt = (char *)NULL;

    Tcl_ResetResult(interp);
    return TCL_OK;
}

static int
RecSolvePollux(Tcl_Interp *interp, CipherItem *itemPtr, char *key, int depth)
{
    PolluxItem *polPtr = (PolluxItem *)itemPtr;

    if (depth >= 10) {
	Tcl_DString dsPtr;
	int i;
	double val;
	char *mt=(char *)NULL;

	itemPtr->curIteration++;

	mt = PolluxToMorse(itemPtr, key);

	if (mt && itemPtr->stepInterval && itemPtr->stepCommand && itemPtr->curIteration%itemPtr->stepInterval == 0) {
	    char temp_str[128];

	    Tcl_DStringInit(&dsPtr);

	    Tcl_DStringAppendElement(&dsPtr, itemPtr->stepCommand);

	    sprintf(temp_str, "%ld", itemPtr->curIteration);
	    Tcl_DStringAppendElement(&dsPtr, temp_str);

	    Tcl_DStringStartSublist(&dsPtr);
	    for(i=0; i < 10; i++) {
		sprintf(temp_str, "%c", key[i]);
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
	    if (MorseStringToString(mt, polPtr->solPt) != NULL) {
		if (DefaultScoreValue(interp, polPtr->solPt, &val) != TCL_OK) {
		    return TCL_ERROR;
		}
		if (val > polPtr->maxSolVal) {
		    char temp_str[128];

		    Tcl_DStringInit(&dsPtr);

		    if (itemPtr->bestFitCommand) {
			Tcl_DStringAppendElement(&dsPtr, itemPtr->bestFitCommand);
		    }

		    sprintf(temp_str, "%ld", itemPtr->curIteration);
		    Tcl_DStringAppendElement(&dsPtr, temp_str);

		    polPtr->maxSolVal = val;
		    for(i=0; i < 10; i++) {
			polPtr->maxSolKey[i] = key[i];
		    }

		    Tcl_DStringStartSublist(&dsPtr);
		    for(i=0; i < 10; i++) {
			sprintf(temp_str, "%c", key[i]);
			Tcl_DStringAppendElement(&dsPtr, temp_str);
		    }
		    Tcl_DStringEndSublist(&dsPtr);

		    sprintf(temp_str, "%g", val);
		    Tcl_DStringAppendElement(&dsPtr, temp_str);

		    Tcl_DStringAppendElement(&dsPtr, polPtr->solPt);

		    if (itemPtr->bestFitCommand) {
			if (Tcl_Eval(interp, Tcl_DStringValue(&dsPtr)) != TCL_OK) {
			    Tcl_ResetResult(interp);
			    Tcl_AppendResult(interp, "Bad command usage:  ", Tcl_DStringValue(&dsPtr), (char *)NULL);

			    Tcl_DStringFree(&dsPtr);
			    return TCL_ERROR;
			}
		    }

		    Tcl_DStringFree(&dsPtr);
		}
	    }
	}
	if (mt)
	    ckfree(mt);
    } else {
	key[depth] = DOT;
	if (RecSolvePollux(interp, itemPtr, key, depth+1) != TCL_OK)
	    return TCL_ERROR;
	key[depth] = DASH;
	if (RecSolvePollux(interp, itemPtr, key, depth+1) != TCL_OK)
	    return TCL_ERROR;
	key[depth] = SPACE;
	if (RecSolvePollux(interp, itemPtr, key, depth+1) != TCL_OK)
	    return TCL_ERROR;
    }

    return TCL_OK;
}

/*
# Laid out, the cipher looks like:
#
# 08639 34257 02417 68596 30414 56234 90874 53609
#
# Solution:  luck helps
#
#    l   u    c   k     h e    l    p   s 
#.-..x..-x-.-.x-.-xx....x.x.-..x.--.x...x
#0863934257024176859630414562349087453609
#
# Key: x - . . x . - - x .
#      1 2 3 4 5 6 7 8 9 0
*/

/*
 * The encoding function will randomly choose numbers to
 * represent the morse marks, as constrained by the key.
 */

int
EncodePollux (Tcl_Interp *interp, CipherItem *itemPtr, const char *pt, const char *key) {

    /* Which digits can represent which marks? */
    int trans[128];
    int palette[3][10];
    int npalette[3] = {0, 0, 0};
    char order[] = "1234567890";
    int i, n, mark;
    char *ct;

    trans[DOT] = 0;
    trans[DASH] = 1;
    trans[SPACE] = 2;
    
    /*
     * Set up the key and verify some conditions.
     */
    if (strlen(key) != 10) {
	Tcl_SetResult(interp, "There should be 10 key elements.", TCL_STATIC);
	return TCL_ERROR;
    }

    for (i=0; i<10; i++) {
	switch (key[i]) {
	case DOT: case DASH: case SPACE: break;
	default:
	    Tcl_SetResult(interp,
		"Only morse code marks are allowed in the key.", TCL_STATIC);
	    return TCL_ERROR;
	}
    }

    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, order, key) != TCL_OK) {
	return TCL_ERROR;
    }

    /*
     * Read the key into a palette for encryption.
     */
    for (i=0; i<10; i++) {
	mark = trans[(unsigned)key[i]];
	palette[mark][npalette[mark]++] = order[i] - '0';
    }

    /*
     * Make sure that there is at least one of each mark type.
     */
    for (i=0; i<3; i++) {
	if (!npalette[i]) {
	    Tcl_SetResult(interp,
		"Each morse code mark (. - x) needs to be present in the key.", TCL_STATIC);
	    return TCL_ERROR;
	}
    }

    /*
     * Get the morse text.
     * Use the palette to randomly encode the morse text.
     */
    ct = StringToMorse(pt);
    n = strlen(ct);
    for (i=0; i<n; i++) {
	mark = trans[(unsigned)ct[i]];
	ct[i] = palette[mark][rand()%npalette[mark]] + '0';
    }

    /*
     * Set the ciphertext.
     */
    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, ct) != TCL_OK) {
	free(ct);
	return TCL_ERROR;
    }
    
    Tcl_SetResult(interp, ct, TCL_VOLATILE);

    free(ct);

    return TCL_OK;
}

int
PolluxCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    PolluxItem *polPtr = (PolluxItem *)clientData;
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
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " cget option", (char *)NULL);
	    return TCL_ERROR;
	} else if (strncmp(argv[1], "-length", 6) == 0) {
	    sprintf(temp_str, "%d", polPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", polPtr->header.period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (itemPtr->ciphertext) {
		Tcl_SetResult(interp, itemPtr->ciphertext, TCL_VOLATILE);
	    } else {
		Tcl_SetResult(interp, "{}", TCL_VOLATILE);
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
	    tPtr = PolluxToMorse(itemPtr, (char *)NULL);

	    if (!tPtr) {
		return TCL_ERROR;
	    }

	    Tcl_SetResult(interp, tPtr, TCL_VOLATILE);
	    ckfree(tPtr);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-fullplaintext", 13) == 0 ||
		   strncmp(argv[1], "-fullptext", 7) == 0) {
	    tPtr = GetSpaceyPollux(interp, itemPtr);
	    Tcl_SetResult(interp, tPtr, TCL_DYNAMIC);

	    return TCL_OK;
	} else if (strncmp(argv[1], "-keyword", 8) == 0) {
	    for(i=0; i < 10; i++) {
		if (polPtr->key[i]) {
		    temp_str[i] = polPtr->key[i];
		} else {
		    temp_str[i] = ' ';
		}
	    }
	    temp_str[i] = '\0';

	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-key", 4) == 0) {
	    for(i=0; i < 10; i++)
		temp_str[i] = (polPtr->key[i]?polPtr->key[i]:' ');
	    temp_str[i] = '\0';

	    Tcl_AppendElement(interp, "0123456789");
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
		Tcl_SetResult(interp, "", TCL_VOLATILE);
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-bestfitcommand", 6) == 0) {
	    if (itemPtr->bestFitCommand) {
		Tcl_SetResult(interp, itemPtr->bestFitCommand, TCL_VOLATILE);
	    } else {
		Tcl_SetResult(interp, "", TCL_VOLATILE);
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
		    Tcl_SetResult(interp, "Invalid interval.", TCL_VOLATILE);
		    return TCL_ERROR;
		}

		if (i < 0) {
		    Tcl_SetResult(interp, "Invalid interval.", TCL_VOLATILE);
		    return TCL_ERROR;
		}

		itemPtr->stepInterval = i;
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

		if (CipherSetStepCmd(itemPtr, argv[1]) != TCL_OK)
		    return TCL_ERROR;
	    } else if (strncmp(*argv, "-ciphertext", 10) == 0 ||
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
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " restore ct mt",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	return (itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1], argv[2]);
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
	    Tcl_SetResult(interp, "", TCL_VOLATILE);
	    return TCL_OK;
	} else {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " undo ?ct?", (char *)NULL);
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
			" restore ct mt", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" substitute ct mt", (char *)NULL);
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
