/*
 * fmorse.c --
 *
 *	This file implements the fractionated morse cipher type.
 *	The morbit cipher has 9!, or 362880 possible combinations.
 *
 * Copyright (c) 2001 Michael Thomas <wart@kobold.org>
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
#include <perm.h>

/* For KeyGenerateK1 used in encoding. */
#include <keygen.h>

#include <cipherDebug.h>

#define KEY_LENGTH 26

static int  CreateFmorse	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
static char *GetFmorse		_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetFmorse		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestoreFmorse	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolveFmorse		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
int FmorseCmd			_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));
static int FmorseUndo		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int FmorseSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int FmorseLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *));
static char *FmorseToMorse 	_ANSI_ARGS_((CipherItem *, const char *));
static int FmorseStringToKeyElem _ANSI_ARGS_((const char *));
static char *FmorseKeyElemToString _ANSI_ARGS_((int));
int FmorseSolveValue		_ANSI_ARGS_((Tcl_Interp *, ClientData,
	    			int *, int));
static int EncodeFmorse		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));

static char fmorse_key_elems[28][4] = {"   ",
	"...", "..-", "..x",
	".-.", ".--", ".-x",
	".x.", ".x-", ".xx",
	"-..", "-.-", "-.x",
	"--.", "---", "--x",
	"-x.", "-x-", "-xx",
	"x..", "x.-", "x.x",
	"x-.", "x--", "x-x",
	"xx.", "xx-", "xxx"};

typedef struct FmorseItem {
    CipherItem header;

    char key[KEY_LENGTH + 1];
    int	histogram[KEY_LENGTH + 1];

    char maxSolKey[KEY_LENGTH + 1];
    int maxSolVal;
    long solValidCount;
    char *solPt;
} FmorseItem;

CipherType FmorseType = {
    "fmorse",
    ATOZ,
    sizeof(FmorseItem),
    CreateFmorse,	/* create proc */
    DeleteCipher,	/* delete proc */
    FmorseCmd,		/* cipher command proc */
    GetFmorse,		/* get ciphertext proc */
    SetFmorse,		/* set ciphertext proc */
    SolveFmorse,	/* solve cipher proc */
    RestoreFmorse,	/* restore proc */
    FmorseLocateTip,	/* locate proc */
    FmorseSubstitute,	/* sub proc */
    FmorseUndo,		/* undo proc */
    EncodeFmorse,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

static int
CreateFmorse(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    FmorseItem *fmorPtr = (FmorseItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    fmorPtr->header.period = 0;
    fmorPtr->solPt = (char *)NULL;
    for(i=0; i < KEY_LENGTH; i++) {
	fmorPtr->key[i] = '\0';
	fmorPtr->histogram[i] = 0;
	fmorPtr->maxSolKey[i] = '\0';
    }

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++)
	Tcl_DStringAppendElement(&dsPtr, argv[i]);

    Tcl_CreateCommand(interp, temp_ptr, FmorseCmd, itemPtr,
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
SetFmorse(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
{
    FmorseItem *fmorPtr = (FmorseItem *)itemPtr;
    char	*c=(char *)NULL;
    int		length=0;
    int		i,
    		val;

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    /*
     * Count the number of valid characters
     */

    length = CountValidChars(itemPtr, ctext);
    if (!length) {
	Tcl_SetResult(interp, "No valid characters found in ciphertext", TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (itemPtr->ciphertext) {
	ckfree(itemPtr->ciphertext);
    }

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    /*
     * Generate the histogram
     */

    for(i=0; i < KEY_LENGTH; i++) {
	fmorPtr->histogram[i] = 0;
    }

    c = ExtractValidChars(itemPtr, ctext);

    if (!c) {
	Tcl_SetResult(interp, "Bad ciphertext", TCL_VOLATILE);
	return TCL_ERROR;
    }

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    itemPtr->ciphertext = c;
    itemPtr->length = strlen(c);

    for(i=0; i < itemPtr->length; i++) {
	val = itemPtr->ciphertext[i] - 'a';

	/*
	 * This should never happen.  The call to "ExtractValidChars()" above
	 * should have ensured that we have only valid ciphertext characters.
	 */
	if (val < 0 || val > KEY_LENGTH) {
	    fprintf(stderr, "Bad character in ciphertext:  %c\n", 
		    itemPtr->ciphertext[i]);
	    abort();
	}

	fmorPtr->histogram[val]++;
    }

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    return TCL_OK;
}

/*
 * Fix me
 */

static int
FmorseLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, char *tip, char *start)
{
    Tcl_SetResult(interp,
	    "No locate tip function defined for fmorse ciphers.",
	    TCL_VOLATILE);
    return TCL_ERROR;
}

static int
FmorseUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int dummy)
{
    FmorseItem *fmorPtr = (FmorseItem *)itemPtr;
    int		i;

    if (ct == (char *)NULL) {
	for(i=0; i < KEY_LENGTH; i++) {
	    fmorPtr->key[i] = '\0';
	}

	return TCL_OK;
    }

    for(i=0; i < strlen(ct); i++) {
	if (IsValidChar(itemPtr, ct[i])) {
	    fmorPtr->key[ct[i]-'a'] = '\0';
	}
    }

    return TCL_OK;
}

/*
 * Fix me
 * Add check to make sure the same morse pattern isn't used twice
 */

static int
FmorseSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, const char *pt, int dummy)
{
    FmorseItem *fmorPtr = (FmorseItem *)itemPtr;
    const char	*p;
    char	q[KEY_LENGTH*3+1],
		r[KEY_LENGTH*3+1];
    int		e;
    char	key[KEY_LENGTH + 1];
    int		valid_sub = NEW_SUB;
    int		olap_sub=0, i;
    int		qcount=0,
    		rcount=0;
    int		*index_used;


    /*
     * Store the substitution in the temporary key.  Look for bad
     * substitutions.
     */ 

    for(p=pt; *p; p++) {
	if (*p != SPACE && *p != DASH && *p != DOT && *p != BLANK) {
	    Tcl_SetResult(interp, "Bad character in substitution morsetext", TCL_STATIC);
	    return BAD_SUB;
	}
    }
    for(p=ct; *p; p++) {
	if (! IsValidChar(itemPtr, *p) && *p != ' ') {
	    Tcl_SetResult(interp, "Bad character in substitution ciphertext", TCL_STATIC);
	    return BAD_SUB;
	}
    }
    if (strlen(pt) %3 != 0) {
	Tcl_SetResult(interp,
		"Plaintext length must be a multiple of three", TCL_VOLATILE);
	return BAD_SUB;
    }
    if (strlen(pt) /3 != strlen(ct)) {
	char temp_str[256];
	sprintf(temp_str, "3 * %d != %d", strlen(ct), strlen(pt));
	Tcl_AppendResult(interp,
		"Plaintext and ciphertext don't match in length (",
		temp_str, ")", (char *)NULL);
	return BAD_SUB;
    }

    index_used = (int *)ckalloc(sizeof(int)*(KEY_LENGTH));
    for(i=0; i < KEY_LENGTH; i++) {
	key[i] = '\0';
	index_used[i] = 0;
    }
    
    p = pt;
    for(i=0, p=pt; i < strlen(ct) && *p && valid_sub != BAD_SUB; i++, p+=3) {
	int f;
	/*
	 * This allows us to use 'cipher restore "ab cd..."', restoring from
	 * a partial key.
	 */
	if (ct[i] == ' ') {
	    continue;
	}
	e = ct[i] - 'a';
	f = FmorseStringToKeyElem(p);

	/*
	if (!f) {
	    valid_sub = BAD_SUB;
	}
	*/

	if (key[e] && key[e] != f) {
	    valid_sub = BAD_SUB;
	} else {
	    key[e] = f;
	    index_used[e] = 1;
	}
    }

    if (valid_sub == BAD_SUB) {
	Tcl_SetResult(interp, "Bad Substitution", TCL_VOLATILE);
	ckfree((char *)index_used);
	return BAD_SUB;
    }

    /*
     * Look for "alternate" substitutions
     */

    p = pt;
    for(i=0, p=pt; i < strlen(ct) && *p && valid_sub != BAD_SUB; i++, p+=3) {
	e = ct[i]-'a';

	if (ct[i] != ' ') {
	    /*
	     * Was this key position occupied by a different letter
	     * before the substitution?
	     */
	    if (fmorPtr->key[e] && fmorPtr->key[e] != key[e]) {
		valid_sub = ALT_SUB;
		sprintf(q+qcount*3, "%2c ", ct[i]);
		qcount++;
	    }

	    if (key[e]) {
		sprintf(r+rcount*3, "%2c ", ct[i]);
		rcount++;
	    }

	    index_used[e] = 1;
	}
    }

    if (valid_sub == BAD_SUB) {
	Tcl_SetResult(interp, "Bad Substitution", TCL_VOLATILE);
	ckfree((char *)index_used);
	return BAD_SUB;
    }

    /*
     * Store the ciphertext and the plaintext in the interpreter result
     */

    for(i=0; i < KEY_LENGTH; i++) {
	if (index_used[i]) {
	    fmorPtr->key[i] = key[i];
	}
    }

    ckfree((char *)index_used);
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
FmorseToMorse(CipherItem *itemPtr, const char *key)
{
    FmorseItem *fmorPtr = (FmorseItem *)itemPtr;
    char	*mt=(char *)ckalloc(sizeof(char) * itemPtr->length * 3 + 1);
    char	*t;
    int		i, j;

    if (!key) {
	key = fmorPtr->key;
    }

    for(i=0; i < itemPtr->length; i++) {
	j = itemPtr->ciphertext[i] - 'a';
	t = FmorseKeyElemToString(key[j]);

	if (t) {
	    mt[i*3+0] = t[0];
	    mt[i*3+1] = t[1];
	    mt[i*3+2] = t[2];
	} else {
	    mt[i*3+0] = ' ';
	    mt[i*3+1] = ' ';
	    mt[i*3+2] = ' ';
	}
    }

    mt[i*3] = '\0';

    return mt;
}

static char *
GetFmorse(Tcl_Interp *interp, CipherItem *itemPtr)
{
    char	*mt;
    char	*pt=(char *)NULL;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp, "Can't do anything until ciphertext has been set",
		TCL_VOLATILE);
	return (char *)NULL;
    }

    /*
     * The plaintext generated for a fractionated morse cipher can be longer
     * or shorter than the ciphertext.  It's highly unlikely, though, that the
     * plaintext length is more than twice that of the ciphertext length.
     * Allocate enough space for the plaintext so that we don't get
     * a memory overrun.
     */
    pt=(char *)ckalloc(sizeof(char) * (itemPtr->length * 2 + 1));

    mt = FmorseToMorse(itemPtr, (char *)NULL);
    if (MorseStringToString(mt, pt) == NULL) {
	ckfree(pt);
	ckfree(mt);
	Tcl_SetResult(interp, "Error converting morse string", TCL_VOLATILE);
	return (char *)NULL;
    }

    ckfree(mt);

    return pt;
}

static char *
GetSpaceyFmorse(Tcl_Interp *interp, CipherItem *itemPtr)
{
    char	*mt;
    char	*pt=(char *)ckalloc(sizeof(char) * itemPtr->length * 3 + 2);

    /*
    fprintf(stdout, "length = %d\n", itemPtr->length);
    fflush(stdout);
    */

    mt = FmorseToMorse(itemPtr, (char *)NULL);

    if (MorseStringToSpaceyString(mt, pt) == NULL) {
	ckfree(pt);
	ckfree(mt);
	Tcl_SetResult(interp, "Error converting morse string", TCL_VOLATILE);
	return (char *)NULL;
    }

    Tcl_SetResult(interp, pt, TCL_VOLATILE);
    ckfree(mt);

    return pt;
}


/*
 * One way to use this function:
 * part1 = "keyabcdfghijlmnopqrstuvwxz", part2 = (char *) NULL.
 * This sets itemPtr->key correctly.
 */

static int
RestoreFmorse(Tcl_Interp *interp, CipherItem *itemPtr, const char *part1, const char *part2)
{
    if (part2 != NULL) {
	if( (itemPtr->typePtr->subProc)(interp, itemPtr, part1, part2, 0) == BAD_SUB) {
	    return TCL_ERROR;
	}
    } else {
	if (strlen(part1) != KEY_LENGTH) {
	    Tcl_SetResult(interp, "Invalid length of restore key.",
		    TCL_VOLATILE);
	    return TCL_ERROR;
	}
	if( (itemPtr->typePtr->subProc)(interp, itemPtr, part1, ".....-..x.-..--.-x.x..x-.xx-..-.--.x--.-----x-x.-x--xxx..x.-x.xx-.x--x-xxx.xx-", 0) == BAD_SUB) {
	    return TCL_ERROR;
	}
    }

    return TCL_OK;
}

static int
SolveFmorse(Tcl_Interp *interp, CipherItem *itemPtr, char *maxkey)
{
    Tcl_SetResult(interp, "You cheat!", TCL_VOLATILE);
    return TCL_ERROR;
}


/*
 * Should be the inverse of fmorse_key_elems+1
 */

static int
FmorseStringToKeyElem(const char *string)
{

    int i;
    int incr;
    int value=0;
    char c;
    for (i=0; i<3; i++) {
	value *= 3;
	c = string[i];
	if (c == DOT) {
	    incr = 0;
	} else if (c == DASH) {
	    incr = 1;
	} else if (c == SPACE) {
	    incr = 2;
	} else {
	    return 0;
	}
	value += incr;
    }

    return value + 1;
}

static char *
FmorseKeyElemToString(int val) {
    if (val < 1 || val > KEY_LENGTH)
	return (char *)NULL;

    return fmorse_key_elems[val];
}

int
FmorseCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    FmorseItem *fmorPtr = (FmorseItem *)clientData;
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
	    sprintf(temp_str, "%d", fmorPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", fmorPtr->header.period);
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
	    tPtr = FmorseToMorse(itemPtr, (char *)NULL);

	    if (!tPtr) {
		return TCL_ERROR;
	    }

	    Tcl_SetResult(interp, tPtr, TCL_VOLATILE);
	    ckfree(tPtr);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-fullplaintext", 13) == 0 ||
		   strncmp(argv[1], "-fullptext", 7) == 0) {
	    tPtr = GetSpaceyFmorse(interp, itemPtr);
	    Tcl_SetResult(interp, tPtr, TCL_VOLATILE);
	    ckfree(tPtr);

	    return TCL_OK;
	} else if (strncmp(argv[1], "-keyword", 8) == 0) {
	    int j;
	    for(i=0; i < KEY_LENGTH; i++) {
		temp_str[i] = ' ';
		for(j=0; j < KEY_LENGTH; j++) {
		    if (fmorPtr->key[j] == i+1) {
			temp_str[i] = j + 'a';
		    }
		}
	    }
	    temp_str[i] = '\0';

	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-key", 4) == 0) {
	    for(i=0; i < KEY_LENGTH; i++) {
		if (fmorPtr->key[i]) {
		    temp_str[i*3+0]=fmorse_key_elems[(int)(fmorPtr->key[i])][0];
		    temp_str[i*3+1]=fmorse_key_elems[(int)(fmorPtr->key[i])][1];
		    temp_str[i*3+2]=fmorse_key_elems[(int)(fmorPtr->key[i])][2];
		} else {
		    temp_str[i*3+0] = ' ';
		    temp_str[i*3+1] = ' ';
		    temp_str[i*3+2] = ' ';
		}
	    }
	    temp_str[i*3] = '\0';

	    Tcl_AppendElement(interp, ATOZ);
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

		if (i < 0 ) {
		    Tcl_SetResult(interp, "Invalid interval.", TCL_VOLATILE);
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
	if (argc != 2 && argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " restore ct ?mt?",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	if (argc == 2) {
	    return (itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1],
		    NULL);
	} else {
	    return (itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1],
		    argv[2]);
	}
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
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " encode pt key",
		    (char *)NULL);
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
			" locate pt", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" undo ct", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" encode pt key", (char *)NULL);
	return TCL_ERROR;
    }

    return TCL_OK;
}


/*
 * This function expects that the key argument is an ascii phrase for K1 key generation.
 * The ciphertext and the internal key will be modified.
 * Functions in keygen.c and morse.c are called.
 */

static int EncodeFmorse(Tcl_Interp *interp, CipherItem *itemPtr, const char *pt, const char *key) {

    char permutation[27];
    int i;
    int ct_length;
    char *mt = (char *) NULL;
    char *ct = (char *) NULL;
    char spacestring[] = {SPACE, '\0'};

    /*
     * I don't know the environment from which this function will be called,
     * so I'll practice a little defensive programming here.
     */
    if (!pt) {
	Tcl_SetResult(interp, "Bad pt pointer.", TCL_STATIC);
	return TCL_ERROR;
    }
    if (!key) {
	Tcl_SetResult(interp, "Bad key pointer.", TCL_STATIC);
	return TCL_ERROR;
    }
    if (!strlen(pt)) {
	Tcl_SetResult(interp, "Empty plaintext.", TCL_STATIC);
	return TCL_ERROR;
    }

    /*
     * Set up the key.
     */
    if (KeyGenerateK1(interp, key, permutation) == TCL_ERROR) {
	return TCL_ERROR;
    }
    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, permutation, (char *) NULL) != TCL_OK) {
	return TCL_ERROR;
    }
    for (i=0; i<26; i++) {
	permutation[i] -= 'a';
    }

    /* 
     * Make the morse string.
     * Enough space is allocated by StringToMorse that we don't have to worry.
     * We do need to free it though.
     * Pad it with SPACEs until it is a multiple of 3.     
     * Make sure the morse text is valid.
     */
    mt = StringToMorse(pt);
    while (strlen(mt) % 3) {
	strcat(mt, spacestring);
    }
    if (!MorseValid(mt)) {
	Tcl_SetResult(interp, "Invalid morse text.", TCL_STATIC);
	free(mt);
	return TCL_ERROR;
    }

    /*
     * The ciphertext is 1/3 the length of the morse text.
     * Do the encryption using the 26 element permutation and the morse text.
     * Free the morse text.
     */
    ct_length = strlen(mt) / 3;
    ct = (char *)ckalloc(sizeof(char) * ct_length + 1);
    for (i=0; i<ct_length; i++) {
	ct[i] = permutation[FmorseStringToKeyElem(mt + i*3) - 1] + 'a';
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


