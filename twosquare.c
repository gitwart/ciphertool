/*
 * twosquare.c --
 *
 *	This file implements the twosquare and foursquare cipher types.
 *
 * Copyright (c) 2000-2008 Michael Thomas <wart@kobold.org>
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

int TwosquareCmd		_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));

#define KEY0	'0'
#define KEY1	'1'
#define KEY2	'2'
#define KEY3	'3'
#define KEY4	'4'
#define KEY5	'5'
#define KEYLEN	25
#define EMPTY	-1

#define SQUARE1		0
#define SQUARE2		1
#define FIXEDSQUARE	2

/*
 * Prototypes for procedures only referenced in this file.
 */

static int  CreateTwosquare	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
void	DeleteTwosquare		_ANSI_ARGS_((ClientData));
static char *GetTwosquare	_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static char *GetFoursquare	_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetTwosquare	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestoreTwosquare	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolveTwosquare	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
static int TwosquareUndo	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int TwosquareSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int TwosquareLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int TwosquareKeyvalToLetter	_ANSI_ARGS_((CipherItem *, const char *,
				int));
static char *TwosquareLetterToKeyval _ANSI_ARGS_((CipherItem *, char, int));
static int TwosquareKeycharToInt	_ANSI_ARGS_((char));
static int TwosquareKeyPairToIndex	_ANSI_ARGS_((int, int));
static int EncodeTwosquare	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static char *EncodeFoursquareString	_ANSI_ARGS_((CipherItem *, const char *));

char *twosquareKeyConv[36] = {"00", "01", "02", "03", "04", "05",
			      "10", "11", "12", "13", "14", "15",
			      "20", "21", "22", "23", "24", "25",
			      "30", "31", "32", "33", "34", "35",
			      "40", "41", "42", "43", "44", "45",
			      "50", "51", "52", "53", "54", "55"};


/*
 * This structure contains the data associated with a single twosquare cipher.
 */

typedef struct TwosquareItem {
    CipherItem header;

    /*
     * The key settings for the first keysquare  The first index for
     * the next two members refers to one of the two keysquares.
     */
    char ptkey[3][KEYLEN+11]; /* The indices are the key values (11, 23, etc.)
			   The values are the letters that the values stand
			   for. */
    char ctkey[3][KEYLEN];/* The indices are the letters, the values are the
			   key values that letters correspond to 
			   (11, 2_, etc).  Note that these need not be
			   full key values, as in the case of '2_'.*/

    char **keyConv;	/* Mapping from a unique key index to a row/column
			   pair. */

    char *pt;

} TwosquareItem;

/*
 * This structure joins the data for an twosquare cipher with common routines
 * used to manipulate it.
 */

CipherType TwosquareType = {
    "twosquare",
    ATOZ,
    sizeof(TwosquareItem),
    CreateTwosquare,	/* create proc */
    DeleteTwosquare,	/* delete proc */
    TwosquareCmd,	/* cipher command proc */
    GetTwosquare,	/* get plaintext proc */
    SetTwosquare,	/* show ciphertext proc */
    SolveTwosquare,	/* solve cipher proc */
    RestoreTwosquare,	/* restore proc */
    TwosquareLocateTip,	/* locate proc */
    TwosquareSubstitute,/* sub proc */
    TwosquareUndo,	/* undo proc */
    EncodeTwosquare,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

/*
 * This structure joins the data for an twosquare cipher with common routines
 * used to manipulate it.  The Foursquare cipher is identical to the twosquare
 * cipher in all but the decipherment procedure.
 */

CipherType FoursquareType = {
    "foursquare",
    ATOZ,
    sizeof(TwosquareItem),
    CreateTwosquare,	/* create proc */
    DeleteTwosquare,	/* delete proc */
    TwosquareCmd,	/* cipher command proc */
    GetFoursquare,	/* get plaintext proc */
    SetTwosquare,	/* show ciphertext proc */
    SolveTwosquare,	/* solve cipher proc */
    RestoreTwosquare,	/* restore proc */
    TwosquareLocateTip,	/* locate proc */
    TwosquareSubstitute,/* sub proc */
    TwosquareUndo,	/* undo proc */
    EncodeTwosquare,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

/*
 * CreateTwosquare --
 *
 *	Create a new twosquare cipher item.
 *
 * Results:
 *
 *	If the cipher could not be created successfully, the routine will
 *	return TCL_ERROR.  Otherwise it will return TCL_OK.
 *
 * Side effects:
 *
 *	Memory is allocated for a new cipher structure.  The structure is
 *	filled in with default values.
 */

static int
CreateTwosquare(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    TwosquareItem *twoPtr = (TwosquareItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    twoPtr->header.period = 0;

    twoPtr->keyConv = twosquareKeyConv;
    twoPtr->pt = (char *)NULL;

    for(i=0; i < KEYLEN; i++) {
	twoPtr->ctkey[SQUARE1][i] = 0;
	twoPtr->ctkey[SQUARE2][i] = 0;
    }
    for (i=0; i < 36; i++) {
	twoPtr->ptkey[SQUARE1][i] = EMPTY;
	twoPtr->ptkey[SQUARE2][i] = EMPTY;
    }
    twoPtr->ptkey[FIXEDSQUARE][7]  = 'a';
    twoPtr->ptkey[FIXEDSQUARE][8]  = 'b';
    twoPtr->ptkey[FIXEDSQUARE][9]  = 'c';
    twoPtr->ptkey[FIXEDSQUARE][10] = 'd';
    twoPtr->ptkey[FIXEDSQUARE][11] = 'e';
    twoPtr->ptkey[FIXEDSQUARE][13] = 'f';
    twoPtr->ptkey[FIXEDSQUARE][14] = 'g';
    twoPtr->ptkey[FIXEDSQUARE][15] = 'h';
    twoPtr->ptkey[FIXEDSQUARE][16] = 'i';
    twoPtr->ptkey[FIXEDSQUARE][17] = 'k';
    twoPtr->ptkey[FIXEDSQUARE][19] = 'l';
    twoPtr->ptkey[FIXEDSQUARE][20] = 'm';
    twoPtr->ptkey[FIXEDSQUARE][21] = 'n';
    twoPtr->ptkey[FIXEDSQUARE][22] = 'o';
    twoPtr->ptkey[FIXEDSQUARE][23] = 'p';
    twoPtr->ptkey[FIXEDSQUARE][25] = 'q';
    twoPtr->ptkey[FIXEDSQUARE][26] = 'r';
    twoPtr->ptkey[FIXEDSQUARE][27] = 's';
    twoPtr->ptkey[FIXEDSQUARE][28] = 't';
    twoPtr->ptkey[FIXEDSQUARE][29] = 'u';
    twoPtr->ptkey[FIXEDSQUARE][31] = 'v';
    twoPtr->ptkey[FIXEDSQUARE][32] = 'w';
    twoPtr->ptkey[FIXEDSQUARE][33] = 'x';
    twoPtr->ptkey[FIXEDSQUARE][34] = 'y';
    twoPtr->ptkey[FIXEDSQUARE][35] = 'z';

    twoPtr->ctkey[FIXEDSQUARE][0]  = 0;
    twoPtr->ctkey[FIXEDSQUARE][1]  = 1;
    twoPtr->ctkey[FIXEDSQUARE][2]  = 2;
    twoPtr->ctkey[FIXEDSQUARE][3]  = 3;
    twoPtr->ctkey[FIXEDSQUARE][4]  = 4;
    twoPtr->ctkey[FIXEDSQUARE][5]  = 5;
    twoPtr->ctkey[FIXEDSQUARE][6]  = 6;
    twoPtr->ctkey[FIXEDSQUARE][7]  = 7;
    twoPtr->ctkey[FIXEDSQUARE][8]  = 8;
    twoPtr->ctkey[FIXEDSQUARE][9]  = 9;
    twoPtr->ctkey[FIXEDSQUARE][10] = 10;
    twoPtr->ctkey[FIXEDSQUARE][11] = 11;
    twoPtr->ctkey[FIXEDSQUARE][12] = 12;
    twoPtr->ctkey[FIXEDSQUARE][13] = 13;
    twoPtr->ctkey[FIXEDSQUARE][14] = 14;
    twoPtr->ctkey[FIXEDSQUARE][15] = 15;
    twoPtr->ctkey[FIXEDSQUARE][16] = 16;
    twoPtr->ctkey[FIXEDSQUARE][17] = 17;
    twoPtr->ctkey[FIXEDSQUARE][18] = 18;
    twoPtr->ctkey[FIXEDSQUARE][19] = 19;
    twoPtr->ctkey[FIXEDSQUARE][20] = 20;
    twoPtr->ctkey[FIXEDSQUARE][21] = 21;
    twoPtr->ctkey[FIXEDSQUARE][22] = 22;
    twoPtr->ctkey[FIXEDSQUARE][23] = 23;
    twoPtr->ctkey[FIXEDSQUARE][24] = 24;

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, TwosquareCmd, itemPtr,
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
DeleteTwosquare(ClientData clientData)
{
    TwosquareItem *twoPtr = (TwosquareItem *)clientData;

    if (twoPtr->pt != NULL) {
	ckfree(twoPtr->pt);
    }

    DeleteCipher(clientData);
}

int
TwosquareCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    TwosquareItem *twoPtr = (TwosquareItem *)clientData;
    CipherItem	*itemPtr = (CipherItem *)clientData;
    char	temp_str[256];
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
	}
	if (strncmp(argv[1], "-plaintext", 9) == 0 ||
		   strncmp(argv[1], "-ptext", 3) == 0) {
	    tPtr = (itemPtr->typePtr->decipherProc)(interp, itemPtr);

	    if (!tPtr) {
		return TCL_ERROR;
	    }

	    Tcl_SetResult(interp, tPtr, TCL_STATIC);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-length", 6) == 0) {
	    sprintf(temp_str, "%d", twoPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", twoPtr->header.period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!twoPtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_VOLATILE);
	    } else {
		Tcl_SetResult(interp, twoPtr->header.ciphertext, TCL_VOLATILE);
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-keyword", 2) == 0) {
	    int temp_str_pos=0;
	    for(i=1; i <= 5; i++) {
		int j;
		for(j=1; j <= 5; j++) {
		    int keyIndex = TwosquareKeyPairToIndex(i, j);
		    char keyLetter = twoPtr->ptkey[SQUARE1][keyIndex];

		    if (keyLetter != EMPTY) {
			temp_str[temp_str_pos++] = keyLetter;
		    } else {
			temp_str[temp_str_pos++] = ' ';
		    }
		}
	    }
	    temp_str[temp_str_pos] = '\0';

	    temp_str_pos=0;
	    Tcl_AppendElement(interp, temp_str);
	    for(i=1; i <= 5; i++) {
		int j;
		for(j=1; j <= 5; j++) {
		    int keyIndex = TwosquareKeyPairToIndex(i, j);
		    char keyLetter = twoPtr->ptkey[SQUARE2][keyIndex];

		    if (keyLetter != EMPTY) {
			temp_str[temp_str_pos++] = keyLetter;
		    } else {
			temp_str[temp_str_pos++] = ' ';
		    }
		}
	    }
	    temp_str[temp_str_pos] = '\0';

	    Tcl_AppendElement(interp, temp_str);
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
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " restore square1 square2",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	return (itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1], argv[2]);
    } else if (**argv == 'e' && (strncmp(*argv, "encode", 1) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " encode pt key",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	return (itemPtr->typePtr->encodeProc)(interp, itemPtr, argv[1], argv[2]);
    } else if (**argv == 's' && (strncmp(*argv, "substitute", 2) == 0)) {
	Tcl_AppendResult(interp,
		"No substitute function defined for ",
		itemPtr->typePtr->type,
		" ciphers",
		(char *)NULL);
	return TCL_ERROR;

	if (argc != 4) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " substitute row col pt",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	if (*argv[1] < '0' || *argv[1] > '5') {
	    Tcl_SetResult(interp,
		    "Invalid row value.  Value must be between 0 and 5.",
		    TCL_VOLATILE);
	    return TCL_ERROR;
	}
	if (*argv[2] < '0' || *argv[2] > '5') {
	    Tcl_SetResult(interp,
		    "Invalid column value.  Value must be between 0 and 5.",
		    TCL_VOLATILE);
	    return TCL_ERROR;
	}
	if (! IsValidChar(itemPtr, *argv[3])) {
	    Tcl_SetResult(interp, "Invalid letter value.", TCL_VOLATILE);
	    return TCL_ERROR;
	}

	/*
	 * *argv[1] and *argv[2] are now guaranteed to be a valid row/column
	 * value (ROW1, ROW3, etc.
	 */
	if ((itemPtr->typePtr->subProc)(interp, itemPtr, argv[1], argv[2], *argv[3]) == BAD_SUB) {
	    return TCL_ERROR;
	} else {
	    return TCL_OK;
	}
    } else if (**argv == 's' && (strncmp(*argv, "solve", 2) == 0)) {
	if ((itemPtr->typePtr->solveProc)(interp, itemPtr, temp_str) != TCL_OK)
	    return TCL_ERROR;

	Tcl_SetResult(interp, temp_str, TCL_VOLATILE);

	return TCL_OK;
    } else if (**argv == 'u' && (strncmp(*argv, "undo", 1) == 0)) {
	if (argc != 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " undo ct", (char *)NULL);
	    return TCL_ERROR;
	}
	if ((itemPtr->typePtr->undoProc)(interp, itemPtr, argv[1], 0) == TCL_OK) {
	    Tcl_SetResult(interp, "", TCL_VOLATILE);
	    return TCL_OK;
	} else {
	    return TCL_ERROR;
	}
    } else if (**argv == 'l' && (strncmp(*argv, "locate", 1) == 0)) {
	if (argc < 2 || argc > 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " locate pt ct",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	if (argc == 2) {
	    return (itemPtr->typePtr->locateProc)(interp, itemPtr, argv[1],
		    (char *)NULL);
	} else {
	    return (itemPtr->typePtr->locateProc)(interp, itemPtr, argv[1],
		    argv[2]);
	}
    } else {
	Tcl_AppendResult(interp, "Unknown option ", *argv, (char *)NULL);
	Tcl_AppendResult(interp, "\nMust be one of:  ", cmd,
			" cget ?option?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" configure ?option value?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" solve", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" substitute row col pt", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" undo ct", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" restore pt positions", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" locate pt ct", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" encode pt key", (char *)NULL);
	return TCL_ERROR;
    }
}

static int
SetTwosquare(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
{
    TwosquareItem *twoPtr = (TwosquareItem *)itemPtr;
    char	*c;
    int		valid = TCL_OK,
    		length=0;

    length = CountValidChars(itemPtr, ctext);
    c = ExtractValidCharsJtoI(itemPtr, ctext);

    if (!c) {
	Tcl_SetResult(interp, "No valid characters found in ciphertext",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (valid==TCL_OK) {
	itemPtr->length = length;
	if (itemPtr->ciphertext) {
	    ckfree(itemPtr->ciphertext);
	}
	itemPtr->ciphertext = c;

	if (itemPtr->ciphertext == NULL) {
	    Tcl_SetResult(interp, "Error mallocing memory for new cipher", TCL_VOLATILE);
	    return TCL_ERROR;
	}

	if (twoPtr->pt) {
	    ckfree(twoPtr->pt);
	}
	twoPtr->pt = (char *)ckalloc(sizeof(char) * length + 1);

	itemPtr->length = length;

	Tcl_SetResult(interp, itemPtr->ciphertext, TCL_STATIC);
    }

    return valid;
}

static int
TwosquareLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, const char *tip, const char *start)
{
    Tcl_AppendResult(interp,
	    "No locate tip function defined for ",
	    itemPtr->typePtr->type,
	    " ciphers",
	    (char *)NULL);
    return TCL_ERROR;
}

static int
TwosquareUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int dummy)
{
    Tcl_AppendResult(interp,
	    "No undo function defined for ",
	    itemPtr->typePtr->type,
	    " ciphers",
	    (char *)NULL);
    return TCL_ERROR;
}

static int
TwosquareSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *row, const char *col, int value)
{
    Tcl_AppendResult(interp,
	    "No substitute function defined for ",
	    itemPtr->typePtr->type,
	    " ciphers",
	    (char *)NULL);
    return BAD_SUB;
}

static int
TwosquareKeycharToInt(char c) {
    if (c > 'i') {
	c--;
    }
    c -= 'a';

    return c;
}

static int
TwosquareKeyPairToIndex(int row, int col)
{
    int keyIndex = 0;

    if (row < 0 || row > 5 || col < 0 || col > 5) {
	return 0;
    } else {
	return row * 6 + col;
    }

    return keyIndex;
}

static char *
GetTwosquare(Tcl_Interp *interp, CipherItem *itemPtr)
{
    TwosquareItem *twoPtr = (TwosquareItem *)itemPtr;
    int		i;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp, "Can't do anything until ciphertext has been set",
		TCL_VOLATILE);
	return (char *)NULL;
    }

    /*
     * Convert every digram to its plaintext equivalent.
     */

    for(i=0; i < itemPtr->length; i += 2) {
	char ct1 = itemPtr->ciphertext[i];
	char ct2 = itemPtr->ciphertext[i+1];
	char *ct1cell = TwosquareLetterToKeyval(itemPtr, ct1, SQUARE2);
	char *ct2cell = TwosquareLetterToKeyval(itemPtr, ct2, SQUARE1);
	char pt1cell[2];
	char pt2cell[2];

	pt1cell[0] = ct1cell[0];
	pt1cell[1] = ct2cell[1];

	pt2cell[0] = ct2cell[0];
	pt2cell[1] = ct1cell[1];

	twoPtr->pt[i] = TwosquareKeyvalToLetter(itemPtr, pt1cell, SQUARE1);
	if (twoPtr->pt[i] == '\0') {
	    twoPtr->pt[i] = ' ';
	}

	twoPtr->pt[i+1] = TwosquareKeyvalToLetter(itemPtr, pt2cell, SQUARE2);
	if (twoPtr->pt[i+1] == '\0') {
	    twoPtr->pt[i+1] = ' ';
	}
    }
    twoPtr->pt[itemPtr->length] = '\0';
	
    return twoPtr->pt;
}

static char *
GetFoursquare(Tcl_Interp *interp, CipherItem *itemPtr)
{
    TwosquareItem *twoPtr = (TwosquareItem *)itemPtr;
    int		i;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp, "Can't do anything until ciphertext has been set",
		TCL_VOLATILE);
	return (char *)NULL;
    }

    /*
     * Convert every digram to its plaintext equivalent.
     */

    for(i=0; i < itemPtr->length; i += 2) {
	char ct1 = itemPtr->ciphertext[i];
	char ct2 = itemPtr->ciphertext[i+1];
	char *ct1cell = TwosquareLetterToKeyval(itemPtr, ct1, SQUARE1);
	char *ct2cell = TwosquareLetterToKeyval(itemPtr, ct2, SQUARE2);
	char pt1cell[2];
	char pt2cell[2];

	pt1cell[0] = ct1cell[0];
	pt1cell[1] = ct2cell[1];

	pt2cell[0] = ct2cell[0];
	pt2cell[1] = ct1cell[1];

	twoPtr->pt[i] = TwosquareKeyvalToLetter(itemPtr, pt1cell, FIXEDSQUARE);
	if (twoPtr->pt[i] == '\0') {
	    twoPtr->pt[i] = ' ';
	}

	twoPtr->pt[i+1] = TwosquareKeyvalToLetter(itemPtr, pt2cell, FIXEDSQUARE);
	if (twoPtr->pt[i+1] == '\0') {
	    twoPtr->pt[i+1] = ' ';
	}
    }
    twoPtr->pt[itemPtr->length] = '\0';
	
    return twoPtr->pt;
}

static int
RestoreTwosquare(Tcl_Interp *interp, CipherItem *itemPtr, const char *square1, const char *square2)
{
    TwosquareItem *twoPtr = (TwosquareItem *)itemPtr;
    char keyLength[TCL_DOUBLE_SPACE];
    int i;

    if (strlen(square1) != KEYLEN) {
	sprintf(keyLength, "%ld", strlen(square1));
	Tcl_AppendResult(interp, "Key '", square1, "' has invalid length ", keyLength, (char *)NULL);
	return TCL_ERROR;
    }

    if (strlen(square2) != KEYLEN) {
	sprintf(keyLength, "%ld", strlen(square2));
	Tcl_AppendResult(interp, "Key '", square2, "' has invalid length ", keyLength, (char *)NULL);
	return TCL_ERROR;
    }

    for(i=0; i < KEYLEN; i++) {
	int keyIndex = TwosquareKeyPairToIndex(i/5+1, i%5+1);

	if (! IsValidChar(itemPtr, square1[i]) && square1[i] != ' ') {
	    Tcl_SetResult(interp, "Invalid character found in key",
		    TCL_VOLATILE);
	    return TCL_ERROR;
	}
	if (! IsValidChar(itemPtr, square2[i]) && square2[i] != ' ') {
	    Tcl_SetResult(interp, "Invalid character found in key",
		    TCL_VOLATILE);
	    return TCL_ERROR;
	}

	if (square1[i] != ' ') {
	    twoPtr->ptkey[SQUARE1][keyIndex] = square1[i];
	    twoPtr->ctkey[SQUARE1][TwosquareKeycharToInt(square1[i])] = keyIndex;
	} else {
	    twoPtr->ptkey[SQUARE1][keyIndex] = EMPTY;
	}
	if (square2[i] != ' ') {
	    twoPtr->ptkey[SQUARE2][keyIndex] = square2[i];
	    twoPtr->ctkey[SQUARE2][TwosquareKeycharToInt(square2[i])] = keyIndex;
	} else {
	    twoPtr->ptkey[SQUARE2][keyIndex] = EMPTY;
	}

    }

    Tcl_SetResult(interp, "", TCL_VOLATILE);
    return TCL_OK;
}

static int
SolveTwosquare(Tcl_Interp *interp, CipherItem *itemPtr, char *result)
{
    Tcl_SetResult(interp, "You cheat!", TCL_VOLATILE);
    return TCL_ERROR;
}

static char *
TwosquareLetterToKeyval(CipherItem *itemPtr, char letter, int squareID)
{
    TwosquareItem *twoPtr = (TwosquareItem *)itemPtr;
    int keyIndex=0;

    if ((letter < 'a' || letter > 'z')) {
	return (char *)NULL;
    }

    keyIndex = TwosquareKeycharToInt(letter);
    if (squareID == FIXEDSQUARE) {
	keyIndex += (7 + keyIndex/5);
    }

    if (twoPtr->ctkey[squareID][keyIndex] == EMPTY) {
	return (char *)NULL;
    }

    return twoPtr->keyConv[(int)(twoPtr->ctkey[squareID][keyIndex])];
}

static int
TwosquareKeyvalToLetter(CipherItem *itemPtr, const char *keyVal, int squareID)
{
    TwosquareItem *twoPtr = (TwosquareItem *)itemPtr;
    int letterIndex;

    if (!keyVal[0] || !keyVal[1]) {
	return '\0';
    }

    if ( (keyVal[0] != KEY1 && keyVal[0] != KEY2 && keyVal[0] != KEY3
		&& keyVal[0] != KEY4 && keyVal[0] != KEY5)
	    || (keyVal[1] != KEY1 && keyVal[1] != KEY2 && keyVal[1] != KEY3
		&& keyVal[1] != KEY4 && keyVal[1] != KEY5)) {
	return '\0';
    }

    letterIndex = (keyVal[0]-'0') * 6 + (keyVal[1]-'0');

    if (twoPtr->ptkey[squareID][letterIndex] != EMPTY) {
	return twoPtr->ptkey[squareID][letterIndex];
    } else {
	return '\0';
    }
}

static char *
EncodeFoursquareString(CipherItem *itemPtr, const char *pt) {
    TwosquareItem *twoPtr = (TwosquareItem *)itemPtr;
    int		i;

    /*
     * Convert every digram to its ciphertext equivalent.
     */

    for(i=0; i < itemPtr->length; i += 2) {
	char pt1 = pt[i];
	char pt2 = pt[i+1];
	/*
	char *pt1cell = TwosquareLetterToKeyval(itemPtr, pt1, FIXEDSQUARE);
	char *pt2cell = TwosquareLetterToKeyval(itemPtr, pt2, FIXEDSQUARE);
	*/
	int pt1keyIndex = TwosquareKeycharToInt(pt[i]);
	int pt2keyIndex = TwosquareKeycharToInt(pt[i+1]);
	char ct1cell[2];
	char ct2cell[2];

	/*
	ct1cell[0] = pt1cell[0];
	ct1cell[1] = pt2cell[1];

	ct2cell[0] = pt2cell[0];
	ct2cell[1] = pt1cell[1];
	*/
	ct1cell[0] = pt1keyIndex/5 + '1';
	ct1cell[1] = pt2keyIndex%5 + '1';

	ct2cell[0] = pt2keyIndex/5 + '1';
	ct2cell[1] = pt1keyIndex%5 + '1';

	twoPtr->pt[i] = TwosquareKeyvalToLetter(itemPtr, ct1cell, SQUARE1);
	if (twoPtr->pt[i] == '\0') {
	    twoPtr->pt[i] = ' ';
	}

	twoPtr->pt[i+1] = TwosquareKeyvalToLetter(itemPtr, ct2cell, SQUARE2);
	if (twoPtr->pt[i+1] == '\0') {
	    twoPtr->pt[i+1] = ' ';
	}
    }
    twoPtr->pt[itemPtr->length] = '\0';
	
    return twoPtr->pt;
}

static int
EncodeTwosquare(Tcl_Interp *interp, CipherItem *itemPtr, const char *pt, const char *key) {
    char *ct = (char *)NULL;
    char *newPt = (char *)NULL;
    char *tempCt = (char *)NULL;
    int count;
    int i;
    const char **argv;

    if (Tcl_SplitList(interp, key, &count, &argv) != TCL_OK) {
	return TCL_ERROR;
    }

    if (count != 2) {
	ckfree((char *)argv);
	Tcl_AppendResult(interp, "Invalid number of items in encoding key '",
	      key, "'.  Should have found 2.", (char *)NULL);
	return TCL_ERROR;
    }

    if (strlen(argv[0]) != 25 || strlen(argv[1]) != 25) {
	Tcl_SetResult(interp, "Invalid length of key elements.", TCL_STATIC);
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    /*
     * Add a cryptographic null to create plaintext with an even number
     * of letters.
     */
    tempCt = ExtractValidCharsJtoI(itemPtr, pt);
    newPt = (char *)ckalloc(sizeof(char) * (strlen(tempCt) + 2));

    for (i=0; i < strlen(tempCt); i++) {
        newPt[i] = tempCt[i];
    }
    if (strlen(tempCt) % 2 == 1) {
        newPt[i] = 'x';
        newPt[i+1] = '\0';
    } else {
        newPt[i] = '\0';
    }
    ckfree((char *)tempCt);

    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, newPt) != TCL_OK) {
	ckfree((char *)argv);
	ckfree((char *)newPt);
	return TCL_ERROR;
    }

    if (strcmp(itemPtr->typePtr->type, "foursquare") == 0) {
        if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[0], argv[1]) != TCL_OK) {
            ckfree((char *)argv);
            return TCL_ERROR;
        }
    } else {
        if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1], argv[0]) != TCL_OK) {
            ckfree((char *)argv);
            return TCL_ERROR;
        }
    }
    /*
     * Warning:  The return value from the two/foursquare decipher functions
     * occupies memory managed by the cipher.  Don't explicitly free it.
     */

    if (strcmp(itemPtr->typePtr->type, "foursquare") == 0) {
        ct = EncodeFoursquareString(itemPtr, newPt);
    } else {
        ct = (itemPtr->typePtr->decipherProc)(interp, itemPtr);
    }
    ckfree((char *)newPt);
    if (ct == (char *)NULL) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }
    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, ct) != TCL_OK) {
	ckfree((char *)argv);
	ckfree(ct);
	return TCL_ERROR;
    }
    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[0], argv[1]) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    Tcl_SetResult(interp, itemPtr->ciphertext, TCL_VOLATILE);
    ckfree((char *)argv);

    return TCL_OK;
}
