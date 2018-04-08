/*
 * bigbifid.c --
 *
 *	This file implements the 6x6 Bifid cipher type.
 *
 * Copyright (c) 2000-2004 Michael Thomas <wart@kobold.org>
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

int BigBifidCmd			_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));

#define KEY1	'1'
#define KEY2	'2'
#define KEY3	'3'
#define KEY4	'4'
#define KEY5	'5'
#define KEY6	'6'
#define KEYLEN	36
#define EMPTY	-1

/*
 * Prototypes for procedures only referenced in this file.
 */

static int  CreateBifid	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
static char *GetBifid		_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetBifid		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestoreBifid	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolveBifid		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
static int BifidUndo		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int BifidSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int BifidLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int BifidSetPeriod	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
	    			int));
static int BifidKeyvalToLetter	_ANSI_ARGS_((CipherItem *, char *));
static char *BifidLetterToKeyval _ANSI_ARGS_((CipherItem *, char));
static char *GetBifidText	_ANSI_ARGS_((CipherItem *, char));
static int BifidKeycharToInt	_ANSI_ARGS_((char));
static int EncodeBifid		 _ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));

static char *bifidKeyConv[37] = {   "11", "12", "13", "14", "15", "16",
				    "21", "22", "23", "24", "25", "26",
				    "31", "32", "33", "34", "35", "36",
				    "41", "42", "43", "44", "45", "46",
				    "51", "52", "53", "54", "55", "56",
				    "61", "62", "63", "64", "65", "66" };
/*
 * This structure contains the data associated with a single bifid cipher.
 */

typedef struct BigbifidItem {
    CipherItem header;

    char ptkey[KEYLEN];	/* The indices are the key values (111, 213, etc.)
			   The values are the letters that the values stand
			   for. */
    char ctkey[KEYLEN];	/* The indices are the letters, the values are the
			   key values that letters correspond to 
			   (111, 2 3, etc).  Note that these need not be
			   full key values, as in the case of '2 3'.*/
    char **keyConv;

} BigbifidItem;

/*
 * This structure joins the data for an bifid cipher with common routines
 * used to manipulate it.
 */

CipherType BigbifidType = {
    "bigbifid",
    ATOZONETONINE,
    sizeof(BigbifidItem),
    CreateBifid,	/* create proc */
    DeleteCipher,	/* delete proc */
    BigBifidCmd,	/* cipher command proc */
    GetBifid,		/* get plaintext proc */
    SetBifid,		/* show ciphertext proc */
    SolveBifid,		/* solve cipher proc */
    RestoreBifid,	/* restore proc */
    BifidLocateTip,	/* locate proc */
    BifidSubstitute,	/* sub proc */
    BifidUndo,		/* undo proc */
    EncodeBifid,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

/*
 * CreateBifid --
 *
 *	Create a new bifid cipher item.
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
CreateBifid(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    BigbifidItem *bifPtr = (BigbifidItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    bifPtr->header.period = 0;

    bifPtr->keyConv = bifidKeyConv;

    for(i=0; i < KEYLEN; i++) {
	bifPtr->ptkey[i] = EMPTY;
	bifPtr->ctkey[i] = EMPTY;
    }

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, BigBifidCmd, itemPtr,
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

int
BigBifidCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    BigbifidItem *bifPtr = (BigbifidItem *)clientData;
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
	if (strncmp(argv[1], "-length", 6) == 0) {
	    sprintf(temp_str, "%d", bifPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", bifPtr->header.period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!bifPtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_STATIC);
	    } else {
		Tcl_SetResult(interp, bifPtr->header.ciphertext, TCL_VOLATILE);
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-plaintext", 9) == 0 ||
		   strncmp(argv[1], "-ptext", 3) == 0) {
	    tPtr = (itemPtr->typePtr->decipherProc)(interp, itemPtr);

	    if (!tPtr) {
		return TCL_ERROR;
	    }

	    Tcl_SetResult(interp, tPtr, TCL_DYNAMIC);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-bifidtext", 9) == 0 ||
		   strncmp(argv[1], "-btext", 3) == 0) {
	    tPtr = GetBifidText(itemPtr, ' ');

	    if (!tPtr) {
		Tcl_SetResult(interp, "", TCL_STATIC);
	    } else {
		Tcl_SetResult(interp, tPtr, TCL_DYNAMIC);
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-key", 4) == 0) {
	    for(i=0; i < KEYLEN; i++) {
		temp_str[i] = (bifPtr->ptkey[i]==EMPTY)?' ':bifPtr->ptkey[i];
	    }
	    temp_str[i] = '\0';

	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
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
	    } else if (strncmp(*argv, "-period", 7) == 0) {
		int period;

		if (sscanf(argv[1], "%d", &period) != 1) {
		    Tcl_SetResult(interp, "Invalid period setting.",
			    TCL_STATIC);
		    return TCL_ERROR;
		}

		return BifidSetPeriod(interp, itemPtr, period);
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
	/*
	 * Bifid restoration only looks at the first value in the restore
	 * argument list, but we need to accept a dummy second argument
	 * so that all cipher restore procs can be called identically.
	 */
	if (argc < 2 || argc > 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " restore key",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	return (itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1], (char *)NULL);
    } else if (**argv == 'e' && (strncmp(*argv, "encode", 1) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " encode pt key",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	return (itemPtr->typePtr->encodeProc)(interp, itemPtr, argv[1], argv[2]);
    } else if (**argv == 's' && (strncmp(*argv, "substitute", 2) == 0)) {
	if (argc != 4) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " substitute row col pt",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	if (*argv[1] < KEY1 || *argv[1] > KEY6) {
	    Tcl_SetResult(interp,
		    "Invalid row value.  Value must be between 1 and 6.",
		    TCL_STATIC);
	    return TCL_ERROR;
	}
	if (*argv[2] < KEY1 || *argv[2] > KEY6) {
	    Tcl_SetResult(interp,
		    "Invalid column value.  Value must be between 1 and 6.",
		    TCL_STATIC);
	    return TCL_ERROR;
	}
	if (! IsValidChar(itemPtr, *argv[3])) {
	    Tcl_SetResult(interp, "Invalid letter value.", TCL_STATIC);
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
	    Tcl_SetResult(interp, "", TCL_STATIC);
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
			" restore key", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" undo ct", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" locate pt ct", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" encode pt key", (char *)NULL);
	return TCL_ERROR;
    }
}

static int
SetBifid(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
{
    char	*c;
    int		valid = TCL_OK,
    		length=0;

    length = CountValidChars(itemPtr, ctext, (int *)NULL);

    if (!length) {
	Tcl_SetResult(interp, "No valid characters found in the ciphertext",
		TCL_STATIC);
	return TCL_ERROR;
    }

    c = ExtractValidChars(itemPtr, ctext);
    if (!c) {
	Tcl_SetResult(interp, "Could not extract ciphertext from string",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (valid==TCL_OK) {
	itemPtr->length = length;
	if (itemPtr->ciphertext) {
	    ckfree(itemPtr->ciphertext);
	}
	itemPtr->ciphertext = c;

	if (itemPtr->ciphertext == NULL) {
	    Tcl_SetResult(interp, "Error mallocing memory for new cipher", TCL_STATIC);
	    return TCL_ERROR;
	}

	itemPtr->length = length;

	Tcl_SetResult(interp, itemPtr->ciphertext, TCL_STATIC);
    }

    return valid;
}

static int
BifidLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, const char *tip, const char *start)
{
    Tcl_SetResult(interp,
	    "No locate tip function defined for bigbifid ciphers.",
	    TCL_STATIC);
    return TCL_ERROR;
}

static int
BifidUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int dummy)
{
    BigbifidItem *bifPtr = (BigbifidItem *)itemPtr;
    int keyIndex;
    const char *c;

    for(c = ct; *c; c++) {
	char ctConv = *c;

	if (! IsValidChar(itemPtr, ctConv)) {
	    Tcl_SetResult(interp, "Attempt to undo invalid character.",
		    TCL_STATIC);
	    return TCL_ERROR;
	} else {
	    int ctConvIndex = BifidKeycharToInt(ctConv);

	    keyIndex = bifPtr->ctkey[ctConvIndex];
	    if (keyIndex != EMPTY) {
		bifPtr->ptkey[keyIndex] = EMPTY;
		bifPtr->ctkey[ctConvIndex] = EMPTY;
	    }
	}
    }

    return TCL_OK;
}

static int
BifidSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *row, const char *col, int value)
{
    BigbifidItem *bifPtr = (BigbifidItem *)itemPtr;
    int valid_sub=NEW_SUB;
    char ptLetter = (char)value;
    int ptLetterIndex = 0;
    int keyIndex = 0;
    int iRow = *row-'1';
    int iCol = *col-'1';

    ptLetterIndex = BifidKeycharToInt(ptLetter);

    /*
     * If this letter is already in use then update its position in the key.
     */

    keyIndex = iRow * 6 + iCol;
    if (bifPtr->ptkey[keyIndex] != EMPTY) {
	int oldPtIndex;
	valid_sub = ALT_SUB;
	oldPtIndex = BifidKeycharToInt(bifPtr->ptkey[keyIndex]);
	bifPtr->ctkey[oldPtIndex] = EMPTY;
    }
    bifPtr->ptkey[keyIndex] = ptLetter;

    if (bifPtr->ctkey[ptLetterIndex] != EMPTY) {
	valid_sub = ALT_SUB;
	bifPtr->ptkey[(int)(bifPtr->ctkey[ptLetterIndex])] = EMPTY;
    }
    bifPtr->ctkey[ptLetterIndex] = keyIndex;

    return valid_sub;
}

static int
BifidKeycharToInt(char c) {
    if (c >= 'a' && c <= 'z') {
	c = c - 'a';
    } else if (c >= '0' && c <= '9') {
	c = c - '0' + 26;
    } else {
	c = '\0';
    }

    return c;
}

static char *
GetBifid(Tcl_Interp *interp, CipherItem *itemPtr)
{
    int		i;
    char	*pt=(char *)NULL;
    char	*bifVal=(char *)NULL;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp, "Can't do anything until ciphertext has been set",
		TCL_STATIC);
	return (char *)NULL;
    }

    if (itemPtr->period <= 0) {
	Tcl_SetResult(interp, "Can't do anything until a period has been set",
		TCL_STATIC);
	return (char *)NULL;
    }

    pt=(char *)ckalloc(sizeof(char) * itemPtr->length+1);

    /*
     * Fill in the array of intermediate bifid values
     */

    bifVal=GetBifidText(itemPtr, '\0');

    /*
     * Read out the plaintext from the bifid array
     */

    for(i=0; i < itemPtr->length; i++) {
	int blockNum = i/itemPtr->period;
	int blockStart = blockNum*itemPtr->period*2;
	int blockLength = itemPtr->period*2;
	int blockPeriod = itemPtr->period;
	char keyVal[3];
	
	if (itemPtr->length*2 - blockStart < blockLength) {
	    blockLength = itemPtr->length*2 - blockStart;
	    blockPeriod = blockLength / 2;
	}

	if (blockStart + i%itemPtr->period + 1*blockPeriod > itemPtr->length * 2) {
	    fprintf(stderr, "Invalid index\n");
	    abort();
	}
	keyVal[0] = bifVal[blockStart + i%itemPtr->period + 0*blockPeriod];
	keyVal[1] = bifVal[blockStart + i%itemPtr->period + 1*blockPeriod];
	keyVal[2] = '\0';
	pt[i] = BifidKeyvalToLetter(itemPtr, keyVal);
	if (pt[i] == '\0') {
	    pt[i] = ' ';
	}
    }
    pt[i] = '\0';
    ckfree(bifVal);

    return pt;
}

static char *
GetBifidText(CipherItem *itemPtr, char emptyChar) {
    int i;
    char *c = itemPtr->ciphertext;
    char *bifVal=(char *)NULL;

    if (!c) {
	return (char *)NULL;
    }

    if (!itemPtr->period) {
	return (char *)NULL;
    }

    bifVal=(char *)ckalloc(sizeof(char) * itemPtr->length * 2 + 1);

    for(i=0; i < itemPtr->length; i++) {
	char *keyVal = BifidLetterToKeyval(itemPtr, c[i]);

	if (keyVal) {
	    bifVal[i*2+0] = keyVal[0];
	    bifVal[i*2+1] = keyVal[1];
	} else {
	    bifVal[i*2+0] = emptyChar;
	    bifVal[i*2+1] = emptyChar;
	}
    }
    bifVal[itemPtr->length*2] = '\0';

    return bifVal;
}

static int
RestoreBifid(Tcl_Interp *interp, CipherItem *itemPtr, const char *savedKey, const char *dummy)
{
    BigbifidItem *bifPtr = (BigbifidItem *)itemPtr;
    int i;
    int validKey = 1;
    int tempReverseKey[KEYLEN];
    int tempKeyPos;
    char keyChar;

    if (strlen(savedKey) != KEYLEN) {
	Tcl_SetResult(interp, "Invalid length for key.", TCL_STATIC);
	return TCL_ERROR;
    }

    for(i=0; i < KEYLEN; i++) {
	tempReverseKey[i] = '\0';
    }

    for(i=0; i < KEYLEN; i++) {
	keyChar = savedKey[i];
	tempKeyPos = BifidKeycharToInt(keyChar);

	if (keyChar == ' ') {
	} else if (! IsValidChar(itemPtr, keyChar)) {
	    validKey = 0;
	} else {
	    if(tempReverseKey[tempKeyPos]) {
		validKey = 0;
	    } else {
		tempReverseKey[tempKeyPos] = keyChar;
	    }
	}
    }

    if (!validKey) {
	Tcl_SetResult(interp, "Invalid key.", TCL_STATIC);
	return TCL_ERROR;
    }

    for(i=0; i < KEYLEN; i++) {
	keyChar = savedKey[i];
	tempKeyPos = BifidKeycharToInt(keyChar);

	if (keyChar != ' ') {
	    bifPtr->ctkey[tempKeyPos] = i;
	    bifPtr->ptkey[i] = keyChar;
	}
    }

    Tcl_SetObjResult(interp, Tcl_NewStringObj(savedKey, -1));
    return TCL_OK;
}

static int
SolveBifid(Tcl_Interp *interp, CipherItem *itemPtr, char *result)
{
    Tcl_SetResult(interp, "You cheat!", TCL_STATIC);
    return TCL_ERROR;
}

static char *
BifidLetterToKeyval(CipherItem *itemPtr, char letter)
{
    BigbifidItem *bifPtr = (BigbifidItem *)itemPtr;
    int keyIndex=0;

    if (! IsValidChar(itemPtr, letter)) {
	return (char *)NULL;
    }

    keyIndex = BifidKeycharToInt(letter);

    if (bifPtr->ctkey[keyIndex] == EMPTY) {
	return (char *)NULL;
    }

    return bifPtr->keyConv[(int)(bifPtr->ctkey[keyIndex])];
}

static int
BifidKeyvalToLetter(CipherItem *itemPtr, char *keyVal)
{
    BigbifidItem *bifPtr = (BigbifidItem *)itemPtr;
    int letterIndex;

    if (!keyVal[0] || !keyVal[1]) {
	return '\0';
    }

    if ( (keyVal[0] != KEY1 && keyVal[0] != KEY2 && keyVal[0] != KEY3
	    && keyVal[0] != KEY4 && keyVal[0] != KEY5 && keyVal[0] != KEY6)
	    || (keyVal[1] != KEY1 && keyVal[1] != KEY2 && keyVal[1] != KEY3
	    && keyVal[1] != KEY4 && keyVal[1] != KEY5 && keyVal[1] != KEY6)) {
	return '\0';
    }

    letterIndex = (keyVal[0]-'1') * 6 + (keyVal[1]-'1');

    if (bifPtr->ptkey[letterIndex] != EMPTY) {
	return bifPtr->ptkey[letterIndex];
    } else {
	return '\0';
    }
}

static int
BifidSetPeriod(Tcl_Interp *interp, CipherItem *itemPtr, int period)
{
    char result[16];

    sprintf(result, "%d", period);

    if (period < 2) {
	Tcl_AppendResult(interp, "Bad period for cipher:  ", result, (char *)NULL);
	return TCL_ERROR;
    }

    if (itemPtr->period == period) {
	Tcl_SetResult(interp, result, TCL_VOLATILE);
	return TCL_OK;
    }

    itemPtr->period = period;

    return TCL_OK;
}

/*
 * Encode a string of plaintext using the key/period found in an
 * existing bifid cipher.
 */
static char *
EncodeBifidString(CipherItem *itemPtr, char *pt) {
    char *ct = (char *)NULL;
    char *bifVal = (char *)NULL;
    int i;

    /*
     * Generate the bifid text  
     */

    bifVal=(char *)ckalloc(sizeof(char) * (strlen(pt) + 1) * 2);
    for (i=0; i < itemPtr->length; i++) {
	int blockNum = i/itemPtr->period;
	int blockStart = blockNum*itemPtr->period*2;
	int blockLength = itemPtr->period*2;
	int blockPeriod = itemPtr->period;
	int blockCol = i % itemPtr->period;
	char *keyVal = BifidLetterToKeyval(itemPtr, pt[i]);

	if (itemPtr->length*2 - blockStart < blockLength) {
	    blockLength = itemPtr->length*2 - blockStart;
	    blockPeriod = blockLength / 2;
	}

	if (keyVal != NULL) {
	    bifVal[blockStart + blockCol] = keyVal[0];
	    bifVal[blockStart + blockCol + blockPeriod] = keyVal[1];
	} else {
	    ckfree((char *)bifVal);
	    return (char *)NULL;
	}
    }

    /*
     * Extract the ciphertext from the bifid text.
     */
    ct=(char *)ckalloc(sizeof(char) * (strlen(pt) + 1));
    for (i=0; i < itemPtr->length; i++) {
	ct[i] = '-';
    }
    for (i=0; i < itemPtr->length; i++) {
	ct[i] = BifidKeyvalToLetter(itemPtr, bifVal + i*2);
    }
    ct[i] = '\0';
    ckfree(bifVal);

    return ct;
}

static int
EncodeBifid(Tcl_Interp *interp, CipherItem *itemPtr, const char *pt, const char *key) {
    char *ct = (char *)NULL;
    int count;
    const char **argv;

    if (Tcl_SplitList(interp, key, &count, &argv) != TCL_OK) {
	return TCL_ERROR;
    }

    if (itemPtr->period < 1) {
	ckfree((char *)argv);
	Tcl_SetResult(interp,
		"Can not encode bifid until a period has been set.",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (count != 1) {
	ckfree((char *)argv);
	Tcl_AppendResult(interp, "Invalid number of items in encoding key '",
	      key, "'.  Should have found 1.", (char *)NULL);
	return TCL_ERROR;
    }

    if (strlen(argv[0]) != 36) {
	Tcl_Obj *intObj = Tcl_NewIntObj(strlen(argv[0]));
	Tcl_AppendResult(interp, "Invalid length of key: ", Tcl_GetString(intObj), (char *)NULL);
	Tcl_DecrRefCount(intObj);
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    /*
     * The plaintext and ciphertext alphabets use the same set of
     * characters.  Set the current item's ciphertext in order to
     * validate the plaintext string.
     */

    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, pt) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    /*
     * Validate and store the key in the current item.  The key functions used
     * by the encoder assume the current item has the encoding key.
     */

    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[0], (char *)NULL)
	    != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    ct = EncodeBifidString(itemPtr, itemPtr->ciphertext);
    if (ct == NULL) {
	Tcl_SetResult(interp, "Inconsistency check failed for encoding key.  Are there blanks in the key?", TCL_STATIC);
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    /*
     * Now make the cipher item consistent by setting the item's ciphertext
     * to the newly calcualted ciphertext and applying the key.
     */
    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, ct) != TCL_OK) {
	ckfree((char *)argv);
	ckfree(ct);
	return TCL_ERROR;
    }
    ckfree(ct);

    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[0], (char *)NULL) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    Tcl_SetResult(interp, itemPtr->ciphertext, TCL_VOLATILE);
    ckfree((char *)argv);
    return TCL_OK;
}
