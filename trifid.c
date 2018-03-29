/*
 * trifid.c --
 *
 *	This file implements the trifid cipher type.
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

int TrifidCmd			_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));

#define KEY1	'1'
#define KEY2	'2'
#define KEY3	'3'
#define KEYLEN	27
#define EMPTY	-1

/*
 * Prototypes for procedures only referenced in this file.
 */

static int  CreateTrifid	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
static char *GetTrifid		_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetTrifid		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestoreTrifid	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolveTrifid		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
static int TrifidUndo		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int TrifidSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int TrifidLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int TrifidSetPeriod	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
	    			int));
static char TrifidKeyvalToLetter	_ANSI_ARGS_((CipherItem *, const char *));
static char *TrifidLetterToKeyval _ANSI_ARGS_((CipherItem *, char));
static char *GetTrifidText	_ANSI_ARGS_((CipherItem *, char));
static int EncodeTrifid		 _ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static char *EncodeTrifidString	 _ANSI_ARGS_((CipherItem *, char *));

static char *trifidKeyConv[27] = {
	"111", "112", "113", "121", "122", "123", "131", "132", "133",
	"211", "212", "213", "221", "222", "223", "231", "232", "233",
	"311", "312", "313", "321", "322", "323", "331", "332", "333"};

/*
 * This structure contains the data associated with a single trifid cipher.
 */

typedef struct TrifidItem {
    CipherItem header;

    char ptkey[KEYLEN];	/* The indices are the key values (111, 213, etc.)
			   The values are the letters that the values stand
			   for. */
    char ctkey[KEYLEN];	/* The indices are the letters, the values are the
			   key values that letters correspond to 
			   (111, 2 3, etc).  Note that these need not be
			   full key values, as in the case of '2 3'.*/
    char **keyConv;

} TrifidItem;

/*
 * This structure joins the data for an trifid cipher with common routines
 * used to manipulate it.
 */

CipherType TrifidType = {
    "trifid",
    "abcdefghijklmnopqrstuvwxyz#",
    sizeof(TrifidItem),
    CreateTrifid,	/* create proc */
    DeleteCipher,	/* delete proc */
    TrifidCmd,		/* cipher command proc */
    GetTrifid,		/* get plaintext proc */
    SetTrifid,		/* show ciphertext proc */
    SolveTrifid,	/* solve cipher proc */
    RestoreTrifid,	/* restore proc */
    TrifidLocateTip,	/* locate proc */
    TrifidSubstitute,	/* sub proc */
    TrifidUndo,		/* undo proc */
    EncodeTrifid,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

/*
 * CreateTrifid --
 *
 *	Create a new trifid cipher item.
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
CreateTrifid(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    TrifidItem *trifPtr = (TrifidItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    trifPtr->header.period = 0;

    trifPtr->keyConv = trifidKeyConv;

    for(i=0; i < KEYLEN; i++) {
	trifPtr->ptkey[i] = EMPTY;
	trifPtr->ctkey[i] = EMPTY;
    }

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, TrifidCmd, itemPtr,
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

int
TrifidCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    TrifidItem *trifPtr = (TrifidItem *)clientData;
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
	    sprintf(temp_str, "%d", trifPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", trifPtr->header.period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!trifPtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_VOLATILE);
	    } else {
		Tcl_SetResult(interp, trifPtr->header.ciphertext, TCL_VOLATILE);
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
	} else if (strncmp(argv[1], "-trifidtext", 9) == 0 ||
		   strncmp(argv[1], "-ttext", 3) == 0) {
	    tPtr = GetTrifidText(itemPtr, ' ');

	    if (!tPtr) {
		Tcl_SetResult(interp, "", TCL_VOLATILE);
	    } else {
		Tcl_SetResult(interp, tPtr, TCL_VOLATILE);
		ckfree(tPtr);
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-key", 4) == 0) {
	    for(i=0; i < KEYLEN; i++) {
		temp_str[i] = (trifPtr->ptkey[i]==EMPTY)?' ':trifPtr->ptkey[i];
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
			    TCL_VOLATILE);
		    return TCL_ERROR;
		}

		return TrifidSetPeriod(interp, itemPtr, period);
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
         * Allow a second restore argument, even though it gets ignored,
         * so that all cipher types can be called the same way.
         */
	if (argc != 2 && argc != 3) {
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
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " substitute ct pt",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	if (strlen(argv[1]) != strlen(argv[2])) {
	    Tcl_SetResult(interp,
		    "ciphertext and plaintext must be the same length",
		    TCL_VOLATILE);
	    return TCL_ERROR;
	}
	if ((itemPtr->typePtr->subProc)(interp, itemPtr, argv[1], argv[2], 0) == BAD_SUB) {
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
			" substitute ct pt", (char *)NULL);
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
SetTrifid(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
{
    char	*c;
    int		valid = TCL_OK,
    		length=0;

    length = CountValidChars(itemPtr, ctext);
    c = ExtractValidChars(itemPtr, ctext);

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

	itemPtr->length = length;

	Tcl_SetResult(interp, itemPtr->ciphertext, TCL_STATIC);
    }

    return valid;
}

static int
TrifidLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, const char *tip, const char *start)
{
    Tcl_SetResult(interp,
	    "No locate tip function defined for trifid ciphers.",
	    TCL_VOLATILE);
    return TCL_ERROR;
}

static int
TrifidUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int dummy)
{
    Tcl_SetResult(interp,
	    "No undo function defined for trifid ciphers.",
	    TCL_VOLATILE);
    return TCL_ERROR;
}

static int
TrifidSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, const char *pt, int dummy)
{
    Tcl_SetResult(interp, "Substitution is not yet defined for trifid ciphers",
	    TCL_VOLATILE);
    return BAD_SUB;
}

static char *
GetTrifid(Tcl_Interp *interp, CipherItem *itemPtr)
{
    int		i;
    char	*pt=(char *)NULL;
    char	*trifVal=(char *)NULL;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp, "Can't do anything until ciphertext has been set",
		TCL_VOLATILE);
	return (char *)NULL;
    }

    if (itemPtr->period <= 0) {
	Tcl_SetResult(interp, "Can't do anything until a period has been set",
		TCL_VOLATILE);
	return (char *)NULL;
    }

    pt=(char *)ckalloc(sizeof(char) * itemPtr->length+1);

    /*
     * Fill in the array of intermediate trifid values
     */
    
    trifVal = GetTrifidText(itemPtr, '\0');

    /*
     * Read out the plaintext from the trifid array
     */

    for(i=0; i < itemPtr->length; i++) {
	int blockNum = i/itemPtr->period;
	int blockStart = blockNum*itemPtr->period*3;
	int blockLength = itemPtr->period*3;
	int blockPeriod = itemPtr->period;
	char keyVal[4];
	
	if (itemPtr->length*3 - blockStart < blockLength) {
	    blockLength = itemPtr->length*3 - blockStart;
	    blockPeriod = blockLength / 3;
	}

	if (blockStart + i%itemPtr->period + 2*blockPeriod > itemPtr->length * 3) {
	    fprintf(stderr, "Invalid index\n");
	    abort();
	}
	keyVal[0] = trifVal[blockStart + i%itemPtr->period + 0*blockPeriod];
	keyVal[1] = trifVal[blockStart + i%itemPtr->period + 1*blockPeriod];
	keyVal[2] = trifVal[blockStart + i%itemPtr->period + 2*blockPeriod];
	keyVal[3] = '\0';
	pt[i] = TrifidKeyvalToLetter(itemPtr, keyVal);
	if (pt[i] == '\0') {
	    pt[i] = ' ';
	}
    }
    pt[i] = '\0';
    ckfree(trifVal);
	
    return pt;
}

static char *
GetTrifidText(CipherItem *itemPtr, char fillChar)
{
    char *trifVal=(char *)ckalloc(sizeof(char) * itemPtr->length * 3 + 1);
    char *c = itemPtr->ciphertext;
    int i;

    for(i=0; i < itemPtr->length; i++) {
	char *keyVal = TrifidLetterToKeyval(itemPtr, c[i]);

	if (keyVal) {
	    trifVal[i*3+0] = keyVal[0];
	    trifVal[i*3+1] = keyVal[1];
	    trifVal[i*3+2] = keyVal[2];
	} else {
	    trifVal[i*3+0] = '\0';
	    trifVal[i*3+1] = '\0';
	    trifVal[i*3+2] = '\0';
	}
    }
    trifVal[itemPtr->length*3] = '\0';

    return trifVal;
}

static int
RestoreTrifid(Tcl_Interp *interp, CipherItem *itemPtr, const char *savedKey, const char *dummy)
{
    TrifidItem *trifPtr = (TrifidItem *)itemPtr;
    int i;
    int validKey = 1;
    int tempReverseKey[KEYLEN];
    int tempKeyPos;
    char tempStr[128];

    if (strlen(savedKey) != KEYLEN) {
	sprintf(tempStr, "%d.  Should be %d", (int) strlen(savedKey), KEYLEN);
	Tcl_AppendResult(interp, "Invalid length for key:  ", (char *)NULL);
	Tcl_AppendResult(interp, tempStr, (char *)NULL);
	return TCL_ERROR;
    }

    for(i=0; i < KEYLEN; i++) {
	tempReverseKey[i] = '\0';
    }

    for(i=0; i < KEYLEN; i++) {
	if (savedKey[i] == ' ') {
	} else if ((savedKey[i] != '#') 
		&& (savedKey[i] < 'a' || savedKey[i] > 'z')) {
	    validKey = 0;
	} else {
	    if (savedKey[i] == '#') {
		tempKeyPos = KEYLEN-1;
	    } else {
		tempKeyPos = savedKey[i] - 'a';
	    }

	    if(tempReverseKey[tempKeyPos]) {
		validKey = 0;
	    } else {
		tempReverseKey[tempKeyPos] = savedKey[i];
	    }
	}
    }

    if (!validKey) {
	Tcl_SetResult(interp, "Invalid key.", TCL_VOLATILE);
	return TCL_ERROR;
    }

    /*
     * Empty out the key so that if there were any missing values in
     * the restored key string they leave uninitialized values.
     */
    for(i=0; i < KEYLEN; i++) {
	trifPtr->ptkey[i] = EMPTY;
	trifPtr->ctkey[i] = EMPTY;
    }

    for(i=0; i < KEYLEN; i++) {
	if (savedKey[i] != ' ') {
	    if (savedKey[i] == '#') {
		tempKeyPos = KEYLEN-1;
	    } else {
		tempKeyPos = savedKey[i] - 'a';
	    }
	    trifPtr->ctkey[tempKeyPos] = i;
	    trifPtr->ptkey[i] = savedKey[i];
	}
    }

    Tcl_SetResult(interp, savedKey, TCL_VOLATILE);
    return TCL_OK;
}

static int
SolveTrifid(Tcl_Interp *interp, CipherItem *itemPtr, char *result)
{
    Tcl_SetResult(interp, "You cheat!", TCL_VOLATILE);
    return TCL_ERROR;
}

static char *
TrifidLetterToKeyval(CipherItem *itemPtr, char letter)
{
    TrifidItem *trifPtr = (TrifidItem *)itemPtr;

    /*
     * The '#' character is a special case.
     */

    if (letter == '#') {
	if (trifPtr->ctkey[KEYLEN-1] == EMPTY) {
	    return (char *)NULL;
	}
	return trifPtr->keyConv[(int)(trifPtr->ctkey[KEYLEN-1])];
    }

    if ((letter < 'a' || letter > 'z')) {
	return (char *)NULL;
    }

    if (trifPtr->ctkey[letter-'a'] == EMPTY) {
	return (char *)NULL;
    }

    return trifPtr->keyConv[(int)(trifPtr->ctkey[(int)(letter-'a')])];
}

static char
TrifidKeyvalToLetter(CipherItem *itemPtr, const char *keyVal)
{
    TrifidItem *trifPtr = (TrifidItem *)itemPtr;
    int letterIndex;

    if ( ((keyVal[0] != KEY1) && (keyVal[0] != KEY2) && (keyVal[0] != KEY3))
	|| ((keyVal[1] != KEY1) && (keyVal[1] != KEY2) && (keyVal[1] != KEY3))
	|| ((keyVal[2] != KEY1) && (keyVal[2] != KEY2) && (keyVal[2] != KEY3))){

	return '\0';
    }

    letterIndex = (keyVal[0]-'1') * 9 + (keyVal[1]-'1') * 3 + (keyVal[2]-'1');

    if (trifPtr->ptkey[letterIndex] != EMPTY) {
	return trifPtr->ptkey[letterIndex];
    } else {
	return '\0';
    }
}

static int
TrifidSetPeriod(Tcl_Interp *interp, CipherItem *itemPtr, int period)
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
 * existing trifid cipher.
 */
static char *
EncodeTrifidString(CipherItem *itemPtr, char *pt) {
    char *ct = (char *)NULL;
    char *trifVal = (char *)NULL;
    int i;

    /*
     * Generate the trifid text  
     */

    trifVal=(char *)ckalloc(sizeof(char) * strlen(pt) * 3 + 1);
    for (i=0; i < itemPtr->length; i++) {
	int blockNum = i/itemPtr->period;
	int blockStart = blockNum*itemPtr->period*3;
	int blockLength = itemPtr->period*3;
	int blockPeriod = itemPtr->period;
	int blockCol = i % itemPtr->period;
	char *keyVal = TrifidLetterToKeyval(itemPtr, pt[i]);

	if (itemPtr->length*3 - blockStart < blockLength) {
	    blockLength = itemPtr->length*3 - blockStart;
	    blockPeriod = blockLength / 3;
	}

	if (keyVal != NULL) {
	    trifVal[blockStart + blockCol] = keyVal[0];
	    trifVal[blockStart + blockCol + blockPeriod] = keyVal[1];
	    trifVal[blockStart + blockCol + blockPeriod*2] = keyVal[2];
	} else {
	    ckfree((char *)trifVal);
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
	ct[i] = TrifidKeyvalToLetter(itemPtr, trifVal + i*3);
    }
    ct[i] = '\0';
    ckfree(trifVal);

    return ct;
}

static int
EncodeTrifid(Tcl_Interp *interp, CipherItem *itemPtr, const char *pt, const char *key) {
    char *ct = (char *)NULL;
    int count;
    const char **argv;

    if (Tcl_SplitList(interp, key, &count, &argv) != TCL_OK) {
	return TCL_ERROR;
    }

    if (itemPtr->period < 1) {
	ckfree((char *)argv);
	Tcl_SetResult(interp,
		"Can not encode trifid until a period has been set.",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (count != 1) {
	ckfree((char *)argv);
	Tcl_AppendResult(interp, "Invalid number of items in encoding key '",
	      key, "'.  Should have found 1.", (char *)NULL);
	return TCL_ERROR;
    }

    if (strlen(argv[0]) != 27) {
	Tcl_SetResult(interp, "Invalid length of key elements.", TCL_STATIC);
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

    ct = EncodeTrifidString(itemPtr, itemPtr->ciphertext);
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
	ckfree(ct);
	ckfree((char *)argv);
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
