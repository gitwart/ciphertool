/*
 * bifid.c --
 *
 *	This file implements the Bifid cipher type.
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

int BifidCmd			_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, char **));

#define KEY0	'0'
#define KEY1	'1'
#define KEY2	'2'
#define KEY3	'3'
#define KEY4	'4'
#define KEY5	'5'
#define KEYLEN	25
#define EMPTY	-1

/*
 * Prototypes for procedures only referenced in this file.
 */

static int  CreateBifid	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, char **));
static char *GetBifid		_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetBifid		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
static int  RestoreBifid	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *));
static int  SolveBifid		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
static int BifidUndo		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, int));
static int BifidSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *, int));
static int BifidLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *));
static int BifidSetPeriod	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
	    			int));
static int BifidKeyvalToLetter	_ANSI_ARGS_((CipherItem *, char *));
static char *BifidLetterToKeyval _ANSI_ARGS_((CipherItem *, char));
static char *GetBifidText	_ANSI_ARGS_((CipherItem *, char));
static int BifidKeycharToInt	_ANSI_ARGS_((char));
static int BifidKeyPairToIndex	_ANSI_ARGS_((int, int));
static int BifidIsCompleteKeyIndex	_ANSI_ARGS_((int));
static int BifidMergeSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *, int));
static int BifidIsValidTipPlacement _ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, int));
static int EncodeBifid		 _ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *));

/*
 * This structure contains the data associated with a single bifid cipher.
 */

char *bifidKeyConv[36] = {"00", "01", "02", "03", "04", "05",
			  "10", "11", "12", "13", "14", "15",
			  "20", "21", "22", "23", "24", "25",
			  "30", "31", "32", "33", "34", "35",
			  "40", "41", "42", "43", "44", "45",
			  "50", "51", "52", "53", "54", "55"};

typedef struct BifidItem {
    CipherItem header;

    char ptkey[KEYLEN+11];	/* The indices are the key values (11, 23, etc.)
			   The values are the letters that the values stand
			   for. */
    char ctkey[KEYLEN];	/* The indices are the letters, the values are the
			   key values that letters correspond to 
			   (11, 2_, etc).  Note that these need not be
			   full key values, as in the case of '2_'.*/
    char **keyConv;	/* Mapping from a unique key index to a row/column
			   pair. */

} BifidItem;

/*
 * This structure joins the data for an bifid cipher with common routines
 * used to manipulate it.
 */

CipherType BifidType = {
    "bifid",
    ATOZNOJ,
    sizeof(BifidItem),
    CreateBifid,	/* create proc */
    DeleteCipher,	/* delete proc */
    BifidCmd,		/* cipher command proc */
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
CreateBifid(Tcl_Interp *interp, CipherItem *itemPtr, int argc, char **argv)
{
    BifidItem *bifPtr = (BifidItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    bifPtr->header.period = 0;
    bifPtr->keyConv = bifidKeyConv;

    for(i=0; i < KEYLEN; i++) {
	bifPtr->ctkey[i] = 0;
    }
    for (i=0; i < 36; i++) {
	bifPtr->ptkey[i] = EMPTY;
    }

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, BifidCmd, itemPtr,
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
BifidCmd(ClientData clientData, Tcl_Interp *interp, int argc, char **argv)
{
    BifidItem *bifPtr = (BifidItem *)clientData;
    CipherItem	*itemPtr = (CipherItem *)clientData;
    char	temp_str[256];
    char	*cmd;
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
		Tcl_SetResult(interp, "{}", TCL_VOLATILE);
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
		Tcl_SetResult(interp, "", TCL_VOLATILE);
	    } else {
		Tcl_SetResult(interp, tPtr, TCL_VOLATILE);
		ckfree(tPtr);
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-keyword", 5) == 0) {
	    int temp_str_pos=0;
	    for(i=1; i <= 5; i++) {
		int j;
		for(j=1; j <= 5; j++) {
		    int keyIndex = BifidKeyPairToIndex(i, j);
		    char keyLetter = bifPtr->ptkey[keyIndex];

		    if (keyLetter != EMPTY) {
			temp_str[temp_str_pos++] = keyLetter;
		    } else {
			temp_str[temp_str_pos++] = ' ';
		    }
		}
	    }
	    temp_str[temp_str_pos] = (char)NULL;

	    Tcl_AppendElement(interp, temp_str);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-key", 4) == 0) {
	    int temp_str_pos=0;
	    Tcl_AppendElement(interp, "abcdefghiklmnopqrstuvwxyz");
	    for(i='a'; i <= 'z'; i++) {
		if (i != 'j') {
		    char *keyVal = BifidLetterToKeyval(itemPtr, (char)i);
		    if (keyVal) {
			temp_str[temp_str_pos++] = keyVal[0];
			temp_str[temp_str_pos++] = keyVal[1];
		    } else {
			temp_str[temp_str_pos++] = '0';
			temp_str[temp_str_pos++] = '0';
		    }
		}
	    }
	    temp_str[temp_str_pos] = (char)NULL;

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
	    } else if (strncmp(*argv, "-period", 7) == 0) {
		int period;

		if (sscanf(argv[1], "%d", &period) != 1) {
		    Tcl_SetResult(interp, "Invalid period setting.",
			    TCL_VOLATILE);
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
	if (argc < 2 || argc >  3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " restore pt positions",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	if (argc == 2 || (argc == 3 && strlen(argv[2]) == 0)) {
	    return (itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1], "11121314152122232425313233343541424344455152535455");
	} else {
	    return (itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1], argv[2]);
	}
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
    } else if (**argv == 'm' && (strncmp(*argv, "mergesubstitute", 2) == 0)) {
	if (argc != 4) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd,
		    " mergesubstitute row col pt", (char *)NULL);
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
	if (BifidMergeSubstitute(interp, itemPtr, argv[1], argv[2], *argv[3]) == BAD_SUB) {
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
			" mergesubstitute row col pt", (char *)NULL);
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
SetBifid(Tcl_Interp *interp, CipherItem *itemPtr, char *ctext)
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
BifidLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, char *tip, char *start)
{
    char *tipStart = (char *)NULL;
    char *ct = itemPtr->ciphertext;
    char *c = (char *)NULL;
    char *curTipLetter;
    int valid_tip;
    char *validTipLocation=(char *)NULL;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp,
		"Can't do anything until the ciphertext has been set",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (itemPtr->period <= 0) {
	Tcl_SetResult(interp,
		"Can't do anything until the period has been set",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    /*
     * Locate the starting point
     */

    if (start) {
	tipStart = strstr((const char *)ct, (const char *)start);
    } else {
	tipStart = ct;
    }

    if (!tipStart) {
	Tcl_SetResult(interp, "Starting location not found.", TCL_VOLATILE);
	return TCL_ERROR;
    }

    /*
     * Loop through every possible starting point.
     */

    for(c=tipStart, valid_tip=0;
	    c <= (ct + itemPtr->length - strlen(tip)) && !valid_tip;
	    c++) {

	for(curTipLetter = tip, valid_tip=1;
	    *curTipLetter && valid_tip;
	    curTipLetter++) {
	    valid_tip = 0;

	    /*
	     * Every tip letter must pass either of the following two
	     * tests.  If both fail then the tip position is invalid.
	     *
	     * If one is valid then don't try the other so that we don't
	     * lose the key information.
	     */

	    if (! valid_tip) {
		BifidUndo(interp, itemPtr, itemPtr->typePtr->valid_chars,
			(int)NULL);
		BifidSubstitute(interp, itemPtr, "1", "1",
			(int) (*curTipLetter));
		if (BifidIsValidTipPlacement(interp, itemPtr, tip, c-ct)
			== NEW_SUB) {
		    valid_tip = 1;
		}
	    }

	    if (! valid_tip) {
		BifidUndo(interp, itemPtr, itemPtr->typePtr->valid_chars,
			(int)NULL);
		BifidSubstitute(interp, itemPtr, "1", "2",
			(int) (*curTipLetter));
		if (BifidIsValidTipPlacement(interp, itemPtr, tip, c-ct)
			== NEW_SUB) {
		    valid_tip = 1;
		}
	    }

	    if (valid_tip) {
		validTipLocation = c;
	    }
	}
    }

    /*
     * No valid tip location was found.  Clear out the key so our work
     * is not noticed.  Ideally we would set the key back to what it was
     * before we started teh tip hunt.
     */

    if (! valid_tip) {
	BifidUndo(interp, itemPtr, itemPtr->typePtr->valid_chars, (int)NULL);
	Tcl_SetResult(interp, "", TCL_VOLATILE);
    } else {
	Tcl_SetResult(interp, validTipLocation, TCL_VOLATILE);
    }

    return TCL_OK;
}

static int
BifidIsValidTipPlacement(Tcl_Interp *interp, CipherItem *itemPtr, char *tip, int startPos)
{
    BifidItem *bifPtr = (BifidItem *)itemPtr;
    int sub_made = 1;
    int valid_sub = NEW_SUB;
    char *bifVal = (char *)NULL;
    char *tipLetter;
    int loopCount=0;

    while (valid_sub == NEW_SUB && sub_made) {
	bifVal = GetBifidText(itemPtr, KEY0);
	/*
	fprintf(stderr, "Iteration %d\n", loopCount);
	fprintf(stderr, "bifVal: %s\n", bifVal);
	*/
	sub_made = 0;
	/*
	 * Merge what is known about every tip letter with what appears in
	 * the bifid text.
	 */

	for (tipLetter = tip; *tipLetter; tipLetter++) {
	    int initialKeyIndex=0;
	    int finalKeyIndex=0;
	    int keyCharVal = 0;
	    char tipBtextValue[3];
	    int ctOffset = startPos + (tipLetter - tip);
	    int blockNum = (ctOffset) / itemPtr->period;
	    int blockStart = blockNum*itemPtr->period*2;
	    int blockLength = itemPtr->period*2;
	    int blockPeriod = itemPtr->period;
	    char tipKeyRowChar;
	    char tipKeyColChar;
	    int tipKeyRow;
	    int tipKeyCol;
	    int rowLetterIndex;
	    char rowLetter;
	    int colLetterIndex;
	    char colLetter;

	    if (itemPtr->length*2 - blockStart < blockLength) {
		blockLength = itemPtr->length*2 - blockStart;
		blockPeriod = blockLength / 2;
	    }

	    keyCharVal = BifidKeycharToInt(*tipLetter);

	    initialKeyIndex = bifPtr->ctkey[keyCharVal];

	    tipKeyRow = bifVal[blockStart + ctOffset%itemPtr->period
		    + 0*blockPeriod];
	    tipKeyCol = bifVal[blockStart + ctOffset%itemPtr->period
		    + 1*blockPeriod];

	    tipBtextValue[0] = tipKeyRow;
	    tipBtextValue[1] = tipKeyCol;
	    tipBtextValue[2] = (char)NULL;

	    /*
	    fprintf(stderr, "MergeSub %c = %c, %c\n",
		    *tipLetter,
		    tipBtextValue[0],
		    tipBtextValue[1]);
	    */

	    if (BifidMergeSubstitute(interp, itemPtr, tipBtextValue,
		    tipBtextValue+1, *tipLetter) != NEW_SUB) {
		/*
		fprintf(stderr, "\tSub failed\n");
		*/
		valid_sub = BAD_SUB;
	    }

	    tipKeyRowChar=bifPtr->keyConv[(int)(bifPtr->ctkey[keyCharVal])][0];
	    tipKeyColChar=bifPtr->keyConv[(int)(bifPtr->ctkey[keyCharVal])][1];
	    
	    /*
	     * Was a substitution made?  That is, did the key value for
	     * the pt letter change?
	     */

	    finalKeyIndex = bifPtr->ctkey[keyCharVal];
	    if (initialKeyIndex != finalKeyIndex) {
		sub_made = 1;
	    }

	    /*
	     * Locate the ct letters touched by the first half of the
	     * key and perform merge substitutions on it.
	     */

	    rowLetterIndex =
		    blockStart + ctOffset%itemPtr->period + 0*blockPeriod;

	    rowLetter = itemPtr->ciphertext[(blockStart
		    + ctOffset%itemPtr->period) / 2];
	    initialKeyIndex = bifPtr->ctkey[BifidKeycharToInt(rowLetter)];
	    if ((ctOffset % itemPtr->period) % 2) {
		/*
		fprintf(stderr, "\tMergeSub %c = %c, %c\n",
			rowLetter,
			'0',
			tipKeyRowChar);
		*/

		if (BifidMergeSubstitute(interp, itemPtr,
			"0", &tipKeyRowChar, rowLetter)
			!= NEW_SUB) {
		    /*
		    fprintf(stderr, "\tSub failed\n");
		    */
		    valid_sub = BAD_SUB;
		}
	    } else {
		/*
		fprintf(stderr, "\tMergeSub %c = %c, %c\n",
			rowLetter,
			tipKeyRowChar,
			'0');
		*/

		if (BifidMergeSubstitute(interp, itemPtr,
			&tipKeyRowChar, "0", rowLetter)
			!= NEW_SUB) {
		    /*
		    fprintf(stderr, "\tSub failed\n");
		    */
		    valid_sub = BAD_SUB;
		}
	    }
	    finalKeyIndex = bifPtr->ctkey[BifidKeycharToInt(rowLetter)];
	    if (initialKeyIndex != finalKeyIndex) {
		/*
		fprintf(stderr, "\tSub Made\n");
		*/
		sub_made = 1;
	    }

	    /*
	     * Locate the ct letters touched by the second half of the
	     * key and perform merge substitutions on it.
	     */

	    colLetterIndex =
		    blockStart + ctOffset%itemPtr->period + 1*blockPeriod;

	    colLetter = itemPtr->ciphertext[(blockStart
		    + ctOffset%itemPtr->period + blockPeriod) / 2];
	    initialKeyIndex = bifPtr->ctkey[BifidKeycharToInt(colLetter)];
	    if ((ctOffset % itemPtr->period + blockPeriod) % 2) {
		/*
		fprintf(stderr, "\tMergeSub %c = %c, %c\n",
			colLetter,
			'0',
			tipKeyColChar);
		*/

		if (BifidMergeSubstitute(interp, itemPtr,
			"0", &tipKeyColChar, colLetter)
			!= NEW_SUB) {
		    /*
		    fprintf(stderr, "\tSub failed\n");
		    */
		    valid_sub = BAD_SUB;
		}
	    } else {
		/*
		fprintf(stderr, "\tMergeSub %c = %c, %c\n",
			colLetter,
			tipKeyColChar,
			'0');
		*/

		if (BifidMergeSubstitute(interp, itemPtr,
			&tipKeyColChar, "0", colLetter)
			!= NEW_SUB) {
		    /*
		    fprintf(stderr, "\tSub failed\n");
		    */
		    valid_sub = BAD_SUB;
		}
	    }
	    finalKeyIndex = bifPtr->ctkey[BifidKeycharToInt(colLetter)];
	    if (initialKeyIndex != finalKeyIndex) {
		/*
		fprintf(stderr, "\tSub Made\n");
		*/
		sub_made = 1;
	    }

	    /*
	     * Count the number of letters whose key entries begin with
	     * each possible row/column.  They should not number more than
	     * the key block width (5).
	     */
	}

	/*
	fprintf(stderr,
		"At end of iteration %d, sub_made = %d, valid_sub = %d\n",
		loopCount, sub_made, valid_sub);
	*/

	loopCount++;

	ckfree(bifVal);
    }

    return valid_sub;
}

static int
BifidUndo(Tcl_Interp *interp, CipherItem *itemPtr, char *ct, int dummy)
{
    BifidItem *bifPtr = (BifidItem *)itemPtr;
    int keyIndex;
    char *c;

    for(c = ct; *c; c++) {
	char ctConv = *c;

	if (! IsValidChar(itemPtr, ctConv)) {
	    Tcl_SetResult(interp, "Attempt to undo invalid character.",
		    TCL_VOLATILE);
	    return TCL_ERROR;
	} else {
	    int ctConvIndex = BifidKeycharToInt(ctConv);

	    keyIndex = bifPtr->ctkey[ctConvIndex];
	    bifPtr->ptkey[keyIndex] = EMPTY;
	    /*
	     * Key index '0' means the letter is in no row or column
	     */
	    bifPtr->ctkey[ctConvIndex] = 0;
	}
    }

    return TCL_OK;
}

static int
BifidSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, char *row, char *col, int value)
{
    BifidItem *bifPtr = (BifidItem *)itemPtr;
    int valid_sub=NEW_SUB;
    char ptLetter = (char)value;
    int ptLetterIndex = (char)NULL;
    int keyIndex = 0;
    int iRow = *row-'0';
    int iCol = *col-'0';
    char altLetter[2];
    altLetter[1] = (char)NULL;

    ptLetterIndex = BifidKeycharToInt(ptLetter);

    keyIndex = BifidKeyPairToIndex(iRow, iCol);
    
    /*
     * Before making any changes to the key, check that we're not trying
     * to put too many letters in a single row/column.
     */

    /*
     * If this letter is already in use then update its position in the key.
     */

    /*
     * Check to see if the cell that we're trying to use is already
     * occupied.
     *
     * Don't mark this as an altermate substitution if it's not a
     * complete key cell description.
     * Don't mark this asn an alternate substitution if we're
     * placing the letter in the cell that it was already in.  That should
     * result in a no-op.
     */
    if (BifidIsCompleteKeyIndex(keyIndex)) {
	if (bifPtr->ptkey[keyIndex] != EMPTY
		&& bifPtr->ptkey[keyIndex] != ptLetter) {
	    int oldPtIndex;
	    valid_sub = ALT_SUB;
	    altLetter[0] = bifPtr->ptkey[keyIndex];
	    oldPtIndex = BifidKeycharToInt(bifPtr->ptkey[keyIndex]);
	    bifPtr->ctkey[oldPtIndex] = 0;
	}
	bifPtr->ptkey[keyIndex] = ptLetter;
    }

    /*
     * If this letter was already in the key then erase its old position.
     *
     * Don't mark it as an alt-substitution if it's previous position
     * was incomplete AND we're placing it in the same column/row that it
     * was originally in.
     */
    if (bifPtr->ctkey[ptLetterIndex] != 0
		&& bifPtr->ctkey[ptLetterIndex] != keyIndex) {
	if (BifidIsCompleteKeyIndex(bifPtr->ctkey[ptLetterIndex])) {
	    valid_sub = ALT_SUB;
	    altLetter[0] = ptLetter;
	} else {
	    char *origCell=bifPtr->keyConv[(int)(bifPtr->ctkey[ptLetterIndex])];
	    char *newCell =bifPtr->keyConv[keyIndex];

	    if (origCell[0] == KEY0 && origCell[1] == newCell[1]) {
	    } else if (origCell[1] == KEY0 && origCell[0] == newCell[0]) {
	    } else {
		valid_sub = ALT_SUB;
		altLetter[0] = ptLetter;
	    }
	}
	/*
	 * We don't need to check that the previous key position is complete
	 * since incomplete key positions are always marked EMPTY.
	 */
	bifPtr->ptkey[(int)(bifPtr->ctkey[ptLetterIndex])] = EMPTY;
    }
    bifPtr->ctkey[ptLetterIndex] = keyIndex;

    if (valid_sub == ALT_SUB) {
	Tcl_SetResult(interp, altLetter, TCL_VOLATILE);
    } else {
	Tcl_SetResult(interp, "", TCL_VOLATILE);
    }

    return valid_sub;
}

static int
BifidMergeSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, char *row, char *col, int value)
{
    BifidItem *bifPtr = (BifidItem *)itemPtr;
    char ptLetter = (char)value;
    int ptLetterIndex = (char)NULL;
    char mRow[2];
    char mCol[2];

    mRow[0] = *row;
    mCol[0] = *col;
    mRow[1] = (char)NULL;
    mCol[1] = (char)NULL;

    ptLetterIndex = BifidKeycharToInt(ptLetter);

    /*
     * Generate a merged key that will actually be substituted for the
     * given key.
     */

    if (mRow[0] == KEY0) {
	mRow[0] = bifPtr->keyConv[(int)(bifPtr->ctkey[ptLetterIndex])][0];
    }

    if (mCol[0] == KEY0) {
	mCol[0] = bifPtr->keyConv[(int)(bifPtr->ctkey[ptLetterIndex])][1];
    }

    return BifidSubstitute(interp, itemPtr, mRow, mCol, value);
}

static int
BifidKeycharToInt(char c) {
    if (c > 'i') {
	c--;
    }
    c -= 'a';

    return c;
}

static int
BifidIsCompleteKeyIndex(int keyIndex)
{
    if (keyIndex == EMPTY) {
	return 0;
    } else if (keyIndex % 6 != 0 && keyIndex > 6) {
	return 1;
    } else {
	return 0;
    }
}

static int
BifidKeyPairToIndex(int row, int col)
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
GetBifid(Tcl_Interp *interp, CipherItem *itemPtr)
{
    int		i;
    char	*pt=(char *)NULL;
    char	*bifVal = (char *)NULL;

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
     * Fill in the array of intermediate bifid values
     */

    bifVal = GetBifidText(itemPtr, (char)NULL);

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
	keyVal[2] = (char)NULL;
	pt[i] = BifidKeyvalToLetter(itemPtr, keyVal);
	if (pt[i] == (char)NULL) {
	    pt[i] = ' ';
	}
    }
    pt[i] = (char)NULL;
    ckfree(bifVal);

    return pt;
}

static char *
GetBifidText(CipherItem *itemPtr, char emptyChar) {
    int i;
    char *c = itemPtr->ciphertext;
    char *bifVal=(char *)ckalloc(sizeof(char) * itemPtr->length * 2 + 1);

    if (!c) {
	return (char *)NULL;
    }

    if (!itemPtr->period) {
	return (char *)NULL;
    }

    for(i=0; i < itemPtr->length; i++) {
	char *keyVal = BifidLetterToKeyval(itemPtr, c[i]);

	if (keyVal) {
	    if (keyVal[0] != KEY0) {
		bifVal[i*2+0] = keyVal[0];
	    } else {
		bifVal[i*2+0] = emptyChar;
	    }
	    if (keyVal[1] != KEY0) {
		bifVal[i*2+1] = keyVal[1];
	    } else {
		bifVal[i*2+1] = emptyChar;
	    }
	} else {
	    abort();
	    /*
	     * bifVal[i*2+0] = emptyChar;
	     * bifVal[i*2+1] = emptyChar;
	     */
	}
    }
    bifVal[itemPtr->length*2] = (char)NULL;

    return bifVal;
}

static int
RestoreBifid(Tcl_Interp *interp, CipherItem *itemPtr, char *pt, char *position)
{
    int i;

    if (strlen(pt) != KEYLEN || strlen(position) != KEYLEN * 2) {
	Tcl_SetResult(interp, "Invalid length for key.", TCL_VOLATILE);
	return TCL_ERROR;
    }

    for(i=0; i < KEYLEN; i++) {
	if (! IsValidChar(itemPtr, pt[i])) {
	    Tcl_SetResult(interp, "Invalid character found in key",
		    TCL_VOLATILE);
	    return TCL_ERROR;
	}
    }

    /*
     * Clear the current key before restoring so we don't detect alternate
     * substitutions from the existing key.
     */

    BifidUndo(interp, itemPtr, itemPtr->typePtr->valid_chars, (int)NULL);

    for(i=0; i < KEYLEN; i++) {
	int result = BifidSubstitute(interp, itemPtr, position + i*2,
		position + i*2+1, pt[i]);
	if (result != NEW_SUB) {
	    if (result == ALT_SUB) {
		Tcl_SetResult(interp, "Duplicate letter/position in key",
			TCL_VOLATILE);
	    }
	    return TCL_ERROR;
	}
    }

    Tcl_SetResult(interp, pt, TCL_VOLATILE);
    return TCL_OK;
}

static int
SolveBifid(Tcl_Interp *interp, CipherItem *itemPtr, char *result)
{
    Tcl_SetResult(interp, "You cheat!", TCL_VOLATILE);
    return TCL_ERROR;
}

static char *
BifidLetterToKeyval(CipherItem *itemPtr, char letter)
{
    BifidItem *bifPtr = (BifidItem *)itemPtr;
    int keyIndex=0;

    if ((letter < 'a' || letter > 'z')) {
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
    BifidItem *bifPtr = (BifidItem *)itemPtr;
    int letterIndex;

    if (!keyVal[0] || !keyVal[1]) {
	return (char)NULL;
    }

    if ( (keyVal[0] != KEY1 && keyVal[0] != KEY2 && keyVal[0] != KEY3
		&& keyVal[0] != KEY4 && keyVal[0] != KEY5)
	    || (keyVal[1] != KEY1 && keyVal[1] != KEY2 && keyVal[1] != KEY3
		&& keyVal[1] != KEY4 && keyVal[1] != KEY5)) {
	return (char)NULL;
    }

    letterIndex = (keyVal[0]-'0') * 6 + (keyVal[1]-'0');

    if (bifPtr->ptkey[letterIndex] != EMPTY) {
	return bifPtr->ptkey[letterIndex];
    } else {
	return (char)NULL;
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
    ct[i] = (char)NULL;
    ckfree(bifVal);

    return ct;
}

static int
EncodeBifid(Tcl_Interp *interp, CipherItem *itemPtr, char *pt, char *key) {
    char *ct = (char *)NULL;
    char *bifVal = (char *)NULL;
    int count;
    char **argv;
    int i;
    char *keyPositions;

    if (Tcl_SplitList(interp, key, &count, &argv) != TCL_OK) {
	return TCL_ERROR;
    }

    if (count == 1) {
	keyPositions = "11121314152122232425313233343541424344455152535455";
    } else {
	keyPositions = argv[1];
    }

    if (itemPtr->period < 1) {
	ckfree((char *)argv);
	Tcl_SetResult(interp,
		"Can not encode bifid until a period has been set.",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (count != 1 && count != 2) {
	ckfree((char *)argv);
	Tcl_AppendResult(interp, "Invalid number of items in encoding key '",
	      key, "'.  Should have found 1 or 2.", (char *)NULL);
	return TCL_ERROR;
    }

    if (strlen(argv[0]) != 25 || (argv[1] && strlen(argv[1]) != 50)) {
	Tcl_SetResult(interp, "Invalid length of key elements.", TCL_STATIC);
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    /*
     * Convert every occurence of 'j' to 'i'.
     */

    ct = (char *)ckalloc(sizeof(char) * (strlen(pt) + 1));
    for (i=0; i < strlen(pt); i++) {
	if (pt[i] == 'j') {
	    ct[i] = 'i';
	} else {
	    ct[i] = pt[i];
	}
    }

    /*
     * The plaintext and ciphertext alphabets use the same set of
     * characters.  Set the current item's ciphertext in order to
     * validate the plaintext string.
     */

    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, pt) != TCL_OK) {
	ckfree(ct);
	ckfree((char *)argv);
	return TCL_ERROR;
    }
    ckfree(ct);
    ct = (char *)NULL;

    /*
     * Validate and store the key in the current item.  The key functions used
     * by the encoder assume the current item has the encoding key.
     */

    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[0], keyPositions)
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
	ckfree(ct);
	ckfree((char *)argv);
	return TCL_ERROR;
    }
    ckfree(ct);

    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[0], keyPositions) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    Tcl_SetResult(interp, itemPtr->ciphertext, TCL_VOLATILE);
    ckfree((char *)argv);
    return TCL_OK;
}
