/*
 * bazeries.c --
 *
 *	This file implements the bazeries cipher type.
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
#include <keygen.h>

#include <cipherDebug.h>

#define MAX_SEQ_VALUE 999999
#define MAX_SEQ_LENGTH 6
#define KEY_PERIOD 5

static int  CreateBazeries	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
static char *GetBazeries	_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetBazeries		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestoreBazeries	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolveBazeries	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
int BazeriesCmd			_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));
static int BazeriesUndo		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int BazeriesSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int BazeriesLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int BazeriesSwapCols	_ANSI_ARGS_((Tcl_Interp *, CipherItem *, int,
	    			int));
static int BazeriesSwapRows	_ANSI_ARGS_((Tcl_Interp *, CipherItem *, int,
	    			int));
static int BazeriesInitSeq	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
	    			const char *));
static int EncodeBazeries	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static char *BazeriesTransform	_ANSI_ARGS_((CipherItem *, char *, int));

typedef struct BazeriesItem {
    CipherItem header;

    char key[KEY_PERIOD][KEY_PERIOD];
    char keyValPos[KEY_PERIOD*KEY_PERIOD+1];
    int keyNumber;
    int	seqLength;
    int seqVal[MAX_SEQ_LENGTH];

    char **maxSolKey;
    int maxSolVal;
} BazeriesItem;

CipherType BazeriesType = {
    "bazeries",
    ATOZ,
    sizeof(BazeriesItem),
    CreateBazeries,	/* create proc */
    DeleteCipher,	/* delete proc */
    BazeriesCmd,	/* cipher command proc */
    GetBazeries,	/* get plaintext proc */
    SetBazeries,	/* show ciphertext proc */
    SolveBazeries,	/* solve cipher proc */
    RestoreBazeries,	/* restore proc */
    BazeriesLocateTip,	/* locate proc */
    BazeriesSubstitute,	/* sub proc */
    BazeriesUndo,	/* undo proc */
    EncodeBazeries,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

static int
CreateBazeries(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    BazeriesItem *bazPtr = (BazeriesItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;
    int		j;

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    bazPtr->header.period = 0;
    bazPtr->maxSolVal = 0;
    bazPtr->maxSolKey = (char **)NULL;
    bazPtr->keyNumber = 1;
    for(i=0; i < KEY_PERIOD; i++) {
	for(j=0; j < KEY_PERIOD; j++) {
	    bazPtr->key[i][j] = '\0';
	}
    }
    for(i=0; i < 26; i++) {
	bazPtr->keyValPos[i] = 0;
    }
    for(i=0; i < MAX_SEQ_LENGTH; i++) {
	bazPtr->seqVal[i] = 0;
    }
    bazPtr->seqLength = 1;
    bazPtr->seqVal[0] = 1;

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, BazeriesCmd, itemPtr,
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
SetBazeries(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
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

    valid = TCL_OK;

    if (valid==TCL_OK) {
	itemPtr->length = length;
	if (itemPtr->ciphertext) {
	    ckfree(itemPtr->ciphertext);
	}
	itemPtr->ciphertext = c;

	if (itemPtr->ciphertext == NULL) {
	    Tcl_SetResult(interp, "Error mallocing memory for new cipher", 
		    TCL_VOLATILE);
	    return TCL_ERROR;
	}

	itemPtr->length = length;

	Tcl_SetResult(interp, itemPtr->ciphertext, TCL_STATIC);
    }

    return valid;
}

static int
BazeriesUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int offset)
{
    BazeriesItem *bazPtr = (BazeriesItem *)itemPtr;
    int i, j;

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    if (! ct) {
	for(i=0; i < KEY_PERIOD; i++) {
	    for(j=0; j < KEY_PERIOD; j++) {
		bazPtr->key[i][j] = '\0';
	    }
	}
	for(i=0; i < 26; i++) {
	    bazPtr->keyValPos[i] = 0;
	}
    } else {
	while (*ct) {
	    int keyVal;

	    if (*ct < 'a' || *ct > 'z') {
		Tcl_SetResult(interp, "Invalid key value", TCL_VOLATILE);
		return TCL_ERROR;
	    }

	    keyVal = bazPtr->keyValPos[*ct-'a'];

	    if (keyVal) {
		keyVal--;
		bazPtr->key[keyVal/KEY_PERIOD][keyVal%KEY_PERIOD]='\0';
	    }

	    ct++;
	}
    }

    Tcl_ValidateAllMemory(__FILE__, __LINE__);
    return TCL_OK;
}

static int
BazeriesSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, const char *pt, int offset)
{
    BazeriesItem *bazPtr = (BazeriesItem *)itemPtr;
    int row, col;

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    /*
     * pt == row
     * ct == col
     * offset == val
     */

    row = *ct - '1';
    col = *pt - '1';

    if (row < 0 || row >= KEY_PERIOD) {
	Tcl_SetResult(interp, "Invalid row specification", TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (col < 0 || col >= KEY_PERIOD) {
	Tcl_SetResult(interp, "Invalid column specification", TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (offset < 'a' || offset > 'z') {
	Tcl_SetResult(interp, "Invalid key value", TCL_VOLATILE);
	return TCL_ERROR;
    }

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    bazPtr->key[row][col] = offset;
    bazPtr->keyValPos[offset-'a'] = row*KEY_PERIOD+col+1;

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    return TCL_OK;
}

static char *
GetBazeries(Tcl_Interp *interp, CipherItem *itemPtr)
{
    if (itemPtr->length == 0) {
	Tcl_SetResult(interp, "Can't do anything until ciphertext has been set",
		TCL_VOLATILE);
	return (char *)NULL;
    }

    return BazeriesTransform(itemPtr, itemPtr->ciphertext, DECODE);
}

static char *
BazeriesTransform(CipherItem *itemPtr, char *text, int mode) {
    BazeriesItem *bazPtr = (BazeriesItem *)itemPtr;
    int		i;
    char	*result=(char *)NULL;
    int		groupStart;
    int		groupLength;
    int		seqNum;
    int		groupNum;

    result=(char *)ckalloc(sizeof(char) * itemPtr->length + 1);

    /*
     * First perform the substitution
     */

    for(i=0; i < itemPtr->length; i++) {
	char	ct = text[i];
	char	pt = ' ';
	int	index;

	if (mode == DECODE) {
	    index = bazPtr->keyValPos[ct-'a'];
	    if (index) {
		index--;
		pt = (index%5)*KEY_PERIOD + index/5 + 'a';
		if (pt > 'i') {
		    pt++;
		}
	    }
	} else {
	    index = (ct <= 'i')?(ct - 'a'):(ct - 'b');
	    pt = bazPtr->key[index%5][index/5];
	}

	result[i] = pt;

	Tcl_ValidateAllMemory(__FILE__, __LINE__);
    }
    result[itemPtr->length] = '\0';

    /*
     * Next perform the transposition
     */

    groupStart = 0;
    groupNum = 0;
    while (groupStart < itemPtr->length) {
	seqNum = groupNum % bazPtr->seqLength;
	groupLength = bazPtr->seqVal[seqNum];
	if (groupStart + groupLength > itemPtr->length) {
	    groupLength = itemPtr->length - groupStart;
	}

	for(i=0; i < groupLength / 2; i++) {
	    int tempVal;

	    tempVal = result[groupStart+i];
	    result[groupStart+i] = result[groupStart+(groupLength-1)-i];
	    result[groupStart+(groupLength-1)-i] = tempVal;
	}

	groupStart = groupStart + groupLength;
	groupNum++;
    }

    return result;
}

static int
RestoreBazeries(Tcl_Interp *interp, CipherItem *itemPtr, const char *key, const char *transString)
{
    BazeriesItem *bazPtr = (BazeriesItem *)itemPtr;
    int i;
    int row;
    int col;

    if (itemPtr->length <= 0) {
	Tcl_SetResult(interp, "Can't do anything until ciphertext has been set",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (strlen(key) != KEY_PERIOD * KEY_PERIOD) {
	Tcl_SetResult(interp, "Invalid key length.", TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (BazeriesInitSeq(interp, itemPtr, transString) != TCL_OK) {
	return TCL_ERROR;
    }

    for(i=0; i < KEY_PERIOD*KEY_PERIOD; i++) {
	bazPtr->keyValPos[i] = 0;
    }

    for(i=0; i < KEY_PERIOD*KEY_PERIOD; i++) {
	if ( (key[i] < 'a' || key[i] > 'z') && (key[i] != ' ')) {
	    Tcl_SetResult(interp, "Invalid character in key", TCL_VOLATILE);
	    return TCL_ERROR;
	}
	row = i / KEY_PERIOD;
	col = i % KEY_PERIOD;

	if (key[i] == ' ') {
	    bazPtr->key[row][col] = '\0';
	} else {
	    bazPtr->key[row][col] = key[i];
	    bazPtr->keyValPos[key[i]-'a'] = i+1;
	}
    }

    return TCL_OK;
}

static int
SolveBazeries(Tcl_Interp *interp, CipherItem *itemPtr, char *maxkey)
{
    Tcl_SetResult(interp, "Solving bazeries ciphers is not yet implemented.",
	    TCL_VOLATILE);
    return TCL_ERROR;
}

static int
BazeriesLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, const char *tip, const char *start)
{
    Tcl_SetResult(interp,
	    "No locate tip function defined for bazeries ciphers.",
	    TCL_VOLATILE);
    return TCL_ERROR;
}

static int
BazeriesSwapCols(Tcl_Interp *interp, CipherItem *itemPtr, int col1, int col2)
{
    BazeriesItem *bazPtr = (BazeriesItem *)itemPtr;
    int i, tempCol, row, col;

    if (col1 < 1 || col2 < 1 || col1 > KEY_PERIOD || col2 > KEY_PERIOD) {
	Tcl_SetResult(interp, "Invalid column in bazeries swap", TCL_VOLATILE);
	return TCL_ERROR;
    }

    col1--;
    col2--;

    for(i=0; i < KEY_PERIOD; i++) {
	tempCol = bazPtr->key[i][col1];
	bazPtr->key[i][col1] = bazPtr->key[i][col2];
	bazPtr->key[i][col2] = tempCol;
    }

    for(i=0; i < 26; i++) {
	bazPtr->keyValPos[i] = 0;
    }

    for(row=0; row < KEY_PERIOD; row++) {
	for(col=0; col < KEY_PERIOD; col++) {
	    int keyPos = row*KEY_PERIOD+col;

	    if (bazPtr->key[keyPos]) {
		bazPtr->keyValPos[bazPtr->key[row][col]-'a'] = keyPos+1;
	    }
	}
    }

    return TCL_OK;
}

static int
BazeriesSwapRows(Tcl_Interp *interp, CipherItem *itemPtr, int row1, int row2)
{
    BazeriesItem *bazPtr = (BazeriesItem *)itemPtr;
    int i, tempRow, row, col;

    if (row1 < 1 || row2 < 1 || row1 > KEY_PERIOD || row2 > KEY_PERIOD) {
	Tcl_SetResult(interp, "Invalid row in bazeries swap", TCL_VOLATILE);
	return TCL_ERROR;
    }

    row1--;
    row2--;

    for(i=0; i < KEY_PERIOD; i++) {
	tempRow = bazPtr->key[row1][i];
	bazPtr->key[row1][i] = bazPtr->key[row2][i];
	bazPtr->key[row2][i] = tempRow;
    }

    for(i=0; i < 26; i++) {
	bazPtr->keyValPos[i] = 0;
    }

    for(row=0; row < KEY_PERIOD; row++) {
	for(col=0; col < KEY_PERIOD; col++) {
	    int keyPos = row*KEY_PERIOD+col;

	    if (bazPtr->key[keyPos]) {
		bazPtr->keyValPos[bazPtr->key[row][col]-'a'] = keyPos+1;
	    }
	}
    }

    return TCL_OK;
}

static int
BazeriesInitSeq(Tcl_Interp *interp, CipherItem *itemPtr, const char *seqString)
{
    BazeriesItem *bazPtr = (BazeriesItem *)itemPtr;
    long seqNum;
    int i;

    if (sscanf(seqString, "%ld", &seqNum) != 1) {
	Tcl_AppendResult(interp, "Invalid transposition sequence '",
		seqString, "'", (char *)NULL, TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (seqNum > MAX_SEQ_VALUE) {
	Tcl_SetResult(interp, "Sequence value is too large.",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (seqNum < 1) {
	Tcl_SetResult(interp, "Sequence value must be greater than zero.",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    bazPtr->seqLength = strlen(seqString);
    for(i=0; i < bazPtr->seqLength; i++) {
	bazPtr->seqVal[i] = seqString[i] - '0';
    }
    bazPtr->keyNumber = seqNum;

    Tcl_SetObjResult(interp, Tcl_NewStringObj(seqString, -1));
    return TCL_OK;
}

int
BazeriesCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    BazeriesItem *bazPtr = (BazeriesItem *)clientData;
    CipherItem	*itemPtr = (CipherItem *)clientData;
    char	temp_str[256];
    const char	*cmd;
    int		i;
    char	*tPtr=(char *)NULL;

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
	    sprintf(temp_str, "%d", bazPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", itemPtr->period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!bazPtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_VOLATILE);
	    } else {
		Tcl_SetResult(interp, bazPtr->header.ciphertext, TCL_VOLATILE);
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
	} else if (strncmp(argv[1], "-key", 4) == 0) {
	    for(i=0; i < KEY_PERIOD; i++) {
		int j;
		for(j=0; j < KEY_PERIOD; j++) {
		    if (bazPtr->key[i][j]) {
			temp_str[j+i*KEY_PERIOD] = bazPtr->key[i][j];
		    } else {
			temp_str[j+i*KEY_PERIOD] = ' ';
		    }
		}
	    }
	    temp_str[KEY_PERIOD*KEY_PERIOD] = '\0';
	    Tcl_AppendElement(interp, temp_str);

	    for(i=0; i < bazPtr->seqLength; i++) {
		temp_str[i] = bazPtr->seqVal[i] + '0';
	    }
	    temp_str[bazPtr->seqLength] = '\0';
	    Tcl_AppendElement(interp, temp_str);

	    return TCL_OK;
	} else if (strncmp(argv[1], "-type", 5) == 0) {
	    Tcl_SetResult(interp, itemPtr->typePtr->type, TCL_STATIC);
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
	    if (strncmp(*argv, "-keysequence", 6) == 0) {
		if (BazeriesInitSeq(interp, itemPtr, argv[1]) != TCL_OK) {
		    return TCL_ERROR;
		}
	    } else if (strncmp(*argv, "-stepinterval", 12) == 0) {
		if (sscanf(argv[1], "%d", &i) != 1) {
		    Tcl_SetResult(interp, "Invalid interval.", TCL_VOLATILE);
		    return TCL_ERROR;
		}

		if (i < 0 ) {
		    Tcl_SetResult(interp, "Invalid interval.", TCL_VOLATILE);
		    return TCL_ERROR;
		}

		itemPtr->stepInterval = i;
	    } else if (strncmp(*argv, "-bestfitcommand", 14) == 0) {
		if (CipherSetBestFitCmd(itemPtr, argv[1]) != TCL_OK) {
		    return TCL_ERROR;
		}
	    } else if (strncmp(*argv, "-stepcommand", 14) == 0) {
		if (CipherSetStepCmd(itemPtr, argv[1]) != TCL_OK) {
		    return TCL_ERROR;
		}
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
    } else if (**argv == 's' && (strncmp(*argv, "swap", 4) == 0)) {
	int col1, col2;

	if (argc != 4) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd,
		    " swap row|col item1 item2", (char *)NULL);
	    return TCL_ERROR;
	} else {
	    if (strcmp(argv[1], "row") != 0 && strcmp(argv[1], "col") != 0) {
		Tcl_SetResult(interp,
			"Invalid parameter.  Must be 'row' or 'col'",
			TCL_VOLATILE);
		return TCL_ERROR;
	    }
	    if (sscanf(argv[2], "%d", &col1) != 1) {
		Tcl_SetResult(interp,
			"Invalid column value.  Value must be between 1 and 5.",
			TCL_VOLATILE);
		return TCL_ERROR;
	    }
	    if (sscanf(argv[3], "%d", &col2) != 1) {
		Tcl_SetResult(interp,
			"Invalid column value.  Value must be between 1 and 5.",
			TCL_VOLATILE);
		return TCL_ERROR;
	    }
	}
	if (strcmp(argv[1], "row") == 0) {
	    return BazeriesSwapRows(interp, itemPtr, col1, col2);
	} else {
	    return BazeriesSwapCols(interp, itemPtr, col1, col2);
	}
    } else if (**argv == 'l' && (strncmp(*argv, "locate", 3) == 0)) {
	Tcl_SetResult(interp,
		"No locate tip function defined for bazeries ciphers.",
		TCL_VOLATILE);
	return TCL_ERROR;
    } else if (**argv == 's' && (strncmp(*argv, "substitute", 3) == 0)) {
	if (argc != 4) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd,
		    " substitute row col val", (char *)NULL);
	    return TCL_ERROR;
	}

	return (itemPtr->typePtr->subProc)(interp, itemPtr, argv[1], argv[2], argv[3][0]);
    } else if (**argv == 'r' && (strncmp(*argv, "restore", 7) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd,
		    " restore key sequence", (char *)NULL);
	    return TCL_ERROR;
	}
	return (itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1],
		argv[2]);
    } else if (**argv == 'e' && (strncmp(*argv, "encode", 1) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " encode pt key",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	return (itemPtr->typePtr->encodeProc)(interp, itemPtr, argv[1], argv[2]);
    } else if (**argv == 'u' && (strncmp(*argv, "undo", 4) == 0)) {
	if (argc == 1) {
	    return (itemPtr->typePtr->undoProc)(interp, itemPtr, (char *)NULL, 0);
	}
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd,
		    " undo row col", (char *)NULL);
	    return TCL_ERROR;
	}

	return (itemPtr->typePtr->subProc)(interp, itemPtr, argv[1], argv[2], 0);
    } else if (**argv == 's' && (strncmp(*argv, "solve", 5) == 0)) {
	return (itemPtr->typePtr->solveProc)(interp, itemPtr, temp_str);
    } else {
	Tcl_AppendResult(interp, "Unknown option ", *argv, (char *)NULL);
	Tcl_AppendResult(interp, "\nMust be one of:  ", cmd,
			" cget ?option?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" configure ?option value?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" restore key", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" solve", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" substitute row col val", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" swap row1 row2", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" undo row col", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" encode pt key", (char *)NULL);
	return TCL_ERROR;
    }
}

static int
EncodeBazeries(Tcl_Interp *interp, CipherItem *itemPtr, const char *pt, const char *key) {
    char *ct = (char *)NULL;
    int count;
    const char **argv;
    char *keyedAlphabet = (char *)NULL;
    char *keySeq = (char *)NULL;
    int seqValue;

    if (Tcl_SplitList(interp, key, &count, &argv) != TCL_OK) {
	return TCL_ERROR;
    }

    if (count != 1 && count != 2) {
	ckfree((char *)argv);
	Tcl_AppendResult(interp, "Invalid number of items in encoding key '",
	      key, "'.  Should have found 1 or 2.", (char *)NULL);
	return TCL_ERROR;
    }

    if (count == 2) {
	keySeq = argv[1];
	keyedAlphabet = argv[0];
    } else {
	keySeq = argv[0];
    }

    if (Tcl_GetInt(interp, keySeq, &seqValue) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    if (count == 1) {
	char *temp = (char *)NULL;
	char *curPos;
	int i;

	// Make sure to free this space later.
	temp = KeyGenerateNum(interp, (long)seqValue);
	if (temp == (char *)NULL) {
	    ckfree((char *)argv);
	    return TCL_ERROR;
	}

	for(curPos = temp, i=0; *curPos; curPos++) {
	    if (*curPos == 'j') {
		*curPos = 'i';
	    }
	    if (*curPos >= 'a' && *curPos <= 'z') {
		temp[i++] = *curPos;
	    }
	}
	temp[i] = '\0';

	keyedAlphabet = (char *)ckalloc(sizeof(char) * (26 + 1));
	if (KeyGenerateK1(interp, temp, keyedAlphabet) != TCL_OK) {
	    ckfree(temp);
	    ckfree((char *)argv);
	    return TCL_ERROR;
	}
        ckfree(temp);

	// It is safe to assume that all 26 letters of the alphabet are
	// present once and only once.
	for(i=0; keyedAlphabet[i] != 'j' && i < 26; i++);
	for(; (keyedAlphabet[i] = keyedAlphabet[i+1]) && i < 26; i++);
	keyedAlphabet[26] = '\0';
    }

    if (strlen(keyedAlphabet) != 25) {
	Tcl_SetResult(interp, "Invalid length of key elements.", TCL_STATIC);
	ckfree((char *)argv);
	if (count == 1) {
	    ckfree((char *)keyedAlphabet);
	}
	return TCL_ERROR;
    }

    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, pt) != TCL_OK) {
	ckfree((char *)argv);
	if (count == 1) {
	    ckfree((char *)keyedAlphabet);
	}
	return TCL_ERROR;
    }
    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, keyedAlphabet, keySeq) != TCL_OK) {
	ckfree((char *)argv);
	if (count == 1) {
	    ckfree((char *)keyedAlphabet);
	}
	return TCL_ERROR;
    }
    ct = BazeriesTransform(itemPtr, itemPtr->ciphertext, ENCODE);
    if (ct == (char *)NULL) {
	ckfree((char *)argv);
	if (count == 1) {
	    ckfree((char *)keyedAlphabet);
	}
	return TCL_ERROR;
    }
    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, ct) != TCL_OK) {
	ckfree((char *)argv);
	if (count == 1) {
	    ckfree((char *)keyedAlphabet);
	}
	return TCL_ERROR;
    }
    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, keyedAlphabet, keySeq) != TCL_OK) {
	ckfree((char *)argv);
	if (count == 1) {
	    ckfree((char *)keyedAlphabet);
	}
	return TCL_ERROR;
    }

    Tcl_SetResult(interp, ct, TCL_DYNAMIC);
    if (count == 1) {
	ckfree((char *)keyedAlphabet);
    }
    ckfree((char *)argv);

    return TCL_OK;
}

#undef KEY_PERIOD
