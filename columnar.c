/*
 * columnar.c --
 *
 *	This file implements the complete/incomplete columnar cipher type.
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
#include <cipher.h>
#include <score.h>
#include <perm.h>

#include <cipherDebug.h>

static int  CreateColumnar	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
void DeleteColumnar		_ANSI_ARGS_((ClientData));
static char *GetColumnar	_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetColumnar		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestoreColumnar	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolveColumnar	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
int ColumnarCmd			_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));
static int ColumnarUndo		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int ColumnarSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int ColumnarLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static void ColumnarInitKey	_ANSI_ARGS_((CipherItem *, int));
int ColumnarCheckSolutionValue  _ANSI_ARGS_((Tcl_Interp *, ClientData,
	    			int *, int));
static int ColumnarSwapColumns	_ANSI_ARGS_((Tcl_Interp *, CipherItem *, int,
	    			int));
static int ColumnarShiftColumn	_ANSI_ARGS_((Tcl_Interp *, CipherItem *, int,
	    			int));
static int EncodeColumnar	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static char *ColumnarTransform	_ANSI_ARGS_((CipherItem *, const char *, int));

typedef struct ColumnarItem {
    CipherItem header;

    int maxColLen;	/* Length of longest column */
    int *colLength;	/* Length of each column */
    char *key;

    char *pt;
    char *maxKey;	/* For solving */
    double maxValue;
} ColumnarItem;

CipherType ColumnarType = {
    "columnar",
    "abcdefghijklmnopqrstuvwxyz-",
    sizeof(ColumnarItem),
    CreateColumnar,	/* create proc */
    DeleteColumnar,	/* delete proc */
    ColumnarCmd,	/* cipher command proc */
    GetColumnar,	/* get plaintext proc */
    SetColumnar,	/* show ciphertext proc */
    SolveColumnar,	/* solve cipher proc */
    RestoreColumnar,	/* restore proc */
    ColumnarLocateTip,  /* locate proc */
    ColumnarSubstitute,	/* sub proc */
    ColumnarUndo,	/* undo proc */
    EncodeColumnar,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

static int
CreateColumnar(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    ColumnarItem *colPtr = (ColumnarItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    colPtr->header.period = 0;
    colPtr->maxColLen = 0;
    colPtr->colLength = (int *)NULL;
    colPtr->key = (char *)NULL;
    colPtr->maxKey = (char *)NULL;
    colPtr->maxValue = 0.0;
    colPtr->pt = (char *)NULL;

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++)
	Tcl_DStringAppendElement(&dsPtr, argv[i]);

    Tcl_CreateCommand(interp, temp_ptr, ColumnarCmd, itemPtr,
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
DeleteColumnar(ClientData clientData)
{
    ColumnarItem *colPtr = (ColumnarItem *)clientData;

    if (colPtr->key) {
	ckfree(colPtr->key);
    }

    if (colPtr->pt) {
	ckfree(colPtr->pt);
    }

    if (colPtr->colLength) {
	ckfree((char *)(colPtr->colLength));
    }

    if (colPtr->maxKey) {
	ckfree((char *)colPtr->maxKey);
    }

    DeleteCipher(clientData);
}

static int
SetColumnar(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
{
    ColumnarItem *colPtr = (ColumnarItem *)itemPtr;
    char	*c;
    int		valid = TCL_OK,
    		length=0;

    length = CountValidChars(itemPtr, ctext);
    c = ExtractValidChars(itemPtr, ctext);

    if (!c) {
	Tcl_SetResult(interp, "No valid characters found in ciphertext",
		TCL_STATIC);
	return TCL_ERROR;
    }

    itemPtr->length = length;
    if (itemPtr->ciphertext) {
	ckfree(itemPtr->ciphertext);
    }
    itemPtr->ciphertext = c;

    if (colPtr->pt) {
	ckfree(colPtr->pt);
    }
    colPtr->pt = (char *)ckalloc(sizeof(char) * length + 1);

    if (colPtr->pt == NULL) {
	Tcl_SetResult(interp,
		"Error mallocing memory for new cipher",
		TCL_STATIC);
	return TCL_ERROR;
    }

    itemPtr->length = length;
    if (itemPtr->period < 0 || itemPtr->period > length) {
	itemPtr->period = 0;
    }

    ColumnarInitKey(itemPtr, itemPtr->period);

    Tcl_SetResult(interp, itemPtr->ciphertext, TCL_STATIC);

    return valid;
}

static int
ColumnarUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int offset)
{
    ColumnarInitKey(itemPtr, itemPtr->period);

    return TCL_OK;
}

static int
ColumnarSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, const char *pt, int offset)
{
    Tcl_SetResult(interp, "No substitute command defined for columnar ciphers.",
	    TCL_STATIC);
    return TCL_ERROR;
}

static char *
GetColumnar(Tcl_Interp *interp, CipherItem *itemPtr)
{
    return ColumnarTransform(itemPtr, itemPtr->ciphertext, DECODE);
}

static char *
ColumnarTransform(CipherItem *itemPtr, const char *text, int mode) {
    ColumnarItem *colPtr = (ColumnarItem *)itemPtr;
    int		i, col, pos;
    int		newCol, row;
    int		*startPos=(int *)ckalloc(sizeof(int)*itemPtr->period);

    /*
     * Locate the starting positions of each column in the ciphertext
     */

    for(col=0, pos=0; col < itemPtr->period; col++) {
	/*
	 * Locate the col'th column in the key
	 */
	for(i=0; i < itemPtr->period && colPtr->key[i]!=col; i++);
	newCol = i;
	startPos[newCol] = pos;
	pos += colPtr->colLength[newCol];
    }

    for (i=0; i < itemPtr->length; i++) {
	colPtr->pt[i] = '_';
    }
    colPtr->pt[itemPtr->length] = '\0';

    for(col=0; col < itemPtr->period; col++) {
	newCol = colPtr->key[col];

	for(row=0; row < colPtr->colLength[newCol]; row++) {
	    int newIndex = row * itemPtr->period + newCol;
	    int oldIndex = startPos[newCol] + row;

	    /*
	    printf("map %d", oldIndex);
	    printf(" (%c) -> %d\n", colPtr->header.ciphertext[oldIndex], newIndex);
	    */

	    if (newIndex > itemPtr->length ||
		oldIndex > itemPtr->length ||
		newIndex < 0 ||
		oldIndex < 0) {
		fprintf(stderr, "Fatal indexing error! %s: line %d\n",
		       	__FILE__, __LINE__);
		abort();
	    }
	    if (mode == DECODE) {
		colPtr->pt[newIndex] = text[oldIndex];
	    } else {
		colPtr->pt[oldIndex] = text[newIndex];
	    }
	}
    }

    colPtr->pt[itemPtr->length] = '\0';

    ckfree((char *)startPos);

    return colPtr->pt;
}

static int
RestoreColumnar(Tcl_Interp *interp, CipherItem *itemPtr, const char *key, const char *dummy)
{
    ColumnarItem *colPtr = (ColumnarItem *)itemPtr;
    int		i;
    int		j;

    if (itemPtr->ciphertext == (char *)NULL) {
	Tcl_SetResult(interp,
		"Can't do anything until ciphertext has been set",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (itemPtr->period <= 0) {
	Tcl_SetResult(interp,
		"Can't do anything until period has been set",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (strlen(key) != colPtr->header.period) {
	Tcl_SetResult(interp, "Length of key does not match period",
		TCL_STATIC);
	return TCL_ERROR;
    }

    for(i=0; i < colPtr->header.period; i++) {
	if (key[i] < 'a' || key[i] > 'z') {
	    Tcl_SetResult(interp, "Invalid character in key", TCL_STATIC);
	    return TCL_ERROR;
	}
	if (key[i] >= colPtr->header.period + 'a') {
	    Tcl_SetResult(interp, "key character out of range", TCL_STATIC);
	    return TCL_ERROR;
	}
	for(j=0; j < colPtr->header.period; j++) {
	    if (key[j] == key[i] && i != j) {
		Tcl_SetResult(interp, "duplicate key characters not allowed",
			TCL_STATIC);
		return TCL_ERROR;
	    }
	}
    }
    for(i=0; i < colPtr->header.period; i++) {
	colPtr->key[i] = key[i] - 'a';
    }

    return TCL_OK;
}

int
ColumnarCheckSolutionValue(Tcl_Interp *interp, ClientData clientData, int *key, int keylen)
{
    ColumnarItem *colPtr = (ColumnarItem *)clientData;
    CipherItem *itemPtr = (CipherItem *)clientData;
    char *pt=(char *)NULL;
    char *tKey=(char *)NULL;
    int i;
    double value;
    Tcl_DString dsPtr;

    if (keylen != colPtr->header.period) {
	Tcl_SetResult(interp, "Key length != period!", TCL_STATIC);
	return TCL_ERROR;
    }

    tKey = (char *)ckalloc(sizeof(char) * keylen);

    for(i=0; i < keylen; i++) {
	tKey[i] = colPtr->key[i];
    }

    for(i=0; i < keylen; i++) {
	colPtr->key[i] = tKey[key[i]];
    }

    itemPtr->curIteration++;

    pt = GetColumnar(interp, (CipherItem *)colPtr);

    if (DefaultScoreValue(interp, pt, &value) != TCL_OK) {
	return TCL_ERROR;
    }

    if (itemPtr->stepInterval && itemPtr->curIteration % itemPtr->stepInterval == 0 && itemPtr->stepCommand && pt) {
	char temp_str[128];

	Tcl_DStringInit(&dsPtr);

	Tcl_DStringAppendElement(&dsPtr, itemPtr->stepCommand);

	sprintf(temp_str, "%lu", itemPtr->curIteration);
	Tcl_DStringAppendElement(&dsPtr, temp_str);

	Tcl_DStringStartSublist(&dsPtr);
	for(i=0; i < keylen; i++) {
	    sprintf(temp_str, "%d", colPtr->key[i]);
	    Tcl_DStringAppendElement(&dsPtr, temp_str);
	}
	Tcl_DStringEndSublist(&dsPtr);

	Tcl_DStringAppendElement(&dsPtr, pt);

	if (Tcl_Eval(interp, Tcl_DStringValue(&dsPtr)) != TCL_OK) {
	    ckfree(pt);
	    Tcl_ResetResult(interp);
	    Tcl_AppendResult(interp, "Bad command usage:  ", Tcl_DStringValue(&dsPtr), (char *)NULL);
	    Tcl_DStringFree(&dsPtr);
	    return TCL_ERROR;
	}
	Tcl_DStringFree(&dsPtr);
    }

    if (value > colPtr->maxValue) {
	char temp_str[128];
	Tcl_DStringInit(&dsPtr);

	if (itemPtr->bestFitCommand) {
	    Tcl_DStringAppendElement(&dsPtr, itemPtr->bestFitCommand);
	}

	sprintf(temp_str, "%lu", itemPtr->curIteration);
	Tcl_DStringAppendElement(&dsPtr, temp_str);

	colPtr->maxValue = value;
	Tcl_DStringStartSublist(&dsPtr);
	for(i=0; i < keylen; i++) {
	    colPtr->maxKey[i] = colPtr->key[i];
	    sprintf(temp_str, "%d", colPtr->maxKey[i]);
	    Tcl_DStringAppendElement(&dsPtr, temp_str);
	}
	Tcl_DStringEndSublist(&dsPtr);

	sprintf(temp_str, "%g", value);
	Tcl_DStringAppendElement(&dsPtr, temp_str);

	Tcl_DStringAppendElement(&dsPtr, pt);

	if (itemPtr->bestFitCommand) {
	    if (Tcl_Eval(interp, Tcl_DStringValue(&dsPtr)) != TCL_OK) {
		ckfree(pt);
		Tcl_ResetResult(interp);
		Tcl_AppendResult(interp, "Bad command usage:  ", Tcl_DStringValue(&dsPtr), (char *)NULL);

		Tcl_DStringFree(&dsPtr);
		return TCL_ERROR;
	    }
	}

	Tcl_DStringFree(&dsPtr);
    }

    for(i=0; i < keylen; i++) {
	colPtr->key[i] = tKey[i];
    }

    ckfree((char *)tKey);
    return TCL_OK;
}

static int
SolveColumnar(Tcl_Interp *interp, CipherItem *itemPtr, char *maxkey)
{
    ColumnarItem *colPtr = (ColumnarItem *)itemPtr;
    int i, result;

    if (itemPtr->ciphertext == (char *)NULL) {
	Tcl_SetResult(interp,
		"Can't do anything until ciphertext has been set",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (itemPtr->period <= 0) {
	Tcl_SetResult(interp,
		"Can't do anything until period has been set",
		TCL_STATIC);
	return TCL_ERROR;
    }

    itemPtr->curIteration = 0;
    colPtr->maxValue = 0;
    if (colPtr->maxKey) {
	ckfree((char *)colPtr->maxKey);
    }

    colPtr->maxKey = (char *)ckalloc(sizeof(char)*itemPtr->period);

    result = _internalDoPermCmd((ClientData)itemPtr, interp, itemPtr->period, ColumnarCheckSolutionValue);

    /*
     * Now apply the best key
     */

    if (result == TCL_OK) {
	for(i=0; i < itemPtr->period; i++) {
	    colPtr->key[i] = colPtr->maxKey[i];
	    maxkey[i] = colPtr->key[i] + 'a';
	}
    }

    Tcl_SetResult(interp, maxkey, TCL_VOLATILE);

    return result;
}

static void
ColumnarInitKey(CipherItem *itemPtr, int period)
{
    ColumnarItem *colPtr = (ColumnarItem *)itemPtr;
    int		i;

    if (colPtr->key) {
	ckfree(colPtr->key);
    }

    if (colPtr->colLength) {
	ckfree((char *)(colPtr->colLength));
    }

    colPtr->key = (char *)NULL;
    colPtr->colLength = (int *)NULL;
    colPtr->header.period = period;

    if (period && itemPtr->length > 0) {
	colPtr->key=ckalloc(sizeof(char)*period+1);
	colPtr->colLength=(int *)ckalloc(sizeof(int)*(period+1));

	colPtr->maxColLen =
	    (itemPtr->length%period == 0)?(itemPtr->length / period):(itemPtr->length/period + 1);

	for(i=0; i < colPtr->header.period; i++) {
	    colPtr->key[i] = (char)i;
	    if ((unsigned int)(period*(colPtr->maxColLen-1)+i) <
		    itemPtr->length) {
		colPtr->colLength[i] = colPtr->maxColLen;
	    } else {
		colPtr->colLength[i] = colPtr->maxColLen - 1;
	    }
	}
	colPtr->key[period]='\0';
    }
}

/*
 * We probably won't need this.
 */

static int
ColumnarLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, const char *tip, const char *start)
{
    Tcl_SetResult(interp,
	    "No locate tip function defined for Columnar ciphers.",
	    TCL_STATIC);
    return TCL_ERROR;
}

static int
ColumnarSwapColumns(Tcl_Interp *interp, CipherItem *itemPtr, int col1, int col2)
{
    ColumnarItem *colPtr = (ColumnarItem *)itemPtr;
    char t;
    int newCol1, newCol2;
    int i;

    if (itemPtr->ciphertext == (char *)NULL) {
	Tcl_SetResult(interp,
		"Can't do anything until ciphertext has been set",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (itemPtr->period <= 0) {
	Tcl_SetResult(interp,
		"Can't do anything until period has been set",
		TCL_STATIC);
	return TCL_ERROR;
    }


    if (col1 < 0 ||
	    col2 < 0 ||
	    col1 >= itemPtr->period ||
	    col2 >= itemPtr->period ||
	    col1 == col2) {

	Tcl_SetResult(interp, "Bad column index", TCL_STATIC);
	return TCL_ERROR;
    }

    /*
    printf("Swapping columns %d and %d\n", col1, col2);
    col1--, col2--;
    */

    newCol1 = -1;
    newCol2 = -1;
    for(i=0; i < itemPtr->period; i++) {
	if (col1 == colPtr->key[i]) {
	    newCol1 = i;
	}
    }
    for(i=0; i < itemPtr->period; i++) {
	if (col2 == colPtr->key[i]) {
	    newCol2 = i;
	}
    }
    /*
     * This should never happen.
     */
    if (newCol1 == -1 || newCol2 == -1) {
	Tcl_SetResult(interp,
		"Fatal error in ColumnarSwapColumns().  Non-unique column index found.",
		TCL_STATIC);
	return TCL_ERROR;
    }
    col1 = newCol1;
    col2 = newCol2;

    t = colPtr->key[col1];
    colPtr->key[col1] = colPtr->key[col2];
    colPtr->key[col2] = t;

    return TCL_OK;
}

static int
ColumnarShiftColumn(Tcl_Interp *interp, CipherItem *itemPtr, int col, int amount)
{
    ColumnarItem *colPtr = (ColumnarItem *)itemPtr;
    int i;
    int start=col;
    int tempKeyVal;

    if (itemPtr->ciphertext == (char *)NULL) {
	Tcl_SetResult(interp,
		"Can't do anything until ciphertext has been set",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (itemPtr->period <= 0) {
	Tcl_SetResult(interp,
		"Can't do anything until period has been set",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (col < 0 || col >= itemPtr->period) {
	Tcl_SetResult(interp, "Bad column index", TCL_STATIC);
	return TCL_ERROR;
    }

    if (amount == 0) {
	/*
	 * No-op.
	 */
	return TCL_OK;
    }

    /*
     * The user specified the columns by label, not absolute position.
     * We need to convert this label to the absolute position to do
     * our work.
     */
    for(i=0; i < itemPtr->period; i++) {
	if (col == colPtr->key[i]) {
	    start = i;
	}
    }

    if (start + amount < 0) {
	Tcl_SetResult(interp, "Can't shift backwards past the first column.", TCL_STATIC);
	return TCL_ERROR;
    }

    /*
     * Don't allow shifting past the end.
     */
    if (start + amount > itemPtr->period) {
	amount = itemPtr->period - start - 1;
    }


    tempKeyVal = colPtr->key[start];
    if (amount < 0) {
	for (i=0; i > amount; i--) {
	    int startIndex = (start + i + itemPtr->period)%itemPtr->period;
	    int endIndex = (start + i - 1 + itemPtr->period)%itemPtr->period;

	    colPtr->key[startIndex] = colPtr->key[endIndex];
	}
    } else {
	for (i=0; i < amount; i++) {
	    int startIndex = (start + i + itemPtr->period)%itemPtr->period;
	    int endIndex = (start + i + 1 + itemPtr->period)%itemPtr->period;

	    colPtr->key[startIndex] = colPtr->key[endIndex];
	}
    }

    colPtr->key[start+i] = tempKeyVal;

    return TCL_OK;
}

int
ColumnarCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    ColumnarItem *colPtr = (ColumnarItem *)clientData;
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
	    sprintf(temp_str, "%d", colPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", itemPtr->period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!colPtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_STATIC);
	    } else {
		Tcl_SetResult(interp, colPtr->header.ciphertext, TCL_VOLATILE);
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-plaintext", 9) == 0 ||
		   strncmp(argv[1], "-ptext", 3) == 0) {
	    tPtr = (itemPtr->typePtr->decipherProc)(interp, itemPtr);

	    if (!tPtr) {
		return TCL_ERROR;
	    }

	    Tcl_SetResult(interp, tPtr, TCL_VOLATILE);

	    return TCL_OK;
	} else if (strncmp(argv[1], "-key", 4) == 0) {
	    for(i=0; i < itemPtr->period; i++) {
		temp_str[i] = colPtr->key[i]+'a';
		/*
		if (temp_str[i] > 'v') temp_str[i]++;
		*/
	    }
	    temp_str[itemPtr->period] = '\0';

	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);

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
	    if (strncmp(*argv, "-period", 7) == 0) {
		int period;
		if (sscanf(argv[1], "%d", &period) != 1) {
		    Tcl_SetResult(interp, "Invalid period setting.", TCL_STATIC);
		    return TCL_ERROR;
		}
		if (period < 0
			|| (itemPtr->length > 0 && period > itemPtr->length)) {
		    Tcl_SetResult(interp, "Invalid period setting.", TCL_STATIC);
		    return TCL_ERROR;
		}

		ColumnarInitKey(itemPtr, period);
		Tcl_SetResult(interp, argv[1], TCL_VOLATILE);
	    } else if (strncmp(*argv, "-stepinterval", 12) == 0) {
		if (argc < 2) {
		    Tcl_AppendResult(interp, "Usage:  ", cmd, " configure -stepinterval val", (char *)NULL);
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
		if (CipherSetBestFitCmd(itemPtr, argv[1]) != TCL_OK) {
		    return TCL_ERROR;
		}
	    } else if (strncmp(*argv, "-stepcommand", 14) == 0) {
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
    } else if (**argv == 'r' && (strncmp(*argv, "restore", 2) == 0)) {
	/*
	 * Allow 2 arguments to restore, but ignore the second.  This is
	 * so that the restore procedure can be called in the same manner
	 * for all ciphers, some of which require 2 arguments.
	 */

	if (argc != 2 && argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " restore key", (char *)NULL);
	    return TCL_ERROR;
	}
	if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1], (char *)NULL) == TCL_ERROR) {
	    return TCL_ERROR;
	} else {
	    return TCL_OK;
	}
    } else if (**argv == 's' && (strncmp(*argv, "substitute", 2) == 0)) {
	Tcl_SetResult(interp,
		"No substitute command defined for columnar ciphers.",
		TCL_STATIC);
	return TCL_ERROR;
    } else if (**argv == 's' && (strncmp(*argv, "shift", 2) == 0)) {
	char	col;
        int	amount;
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " shift col amount",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	col = *argv[1];
	if (sscanf(argv[2], "%d", &amount) != 1) {
	    Tcl_AppendResult(interp, "Invalid shift value ", argv[2],
		    (char *)NULL);
	    return TCL_ERROR;
	}

	col -= 'a';

	if (ColumnarShiftColumn(interp, itemPtr, col, amount) != TCL_OK) {
	    return TCL_ERROR;
	}
    } else if (**argv == 's' && (strncmp(*argv, "swap", 2) == 0)) {
	char col1, col2;
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " swap col1 col2",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	col1 = *argv[1];
	col2 = *argv[2];
	col1 -= 'a';
	col2 -= 'a';

	if (ColumnarSwapColumns(interp, itemPtr, col1, col2) != TCL_OK) {
	    return TCL_ERROR;
	}
    } else if (**argv == 'e' && (strncmp(*argv, "encode", 1) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " encode pt key",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	return (itemPtr->typePtr->encodeProc)(interp, itemPtr, argv[1], argv[2]);
    } else if (**argv == 's' && (strncmp(*argv, "solve", 2) == 0)) {
	if( (itemPtr->typePtr->solveProc)(interp, itemPtr, temp_str) != TCL_OK) {
	    return TCL_ERROR;
	} else {
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	}
    } else if (**argv == 'u' && (strncmp(*argv, "undo", 1) == 0)) {
	(itemPtr->typePtr->undoProc)(interp, itemPtr, argv[1], 0);
	Tcl_SetResult(interp, "", TCL_STATIC);
	return TCL_OK;
    } else if (**argv == 'l' && (strncmp(*argv, "locate", 1) == 0)) {
	Tcl_SetResult(interp,
		"No locate tip function defined for Columnar ciphers.",
		TCL_STATIC);
	return TCL_ERROR;
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
			" swap col1 col2", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" undo ct", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" encode pt key", (char *)NULL);
	return TCL_ERROR;
    }

    return TCL_OK;
}

static int
EncodeColumnar(Tcl_Interp *interp, CipherItem *itemPtr, const char *pt, const char *key) {
    char *ct = (char *)NULL;
    int count;
    const char **argv;

    if (Tcl_SplitList(interp, key, &count, &argv) != TCL_OK) {
	return TCL_ERROR;
    }

    if (count != 1) {
	ckfree((char *)argv);
	Tcl_AppendResult(interp, "Invalid number of items in encoding key '",
	      key, "'.  Should have found 1.", (char *)NULL);
	return TCL_ERROR;
    }

    ColumnarInitKey(itemPtr, strlen(key));

    /*
    if (strlen(argv[0]) != itemPtr->period) {
	Tcl_SetResult(interp,
		"Length of key does not match the period.", TCL_STATIC);
	ckfree((char *)argv);
	return TCL_ERROR;
    }
    */

    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, pt) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }
    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[0], (char *)NULL) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }
    ct = ColumnarTransform(itemPtr, itemPtr->ciphertext, ENCODE);
    if (ct == (char *)NULL) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }
    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, ct) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }
    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[0], (char *)NULL) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    Tcl_SetResult(interp, itemPtr->ciphertext, TCL_VOLATILE);
    ckfree((char *)argv);

    return TCL_OK;
}
