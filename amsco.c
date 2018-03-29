/*
 * amsco.c --
 *
 *	This file implements the complete/incomplete amsco cipher type.
 *
 * Copyright (c) 2003 Michael Thomas <wart@kobold.org>
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

static int  CreateAmsco		_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
void DeleteAmsco		_ANSI_ARGS_((ClientData));
static char *GetAmsco		_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetAmsco		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestoreAmsco	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolveAmsco		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
int AmscoCmd			_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));
static int AmscoUndo		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int AmscoSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int AmscoLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static void AmscoInitKey	_ANSI_ARGS_((CipherItem *, int));
int AmscoCheckSolutionValue  	_ANSI_ARGS_((Tcl_Interp *, ClientData,
	    			int *, int));
static int AmscoSwapColumns	_ANSI_ARGS_((Tcl_Interp *, CipherItem *, int,
	    			int));
static int AmscoShiftColumn	_ANSI_ARGS_((Tcl_Interp *, CipherItem *, int,
	    			int));
static int EncodeAmsco		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static char *AmscoTransform	_ANSI_ARGS_((CipherItem *, char *, int));

typedef struct AmscoItem {
    CipherItem header;

    int firstCellSize;  /* Indicates if the first cell contains 1 character
			 * or two.
			 */
    int *colLength;	/* Length of each column */
    char *key;

    char *pt;
    char *maxKey;	/* For solving */
    int maxFirstCellSize;
    double maxValue;
} AmscoItem;

CipherType AmscoType = {
    "amsco",
    ATOZ,
    sizeof(AmscoItem),
    CreateAmsco,	/* create proc */
    DeleteAmsco,	/* delete proc */
    AmscoCmd,		/* cipher command proc */
    GetAmsco,		/* get plaintext proc */
    SetAmsco,		/* show ciphertext proc */
    SolveAmsco,		/* solve cipher proc */
    RestoreAmsco,	/* restore proc */
    AmscoLocateTip,	/* locate proc */
    AmscoSubstitute,	/* sub proc */
    AmscoUndo,		/* undo proc */
    EncodeAmsco,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

static int
CreateAmsco(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    AmscoItem *amscoPtr = (AmscoItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    amscoPtr->header.period = 0;
    amscoPtr->colLength = (int *)NULL;
    amscoPtr->key = (char *)NULL;
    amscoPtr->maxKey = (char *)NULL;
    amscoPtr->maxValue = 0.0;
    amscoPtr->maxFirstCellSize = 1;
    amscoPtr->pt = (char *)NULL;
    amscoPtr->firstCellSize = 1;

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++)
	Tcl_DStringAppendElement(&dsPtr, argv[i]);

    Tcl_CreateCommand(interp, temp_ptr, AmscoCmd, itemPtr,
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
DeleteAmsco(ClientData clientData)
{
    AmscoItem *amscoPtr = (AmscoItem *)clientData;

    if (amscoPtr->key) {
	ckfree(amscoPtr->key);
    }

    if (amscoPtr->pt) {
	ckfree(amscoPtr->pt);
    }

    if (amscoPtr->colLength) {
	ckfree((char *)(amscoPtr->colLength));
    }

    if (amscoPtr->maxKey) {
	ckfree((char *)amscoPtr->maxKey);
    }

    DeleteCipher(clientData);
}

static int
SetAmsco(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
{
    AmscoItem *amscoPtr = (AmscoItem *)itemPtr;
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

    if (amscoPtr->pt) {
	ckfree(amscoPtr->pt);
    }
    amscoPtr->pt = (char *)ckalloc(sizeof(char) * length + 1);

    if (itemPtr->ciphertext == NULL) {
	Tcl_SetResult(interp,
		"Error mallocing memory for new cipher",
		TCL_STATIC);
	return TCL_ERROR;
    }

    itemPtr->length = length;
    if (itemPtr->period < 0 || itemPtr->period > length) {
	itemPtr->period = 0;
    }

    AmscoInitKey(itemPtr, itemPtr->period);

    Tcl_SetResult(interp, itemPtr->ciphertext, TCL_STATIC);

    return valid;
}

static int
AmscoUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int offset)
{
    AmscoInitKey(itemPtr, itemPtr->period);

    return TCL_OK;
}

static int
AmscoSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, const char *pt, int offset)
{
    Tcl_SetResult(interp, "No substitute command defined for amsco ciphers.",
	    TCL_STATIC);
    return TCL_ERROR;
}

static char *
GetAmsco(Tcl_Interp *interp, CipherItem *itemPtr) {
    return AmscoTransform(itemPtr, itemPtr->ciphertext, DECODE);
}

static char *
AmscoTransform(CipherItem *itemPtr, char *text, int mode) {
    AmscoItem *amscoPtr = (AmscoItem *)itemPtr;
    int		i, col, pos;
    int		newCol;
    int		lineOffset = 0;
    int		*startPos=(int *)ckalloc(sizeof(int)*itemPtr->period);
    int		ptStartPosition = 0;
    int		ptPosition = 0;
    int		colStartCellSize = amscoPtr->firstCellSize;

    /*
     * The key contains the order in which the columns will be filled
     * with the ciphertext.
     */

    /*
     * Determine the distance between cells for odd and even periods
     */
    if (itemPtr->period % 2 == 1) {
	lineOffset = (itemPtr->period - 1) / 2 * 3;
    } else {
	lineOffset = (itemPtr->period) / 2 * 3 - 1;
    }

    /*
     * Locate the starting positions of each column in the ciphertext
     */

    for(col=0, pos=0; col < itemPtr->period; col++) {
	/*
	 * Locate the col'th column in the key
	 */
	for(i=0; i < itemPtr->period && amscoPtr->key[i]!=col; i++);
	/*
	 * Sanity check to make sure that we found the column in the key.
	 */
	if (i >= itemPtr->period) {
	    fprintf(stderr,
		"Column not found in key.  %s: line %d\n",
		__FILE__, __LINE__);
	    abort();
	}
	newCol = i;
	startPos[newCol] = pos;

	/*
	printf("Start position for column %d is %d\n", newCol, pos);
	printf("Length of column %d is %d\n", newCol, amscoPtr->colLength[newCol]);
	fflush(stdout);
	*/
	pos += amscoPtr->colLength[newCol];

    }

    for (i=0; i < itemPtr->length; i++) {
	amscoPtr->pt[i] = '_';
    }
    amscoPtr->pt[itemPtr->length] = '\0';

    for (col=0; col < itemPtr->period; col++) {
	int row=0;
	int keyColumn = col;
	int cellSize = colStartCellSize;
	ptPosition = ptStartPosition;
	for (i=startPos[keyColumn];
	     i < startPos[keyColumn] + amscoPtr->colLength[keyColumn];
	     i++) {

	    if (ptPosition > itemPtr->length) {
		fprintf(stderr,
		    "Fatal indexing error.  %s: line %d\n",
		    __FILE__, __LINE__);
		abort();
	    }
	    /*
	    printf("pt[%d] = ct[%d] (%c)\n", ptPosition,
		    i, itemPtr->ciphertext[i]);
	    */
	    if (mode == DECODE) {
		amscoPtr->pt[ptPosition] = itemPtr->ciphertext[i];
	    } else {
		amscoPtr->pt[i] = itemPtr->ciphertext[ptPosition];
	    }

	    ptPosition++;
	    if (cellSize == 2 && ptPosition < itemPtr->length) {
		i++;
		if (ptPosition >= itemPtr->length || i > itemPtr->length) {
		    fprintf(stderr,
			"Fatal indexing error.  %s: line %d\n",
			__FILE__, __LINE__);
		    abort();
		}
		/*
		printf("pt[%d] = ct[%d] (%c)\n",
			ptPosition, i, itemPtr->ciphertext[i]);
		*/
		if (mode == DECODE) {
		    amscoPtr->pt[ptPosition] = text[i];
		} else {
		    amscoPtr->pt[i] = text[ptPosition];
		}

		ptPosition++;
	    }
	    ptPosition += lineOffset;
	    /*
	     * Even-period amsco ciphers need to adjust the line offset
	     */
	    if (itemPtr->period % 2 == 0) {
		if (amscoPtr->firstCellSize == 1 && row%2 == 1) {
		    ptPosition--;
		} else if (amscoPtr->firstCellSize == 2 && row%2 == 0) {
		    ptPosition--;
		}
	    }
	    row++;
	    cellSize = 3 - cellSize;
	}
	ptStartPosition += colStartCellSize;
	colStartCellSize = 3 - colStartCellSize;
    }

    amscoPtr->pt[itemPtr->length] = '\0';

    ckfree((char *)startPos);

    return amscoPtr->pt;
}

static int
RestoreAmsco(Tcl_Interp *interp, CipherItem *itemPtr, const char *key, const char *dummy)
{
    AmscoItem *amscoPtr = (AmscoItem *)itemPtr;
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

    if (strlen(key) != amscoPtr->header.period) {
	Tcl_SetResult(interp, "Length of key does not match period",
		TCL_STATIC);
	return TCL_ERROR;
    }

    for(i=0; i < amscoPtr->header.period; i++) {
	if (key[i] < 'a' || key[i] > 'z') {
	    Tcl_SetResult(interp, "Invalid character in key", TCL_STATIC);
	    return TCL_ERROR;
	}
	if (key[i] >= amscoPtr->header.period + 'a') {
	    Tcl_SetResult(interp, "key character out of range", TCL_STATIC);
	    return TCL_ERROR;
	}
	for(j=0; j < amscoPtr->header.period; j++) {
	    if (key[j] == key[i] && i != j) {
		Tcl_SetResult(interp, "duplicate key characters not allowed",
			TCL_STATIC);
		return TCL_ERROR;
	    }
	}
    }
    for(i=0; i < amscoPtr->header.period; i++) {
	amscoPtr->key[i] = key[i] - 'a';
    }

    return TCL_OK;
}

int
AmscoCheckSolutionValue(Tcl_Interp *interp, ClientData clientData, int *key, int keylen)
{
    AmscoItem *amscoPtr = (AmscoItem *)clientData;
    CipherItem *itemPtr = (CipherItem *)clientData;
    char *pt=(char *)NULL;
    char *tKey=(char *)NULL;
    int i;
    double value;
    Tcl_DString dsPtr;

    if (keylen != amscoPtr->header.period) {
	Tcl_SetResult(interp, "Key length != period!", TCL_STATIC);
	return TCL_ERROR;
    }

    tKey = (char *)ckalloc(sizeof(int) * keylen);

    for(i=0; i < keylen; i++) {
	tKey[i] = amscoPtr->key[i];
    }

    for(i=0; i < keylen; i++) {
	amscoPtr->key[i] = tKey[key[i]];
    }

    itemPtr->curIteration++;

    pt = GetAmsco(interp, (CipherItem *)amscoPtr);

    if (DefaultScoreValue(interp, (const char *)pt, &value) != TCL_OK) {
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
	    sprintf(temp_str, "%d", amscoPtr->key[i]);
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

    if (value > amscoPtr->maxValue) {
	char temp_str[128];
	Tcl_DStringInit(&dsPtr);

	if (itemPtr->bestFitCommand) {
	    Tcl_DStringAppendElement(&dsPtr, itemPtr->bestFitCommand);
	}

	sprintf(temp_str, "%lu", itemPtr->curIteration);
	Tcl_DStringAppendElement(&dsPtr, temp_str);

	amscoPtr->maxFirstCellSize = amscoPtr->firstCellSize;
	amscoPtr->maxValue = value;
	Tcl_DStringStartSublist(&dsPtr);
	for(i=0; i < keylen; i++) {
	    amscoPtr->maxKey[i] = amscoPtr->key[i];
	    sprintf(temp_str, "%d", amscoPtr->maxKey[i]);
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
	amscoPtr->key[i] = tKey[i];
    }

    ckfree((char *)tKey);
    return TCL_OK;
}

static int
SolveAmsco(Tcl_Interp *interp, CipherItem *itemPtr, char *maxkey)
{
    AmscoItem *amscoPtr = (AmscoItem *)itemPtr;
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
    amscoPtr->maxValue = 0;
    if (amscoPtr->maxKey) {
	ckfree((char *)amscoPtr->maxKey);
    }

    amscoPtr->maxKey = (char *)ckalloc(sizeof(char)*itemPtr->period);

    amscoPtr->firstCellSize = 1;
    AmscoInitKey(itemPtr, itemPtr->period);

    result = _internalDoPermCmd((ClientData)itemPtr, interp, itemPtr->period, AmscoCheckSolutionValue);

    if (result != TCL_OK) {
	return result;
    }

    amscoPtr->firstCellSize = 2;
    AmscoInitKey(itemPtr, itemPtr->period);

    result = _internalDoPermCmd((ClientData)itemPtr, interp, itemPtr->period, AmscoCheckSolutionValue);

    if (result != TCL_OK) {
	return result;
    }

    /*
     * Now apply the best key
     */

    amscoPtr->firstCellSize = amscoPtr->maxFirstCellSize;
    AmscoInitKey(itemPtr, itemPtr->period);
    for(i=0; i < itemPtr->period; i++) {
	amscoPtr->key[i] = amscoPtr->maxKey[i];
	maxkey[i] = amscoPtr->key[i] + 'a';
    }
    maxkey[i] = '\0';

    Tcl_SetResult(interp, maxkey, TCL_VOLATILE);

    return result;
}

static void
AmscoInitKey(CipherItem *itemPtr, int period)
{
    AmscoItem *amscoPtr = (AmscoItem *)itemPtr;
    int		i;

    if (amscoPtr->key) {
	ckfree(amscoPtr->key);
    }

    if (amscoPtr->colLength) {
	ckfree((char *)(amscoPtr->colLength));
    }

    amscoPtr->key = (char *)NULL;
    amscoPtr->colLength = (int *)NULL;
    amscoPtr->header.period = period;

    if (period) {
	int twoRowLength = period * 3;
	int remainder = itemPtr->length % twoRowLength;
	int baseColLen = (itemPtr->length - remainder) / period;
	int cellSize = amscoPtr->firstCellSize;

	amscoPtr->key=ckalloc(sizeof(char)*period+1);
	amscoPtr->colLength=(int *)ckalloc(sizeof(int)*(period+1));

	// Set the column lengths based on the first row of the remainder.
	for (i=0; i < period; i++) {
	    amscoPtr->key[i] = i;
	    amscoPtr->colLength[i] = baseColLen;

	    // Check for a cell size of 2 but only 1 character remaining.
	    if (remainder) {
		if (cellSize > remainder) {
		    amscoPtr->colLength[i] += remainder;
		    remainder = 0;
		} else {
		    amscoPtr->colLength[i] += cellSize;
		    remainder -= cellSize;
		    cellSize = 3 - cellSize;
		}
	    }
	}

	// Adjust the column lengths based on the second row of the remainder,
	// if any.
	cellSize = 3 - amscoPtr->firstCellSize;
	for (i=0; i < period && remainder > 0; i++) {
	    // Check for a cell size of 2 but only 1 character remaining.
	    if (cellSize > remainder) {
		amscoPtr->colLength[i] += remainder;
		remainder = 0;
	    } else {
		amscoPtr->colLength[i] += cellSize;
		remainder -= cellSize;
		cellSize = 3 - cellSize;
	    }
	}

	amscoPtr->key[period]='\0';
    }
}

static int
AmscoLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, const char *tip, const char *start)
{
    Tcl_SetResult(interp,
	    "No locate tip function defined for Amsco ciphers.",
	    TCL_STATIC);
    return TCL_ERROR;
}

static int
AmscoSwapColumns(Tcl_Interp *interp, CipherItem *itemPtr, int col1, int col2)
{
    AmscoItem *amscoPtr = (AmscoItem *)itemPtr;
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
	if (col1 == amscoPtr->key[i]) {
	    newCol1 = i;
	}
    }
    for(i=0; i < itemPtr->period; i++) {
	if (col2 == amscoPtr->key[i]) {
	    newCol2 = i;
	}
    }
    /*
     * This should never happen.
     */
    if (newCol1 == -1 || newCol2 == -1) {
	Tcl_SetResult(interp,
		"Fatal error in AmscoSwapColumns().  Non-unique column index found.",
		TCL_STATIC);
	return TCL_ERROR;
    }
    col1 = newCol1;
    col2 = newCol2;

    t = amscoPtr->key[col1];
    amscoPtr->key[col1] = amscoPtr->key[col2];
    amscoPtr->key[col2] = t;

    return TCL_OK;
}

static int
AmscoShiftColumn(Tcl_Interp *interp, CipherItem *itemPtr, int col, int amount)
{
    AmscoItem *amscoPtr = (AmscoItem *)itemPtr;
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
	if (col == amscoPtr->key[i]) {
	    start = i;
	}
    }

    if (start + amount < 0) {
	Tcl_SetResult(interp, "Can't shift backwards past the first column.",
		TCL_STATIC);
	return TCL_ERROR;
    }

    /*
     * Don't allow shifting past the end.
     */
    if (start + amount > itemPtr->period) {
	amount = itemPtr->period - start - 1;
    }

    tempKeyVal = amscoPtr->key[start];
    if (amount < 0) {
	for (i=0; i > amount; i--) {
	    int startIndex = (start + i + itemPtr->period)%itemPtr->period;
	    int endIndex = (start + i - 1 + itemPtr->period)%itemPtr->period;

	    amscoPtr->key[startIndex] = amscoPtr->key[endIndex];
	}
    } else {
	for (i=0; i < amount; i++) {
	    int startIndex = (start + i + itemPtr->period)%itemPtr->period;
	    int endIndex = (start + i + 1 + itemPtr->period)%itemPtr->period;

	    amscoPtr->key[startIndex] = amscoPtr->key[endIndex];
	}
    }

    amscoPtr->key[start+i] = tempKeyVal;

    return TCL_OK;
}

int
AmscoCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    AmscoItem *amscoPtr = (AmscoItem *)clientData;
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
	    sprintf(temp_str, "%d", amscoPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", itemPtr->period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!amscoPtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_STATIC);
	    } else {
		Tcl_SetResult(interp, amscoPtr->header.ciphertext, TCL_VOLATILE);
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
		temp_str[i] = amscoPtr->key[i]+'a';
		/*
		if (temp_str[i] > 'v') temp_str[i]++;
		*/
	    }
	    temp_str[itemPtr->period] = '\0';

	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);

	    return TCL_OK;
	} else if (strncmp(argv[1], "-startcellsize", 13) == 0) {
	    sprintf(temp_str, "%d", amscoPtr->firstCellSize);
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
		    Tcl_SetResult(interp, "Invalid period setting.",
			    TCL_STATIC);
		    return TCL_ERROR;
		}
		if (period < 0
			|| (itemPtr->length > 0 && period > itemPtr->length)) {
		    Tcl_SetResult(interp, "Invalid period setting.",
			    TCL_STATIC);
		    return TCL_ERROR;
		}

		AmscoInitKey(itemPtr, period);
		Tcl_SetResult(interp, argv[1], TCL_VOLATILE);
	    } else if (strncmp(*argv, "-startcellsize", 13) == 0) {
		int cellSize;
		if (sscanf(argv[1], "%d", &cellSize) != 1) {
		    Tcl_SetResult(interp, "Invalid startcellsize setting.",
			    TCL_STATIC);
		    return TCL_ERROR;
		}
		if (cellSize < 1 || cellSize > 2) {
		    Tcl_SetResult(interp, "Invalid startcellsize setting.  Must be 1 or 2",
			    TCL_STATIC);
		    return TCL_ERROR;
		}

		amscoPtr->firstCellSize = cellSize;
		AmscoInitKey(itemPtr, itemPtr->period);
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
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " restore key ?junk?", (char *)NULL);
	    return TCL_ERROR;
	}
	if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1], (char *)NULL) == TCL_ERROR) {
	    return TCL_ERROR;
	} else {
	    return TCL_OK;
	}
    } else if (**argv == 'e' && (strncmp(*argv, "encode", 1) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " encode pt key",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	return (itemPtr->typePtr->encodeProc)(interp, itemPtr, argv[1], argv[2]);
    } else if (**argv == 's' && (strncmp(*argv, "substitute", 2) == 0)) {
	Tcl_SetResult(interp,
		"No substitute command defined for amsco ciphers.",
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

	if (AmscoShiftColumn(interp, itemPtr, col, amount) != TCL_OK) {
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

	if (AmscoSwapColumns(interp, itemPtr, col1, col2) != TCL_OK) {
	    return TCL_ERROR;
	}
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
		"No locate tip function defined for amsco ciphers.",
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
EncodeAmsco(Tcl_Interp *interp, CipherItem *itemPtr, const char *pt, const char *key) {
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

    if (strlen(argv[0]) != itemPtr->period) {
	Tcl_SetResult(interp,
		"Length of key does not match the period.", TCL_STATIC);
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, pt) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }
    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[0], (char *)NULL) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }
    ct = AmscoTransform(itemPtr, itemPtr->ciphertext, ENCODE);
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
