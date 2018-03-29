/*
 * myszcowski.c --
 *
 *	This file implements the myszcowski cipher type.
 * According to my tests, here is the relationship between key length
 * and number of possible keys:
 *
 * Key Length	Number of Keys
 *     1                    1
 *     2                    3
 *     3                   13
 *     4                   75
 *     5                  541
 *     6                4 683
 *     7               47 293
 *     8              545 835
 *     9            7 087 261
 *    10          102 247 563
 *    11        1 622 632 573
 *
 * Copyright (c) 1998-2003 Michael Thomas <wart@kobold.org>
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

#include <cipherDebug.h>

static int  CreateMyszcowski	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
void DeleteMyszcowski		_ANSI_ARGS_((ClientData));
static char *GetMyszcowski	_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetMyszcowski	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestoreMyszcowski	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolveMyszcowski	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
int MyszcowskiCmd		_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));
static int MyszcowskiUndo	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int MyszcowskiSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int MyszcowskiLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static void MyszcowskiInitKey	_ANSI_ARGS_((CipherItem *, int));
static void MyszcowskiAdjustKey	_ANSI_ARGS_((CipherItem *));
static int RecSolveMyszcowski	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
	    			int, int, int));
static int MyszcowskiShiftColumn _ANSI_ARGS_((Tcl_Interp *, CipherItem *, int,
	    			int));
static char *MyszcowskiTransform _ANSI_ARGS_((CipherItem *, const char *, int));
static int EncodeMyszcowski	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));

typedef struct MyszcowskiItem {
    CipherItem header;

    int maxColLen;	/* Length of longest column */
    int *colLength;	/* Length of each column */
    int *key;

    int *curKey;
    int *maxKey;
    double maxVal;
    int *tempArr1;
    int *tempArr2;
} MyszcowskiItem;

CipherType MyszcowskiType = {
    "myszcowski",
    ATOZ,
    sizeof(MyszcowskiItem),
    CreateMyszcowski,	/* create proc */
    DeleteMyszcowski,	/* delete proc */
    MyszcowskiCmd,	/* cipher command proc */
    GetMyszcowski,	/* get plaintext proc */
    SetMyszcowski,	/* show ciphertext proc */
    SolveMyszcowski,	/* solve cipher proc */
    RestoreMyszcowski,	/* restore proc */
    MyszcowskiLocateTip,/* locate proc */
    MyszcowskiSubstitute,	/* sub proc */
    MyszcowskiUndo,	/* undo proc */
    EncodeMyszcowski,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

static int
CreateMyszcowski(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    MyszcowskiItem *myszPtr = (MyszcowskiItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    myszPtr->header.period = 0;
    myszPtr->maxColLen = 0;
    myszPtr->colLength = (int *)NULL;
    myszPtr->key = (int *)NULL;
    myszPtr->maxKey = (int *)NULL;
    myszPtr->curKey = (int *)NULL;
    myszPtr->maxVal = 0.0;
    myszPtr->tempArr1 = (int *)NULL;
    myszPtr->tempArr2 = (int *)NULL;

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, MyszcowskiCmd, itemPtr,
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
DeleteMyszcowski(ClientData clientData)
{
    MyszcowskiItem *myszPtr = (MyszcowskiItem *)clientData;

    if (myszPtr->key) {
	ckfree((char *)myszPtr->key);
    }

    if (myszPtr->colLength) {
	ckfree((char *)(myszPtr->colLength));
    }

    if (myszPtr->maxKey) {
	ckfree((char *)(myszPtr->maxKey));
    }

    if (myszPtr->curKey) {
	ckfree((char *)(myszPtr->curKey));
    }

    if (myszPtr->tempArr1) {
	ckfree((char *)(myszPtr->tempArr1));
    }

    if (myszPtr->tempArr2) {
	ckfree((char *)(myszPtr->tempArr2));
    }

    DeleteCipher(clientData);
}

static int
SetMyszcowski(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
{
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

    valid = TCL_OK;

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
	if (itemPtr->period < 0 || itemPtr->period > length) {
	    itemPtr->period = 0;
	}

	Tcl_ValidateAllMemory(__FILE__, __LINE__);

	Tcl_ValidateAllMemory(__FILE__, __LINE__);

	Tcl_SetResult(interp, itemPtr->ciphertext, TCL_STATIC);
    }

    MyszcowskiInitKey(itemPtr, itemPtr->period);

    return valid;
}

static int
MyszcowskiUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int offset)
{
    MyszcowskiInitKey(itemPtr, itemPtr->period);

    return TCL_OK;
}

static int
MyszcowskiSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, const char *offset, int col)
{
    MyszcowskiItem *myszPtr = (MyszcowskiItem *)itemPtr;
    int intOffset = *offset-'a';

    col--;

    if (col < 0 || col >= itemPtr->period) {
	Tcl_SetResult(interp, "Bad column.", TCL_STATIC);
	return TCL_ERROR;
    }

    if (intOffset < 0 || intOffset >= itemPtr->period) {
	Tcl_SetResult(interp, "Bad value for column.", TCL_STATIC);
	return TCL_ERROR;
    }

    myszPtr->key[col] = intOffset+'a';
    /*
    printf("Pre-key:  ");
    for(i=0; i < itemPtr->period; i++) {
	printf("%3d ", myszPtr->key[i]);
    }
    */
	

    MyszcowskiAdjustKey(itemPtr);
    /*
    printf("\nPost-key: ");
    for(i=0; i < itemPtr->period; i++) {
	printf("%3d ", myszPtr->key[i]);
    }
    printf("\n");
    fflush(stdout);
    */

    Tcl_SetResult(interp, ct, TCL_VOLATILE);
    return TCL_OK;
}

static char *
GetMyszcowski(Tcl_Interp *interp, CipherItem *itemPtr)
{
    return MyszcowskiTransform(itemPtr, itemPtr->ciphertext, DECODE);
}

static char *
MyszcowskiTransform(CipherItem *itemPtr, const char *text, int mode) {
    MyszcowskiItem *myszPtr = (MyszcowskiItem *)itemPtr;
    char	*c;
    int		i, col, pos;
    char	*result=(char *)ckalloc(sizeof(char) * itemPtr->length + 1);
    int		newCol, row, numCols;
    int		*startPos=(int *)ckalloc(sizeof(int)*itemPtr->period);
    int		*colArr=(int *)ckalloc(sizeof(int)*itemPtr->period);
    int		*orderArr=(int *)ckalloc(sizeof(int)*itemPtr->period);
    int		*orderCount=(int *)ckalloc(sizeof(int)*itemPtr->period);

    /*
     * Locate the starting positions of each column in the ciphertext
     */

    for(col=0; col < itemPtr->period; col++) {
	orderCount[col] = 0;
	orderArr[col] = 0;
    }

    for(col=0, pos=0; col < itemPtr->period; col++) {
	int temp_pos;

	orderCount[myszPtr->key[col]]++;
	/*
	 * Locate the col'th column(s) in the key
	 */
	for(i=0, numCols=0; i < itemPtr->period; i++) {
	    if (myszPtr->key[i] == col) {
		colArr[numCols++] = i;
	    }
	}

	temp_pos = pos;
	for(i=0; i < numCols; i++) {
	    startPos[colArr[i]] = pos;
	    temp_pos += myszPtr->colLength[colArr[i]];
	}
	pos = temp_pos;
    }

    c = itemPtr->ciphertext;

    /*
     * Initialize the result.  Use a bogus character so that we can easily
     * detect errors in this routine.
     */
    for (col=0; col < itemPtr->length ; col++) {
	result[col] = '_';
    }

    for(col=0; col < itemPtr->period; col++) {
	newCol = myszPtr->key[col];

	for(row=0; row < myszPtr->colLength[col]; row++) {
	    int newIndex = row * itemPtr->period + orderArr[newCol] + newCol;
	    int oldIndex = startPos[col] + row * orderCount[newCol] + orderArr[newCol];
	    newIndex = col + row * itemPtr->period;

	    /*
	    fprintf(stdout, "map %d (%c) -> %d\n", oldIndex,
		    myszPtr->header.ciphertext[oldIndex], newIndex);
	    fflush(stdout);
	    */

	    if (newIndex > itemPtr->length || oldIndex > itemPtr->length) {
		fprintf(stderr, "Fatal indexing error!\n");
		abort();
	    }
	    if (mode == DECODE) {
		result[newIndex] = text[oldIndex];
	    } else {
		result[oldIndex] = text[newIndex];
	    }
	}
	orderArr[newCol]++;
    }

    result[itemPtr->length] = '\0';

    ckfree((char *)startPos);
    ckfree((char *)colArr);
    ckfree((char *)orderArr);
    ckfree((char *)orderCount);

    return result;
}

static void
MyszcowskiAdjustKey(CipherItem *itemPtr)
{
    MyszcowskiItem *myszPtr = (MyszcowskiItem *)itemPtr;
    int *foundArr;
    int *newArr;
    int i, minVal, curVal, maxVal, threshhold;

    if (itemPtr->period < 1) {
	return;
    }

    foundArr = (int *)ckalloc(sizeof(int) * itemPtr->period);
    newArr = (int *)ckalloc(sizeof(int) * itemPtr->period);

    curVal = 0;
    threshhold = 0;

    minVal = maxVal = myszPtr->key[0];

    for(i=0; i < itemPtr->period; i++) {
	foundArr[i] = 0;
	if (myszPtr->key[i] < minVal) {
	    minVal = myszPtr->key[i];
	}
	if (myszPtr->key[i] > maxVal) {
	    maxVal = myszPtr->key[i];
	}
    }

    for(i=0; i < itemPtr->period; i++) {
	foundArr[myszPtr->key[i]]++;
	newArr[i] = myszPtr->key[i];
    }

    while (curVal < itemPtr->period) {
	minVal = maxVal;

	for(i=0; i < itemPtr->period; i++) {
	    if (myszPtr->key[i] >= threshhold && myszPtr->key[i] < minVal) {
		minVal = myszPtr->key[i];
	    }
	}

	for(i=0; i < itemPtr->period; i++) {
	    if (myszPtr->key[i] == minVal) {
		newArr[i] = curVal;
	    }
	}

	threshhold = minVal + 1;
	curVal += foundArr[minVal];
    }
 
    for(i=0; i < itemPtr->period; i++) {
	myszPtr->key[i] = newArr[i];
    }

    ckfree((char *)foundArr);
    ckfree((char *)newArr);
}

static int
RestoreMyszcowski(Tcl_Interp *interp, CipherItem *itemPtr, const char *key, const char *junk)
{
    MyszcowskiItem *myszPtr = (MyszcowskiItem *)itemPtr;
    int i;

    if (myszPtr->header.length <= 0) {
	Tcl_SetResult(interp,
		"Can't restore until the ciphertext has been set.",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (myszPtr->header.period <= 0) {
	Tcl_SetResult(interp, "Can't restore until the period has been set.",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (myszPtr->header.period != strlen(key)) {
	Tcl_SetResult(interp, "Length of key does not match the period.",
		TCL_STATIC);
	return TCL_ERROR;
    }

    for(i=0; i < myszPtr->header.period; i++) {
	int tempKeyVal = key[i] - 'a';
	if (tempKeyVal < 0 || tempKeyVal >= myszPtr->header.period) {
	    Tcl_SetResult(interp, "Invalid character in key", TCL_STATIC);
	    return TCL_ERROR;
	}
    }
    for(i=0; i < myszPtr->header.period; i++) {
	myszPtr->key[i] = key[i]-'a';
    }

    return TCL_OK;
}

static int
SolveMyszcowski(Tcl_Interp *interp, CipherItem *itemPtr, char *maxkey)
{
    MyszcowskiItem *myszPtr = (MyszcowskiItem *)itemPtr;
    int i, sum=0;

    if (itemPtr->length <= 0) {
	Tcl_SetResult(interp, "Can't solve until the ciphertext has been set.",
		TCL_STATIC);
	return TCL_ERROR;
    }
    if (itemPtr->period <= 0) {
	Tcl_SetResult(interp, "Can't solve until the period has been set.",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (myszPtr->maxKey) {
	ckfree((char *)(myszPtr->maxKey));
    }
    if (myszPtr->curKey) {
	ckfree((char *)(myszPtr->curKey));
    }
    myszPtr->maxKey = (int *)ckalloc(sizeof(int) * itemPtr->period);
    myszPtr->curKey = (int *)ckalloc(sizeof(int) * itemPtr->period);
    for(i=0; i < itemPtr->period; i++) {
	myszPtr->maxKey[i] = '\0';
    }
    myszPtr->maxVal = 0.0;
    itemPtr->curIteration = 0;

    for(i=0, sum=0; i < itemPtr->period; i++) {
	sum += i;
	myszPtr->tempArr1[i] = myszPtr->tempArr2[i] = 0;
    }

    if (RecSolveMyszcowski(interp, itemPtr, 0, sum, 0) != TCL_OK) {
	return TCL_ERROR;
    }

    for(i=0; i < itemPtr->period; i++) {
	myszPtr->key[i] = myszPtr->maxKey[i];
    }

    if (myszPtr->maxKey) {
	ckfree((char *)(myszPtr->maxKey));
    }
    if (myszPtr->curKey) {
	ckfree((char *)(myszPtr->curKey));
    }
    myszPtr->maxKey = (int *)NULL;
    myszPtr->curKey = (int *)NULL;
    /*
    printf("Tried %ld keys\n", itemPtr->curIteration);
    */

    Tcl_SetResult(interp, "", TCL_STATIC);

    return TCL_OK;
}

static int
RecSolveMyszcowski(Tcl_Interp *interp, CipherItem *itemPtr, int depth, int sum, int total)
{
    MyszcowskiItem *myszPtr = (MyszcowskiItem *)itemPtr;
    int i, j;

    if (depth >= itemPtr->period) {
	Tcl_DString dsPtr;
	double value=0.0;
	char *pt = (char *)NULL;

	itemPtr->curIteration++;

	/*
	 * Check the current value
	 */

	pt = GetMyszcowski(interp, itemPtr);

	if (itemPtr->stepInterval && itemPtr->curIteration % itemPtr->stepInterval == 0 && itemPtr->stepCommand && pt) {
	    char temp_str[128];

	    Tcl_DStringInit(&dsPtr);

	    Tcl_DStringAppendElement(&dsPtr, itemPtr->stepCommand);

	    sprintf(temp_str, "%ld", itemPtr->curIteration);
	    Tcl_DStringAppendElement(&dsPtr, temp_str);

	    Tcl_DStringStartSublist(&dsPtr);
	    for(i=0; i < itemPtr->period; i++) {
		sprintf(temp_str, "%d", myszPtr->key[i]);
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

	if (pt) {
	    if (DefaultScoreValue(interp, pt, &value)
                    != TCL_OK) {
		return TCL_ERROR;
	    }

	    if (value > myszPtr->maxVal) {
		char temp_str[128];

		Tcl_DStringInit(&dsPtr);

		if (itemPtr->bestFitCommand) {
		    Tcl_DStringAppendElement(&dsPtr, itemPtr->bestFitCommand);
		}

		sprintf(temp_str, "%ld", itemPtr->curIteration);
		Tcl_DStringAppendElement(&dsPtr, temp_str);

		myszPtr->maxVal = value;
		for(i=0; i < itemPtr->period; i++) {
		    myszPtr->maxKey[i] = myszPtr->key[i];
		}

		Tcl_DStringStartSublist(&dsPtr);
		for(i=0; i < itemPtr->period; i++) {
		    sprintf(temp_str, "%d", myszPtr->key[i]);
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

	    ckfree(pt);
	    pt = (char *)NULL;
	}
    } else {
	int end = itemPtr->period-1;
	int valid=1;

	for(i=0; i <= end && (total+i<=sum); i++) {
	    valid=1;

	    myszPtr->tempArr1[i]++;

	    if (myszPtr->tempArr2[i]) {
		valid = 0;
	    }

	    for(j=1; j < myszPtr->tempArr1[i] && valid; j++) {
		/*
		 * Check that we're not inserting too many of one number
		 * beneath another:
		 *
		 * 5,4 -> 5,4,4
		 *
		 * or
		 *
		 * 0,0 -> 0,0,1
		 */
		if (myszPtr->tempArr1[i+j]) {
		    valid=0;
		} else {
		    myszPtr->tempArr2[i+j] = 1;
		}
	    }

	    if (valid) {
		myszPtr->key[depth] = i;
		if (RecSolveMyszcowski(interp, itemPtr, depth+1, sum, total+i)
			!= TCL_OK)
		    return TCL_ERROR;

		myszPtr->tempArr2[myszPtr->tempArr1[i]-1 + i] = 0;
	    }
	    myszPtr->tempArr1[i]--;
	}
    }

    return TCL_OK;
}

static void
MyszcowskiInitKey(CipherItem *itemPtr, int period)
{
    MyszcowskiItem *myszPtr = (MyszcowskiItem *)itemPtr;
    int		i;

    if (myszPtr->colLength) {
	ckfree((char *)(myszPtr->colLength));
    }

    if (myszPtr->key) {
	ckfree((char *)(myszPtr->key));
    }

    if (myszPtr->tempArr1) {
	ckfree((char *)(myszPtr->tempArr1));
    }

    if (myszPtr->tempArr2) {
	ckfree((char *)(myszPtr->tempArr2));
    }

    myszPtr->key = (int *)NULL;
    myszPtr->tempArr1 = (int *)NULL;
    myszPtr->tempArr2 = (int *)NULL;
    myszPtr->colLength = (int *)NULL;
    myszPtr->header.period = period;

    if (period) {
	myszPtr->key=(int *)ckalloc(sizeof(int)*(period+1));
	myszPtr->tempArr1=(int *)ckalloc(sizeof(int)*(period+1));
	myszPtr->tempArr2=(int *)ckalloc(sizeof(int)*(period+1));
	myszPtr->colLength=(int *)ckalloc(sizeof(int)*(period+1));

	myszPtr->maxColLen =
	    (itemPtr->length%period == 0)?(itemPtr->length / period):(itemPtr->length/period + 1);

	for(i=0; i < itemPtr->period; i++) {
	    myszPtr->key[i] = i;
	    if ((unsigned int)(period*(myszPtr->maxColLen-1)+i) < itemPtr->length) {
		myszPtr->colLength[i] = myszPtr->maxColLen;
	    } else {
		myszPtr->colLength[i] = myszPtr->maxColLen - 1;
	    }
	}
	myszPtr->key[period]=0;
    }
}

/*
 * We probably won't need this.
 */

static int
MyszcowskiLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, const char *tip, const char *start)
{
    Tcl_SetResult(interp,
	    "No locate tip function defined for Myszcowski ciphers.",
	    TCL_STATIC);
    return TCL_ERROR;
}

static int
MyszcowskiSwapColumns(Tcl_Interp *interp, CipherItem *itemPtr, int col1, int col2)
{
    MyszcowskiItem *myszPtr = (MyszcowskiItem *)itemPtr;
    char t;
    int i;
    int newCol1 = -1;
    int newCol2 = -1;

    if (col1 < 1 || col1 > itemPtr->period) {
	    char temp_str[2];
	temp_str[0] = (char) (col1 + 'a' - 1);
	temp_str[1] = '\0';
	Tcl_AppendResult(interp, "Bad column index '", temp_str, "'",
		(char *)NULL);
	return TCL_ERROR;
    }

    if (col2 < 1 || col2 > itemPtr->period) {
	char temp_str[2];
	temp_str[0] = (char) (col2 + 'a' - 1);
	temp_str[1] = '\0';
	Tcl_AppendResult(interp, "Bad column index '", temp_str, "'",
		(char *)NULL);
	return TCL_ERROR;
    }

    col1--, col2--;

    for(i=0; i < itemPtr->period; i++) {
	if (col1 == myszPtr->key[i]) {
	    newCol1 = i;
	}
    }
    for(i=0; i < itemPtr->period; i++) {
	if (col2 == myszPtr->key[i]) {
	    newCol2 = i;
	}
    }
    col1 = newCol1;
    col2 = newCol2;

    if (col1 == col2) {
	return TCL_OK;
    }

    t = myszPtr->key[col1];
    myszPtr->key[col1] = myszPtr->key[col2];
    myszPtr->key[col2] = t;

    return TCL_OK;
}

int
MyszcowskiCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    MyszcowskiItem *myszPtr = (MyszcowskiItem *)clientData;
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
	    Tcl_AppendResult(interp, "Usage:  ", cmd,
		    " cget option", (char *)NULL);
	    return TCL_ERROR;
	}
	if (strncmp(argv[1], "-length", 6) == 0) {
	    sprintf(temp_str, "%d", myszPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", itemPtr->period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!myszPtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_STATIC);
	    } else {
		Tcl_SetResult(interp, myszPtr->header.ciphertext, TCL_VOLATILE);
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
	    for(i=0; i < itemPtr->period; i++) {
		temp_str[i] = myszPtr->key[i]+'a';
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
	    } else if (strncmp(*argv, "-period", 7) == 0) {
		int period;

		if (argc < 2) {
		    Tcl_AppendResult(interp, "Usage:  ", cmd,
			    " configure -period val", (char *)NULL);
		    return TCL_ERROR;
		}

		if (sscanf(argv[1], "%d", &period) != 1) {
		    Tcl_SetResult(interp, "Invalid period setting.",
			    TCL_STATIC);
		    return TCL_ERROR;
		}
		if (period < 0 || (itemPtr->length > 0 && period > itemPtr->length)) {
		    Tcl_SetResult(interp, "Invalid period setting.",
			    TCL_STATIC);
		    return TCL_ERROR;
		}

		MyszcowskiInitKey(itemPtr, period);
		Tcl_SetResult(interp, argv[1], TCL_VOLATILE);
	    } else if (strncmp(*argv, "-ciphertext", 10) == 0 ||
		strncmp(*argv, "-ctext", 3) == 0) {
		if (argc < 2) {
		    Tcl_AppendResult(interp, "Usage:  ", cmd,
			    " configure -ciphertext text", (char *)NULL);
		    return TCL_ERROR;
		}

		if ((itemPtr->typePtr->setctProc)(interp, itemPtr, argv[1])
			!= TCL_OK) {
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
    } else if (**argv == 'r' && (strncmp(*argv, "restore", 2) == 0)) {
	/*
	 * Accept a 4th argument even though we just ignore it.  This way
	 * all ciphers can be restored with the same number of arguments.
	 * Consistency is good.
	 */
	if (argc < 2 || argc > 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd,
		    " restore key", (char *)NULL);
	    return TCL_ERROR;
	}
	if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1], (char *)NULL)
		== TCL_ERROR) {
	    return TCL_ERROR;
	} else {
	    return TCL_OK;
	}
    } else if (**argv == 's' && (strncmp(*argv, "substitute", 2) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd,
		    " substitute col val", (char *)NULL);
	    return TCL_ERROR;
	}
	if (sscanf(argv[1], "%d", &i) != 1) {
	    Tcl_SetResult(interp, "Invalid column", TCL_STATIC);
	    return TCL_ERROR;
	}
	/*
	 * Adjust the column to a more useful value
	 */
	return (itemPtr->typePtr->subProc)(interp, itemPtr,
		(char *)NULL, argv[2], i);
    } else if (**argv == 's' && (strncmp(*argv, "swap", 2) == 0)) {
	int col1, col2;
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " swap col1 col2",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	if (strlen(argv[1]) != 1) {
	    Tcl_AppendResult(interp, "Bad column index '", argv[1], "'",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	col1 = argv[1][0]-'a'+1;
	if (strlen(argv[2]) != 1) {
	    Tcl_AppendResult(interp, "Bad column index '", argv[2], "'",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	col2 = argv[2][0]-'a'+1;

	if (itemPtr->period < 1) {
	    Tcl_SetResult(interp,
		    "Can't swap columns until the period has been set.",
		    TCL_STATIC);
	    return TCL_ERROR;
	}

	if (itemPtr->length <= 0) {
	    Tcl_SetResult(interp,
		    "Can't swap columns until the ciphertext has been set.",
		    TCL_STATIC);
	    return TCL_ERROR;
	}

	if (MyszcowskiSwapColumns(interp, itemPtr, col1, col2) != TCL_OK) {
	    return TCL_ERROR;
	}
    } else if (**argv == 's' && (strncmp(*argv, "solve", 2) == 0)) {
	if( (itemPtr->typePtr->solveProc)(interp, itemPtr, temp_str)
		!= TCL_OK) {
	    return TCL_ERROR;
	} else {
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	}
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

	if (MyszcowskiShiftColumn(interp, itemPtr, col, amount) != TCL_OK) {
	    return TCL_ERROR;
	}
    } else if (**argv == 'e' && (strncmp(*argv, "encode", 1) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " encode pt key",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	return (itemPtr->typePtr->encodeProc)(interp, itemPtr, argv[1], argv[2]);
    } else if (**argv == 'u' && (strncmp(*argv, "undo", 1) == 0)) {
	(itemPtr->typePtr->undoProc)(interp, itemPtr, argv[1], 0);
	Tcl_SetResult(interp, "", TCL_STATIC);
	return TCL_OK;
    } else if (**argv == 'l' && (strncmp(*argv, "locate", 1) == 0)) {
	if (argc < 2 || argc > 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd,
		    " locate pt ct", (char *)NULL);
	    return TCL_ERROR;
	}
	if (argc == 2)
	    return (itemPtr->typePtr->locateProc)(interp, itemPtr,
		    argv[1], (char *)NULL);
	else 
	    return (itemPtr->typePtr->locateProc)(interp, itemPtr,
		    argv[1], argv[2]);
    } else {
	Tcl_AppendResult(interp, "Unknown option ", *argv, (char *)NULL);
	Tcl_AppendResult(interp, "\nMust be one of:  ", cmd,
			" cget ?option?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" configure ?option value?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" restore key", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" substitute col val", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" shift col amount", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" swap col1 col2", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" solve", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" undo ct", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" encode pt key", (char *)NULL);
	return TCL_ERROR;
    }

    return TCL_OK;
}

static int
MyszcowskiShiftColumn(Tcl_Interp *interp, CipherItem *itemPtr, int col, int amount)
{
    MyszcowskiItem *myszPtr = (MyszcowskiItem *)itemPtr;
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
	if (col == myszPtr->key[i]) {
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


    tempKeyVal = myszPtr->key[start];
    if (amount < 0) {
	for (i=0; i > amount; i--) {
	    int startIndex = (start + i + itemPtr->period)%itemPtr->period;
	    int endIndex = (start + i - 1 + itemPtr->period)%itemPtr->period;

	    myszPtr->key[startIndex] = myszPtr->key[endIndex];
	}
    } else {
	for (i=0; i < amount; i++) {
	    int startIndex = (start + i + itemPtr->period)%itemPtr->period;
	    int endIndex = (start + i + 1 + itemPtr->period)%itemPtr->period;

	    myszPtr->key[startIndex] = myszPtr->key[endIndex];
	}
    }

    myszPtr->key[start+i] = tempKeyVal;

    return TCL_OK;
}

static int
EncodeMyszcowski(Tcl_Interp *interp, CipherItem *itemPtr, const char *pt, const char *key) {
    char *ct = (char *)NULL;
    int count;
    char **argv;

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
    ct = MyszcowskiTransform(itemPtr, itemPtr->ciphertext, ENCODE);
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

    Tcl_SetResult(interp, ct, TCL_DYNAMIC);
    ckfree((char *)argv);

    return TCL_OK;
}
