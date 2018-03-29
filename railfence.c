/*
 * railfence.c --
 *
 *	This file implements the railfence cipher type.
 *
 * Copyright (c) 1995-2000 Michael Thomas <wart@kobold.org>
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

static int  CreateRailfence	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
void DeleteRailfence		_ANSI_ARGS_((ClientData));
static char *GetRailfence	_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetRailfence	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestoreRailfence	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolveRailfence	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
int RailfenceCmd		_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));
static int RailfenceUndo	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int RailfenceSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int RailfenceLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static void RailfenceInitKey	_ANSI_ARGS_((CipherItem *, int));
static void RailfenceAdjustKey	_ANSI_ARGS_((CipherItem *));
static int RailfenceSwapRails	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
	    			int, int));
static int RailfenceMoveStart	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
	    			int, int));
static void RailfenceSetKey	_ANSI_ARGS_((CipherItem *, int, int));
static char *RailfenceTransform	_ANSI_ARGS_((CipherItem *, const char *, int));

typedef struct RailfenceItem {
    CipherItem header;

    int maxColLen;	/* Length of longest column */
    int *colLength;	/* Length of each column */
    int *key;
    int numRails;	/* Number of rails.  == period * 2 - 2 */
} RailfenceItem;

CipherType RailfenceType = {
    "railfence",
    ATOZ,
    sizeof(RailfenceItem),
    CreateRailfence,	/* create proc */
    DeleteRailfence,	/* delete proc */
    RailfenceCmd,	/* cipher command proc */
    GetRailfence,	/* get plaintext proc */
    SetRailfence,	/* show ciphertext proc */
    SolveRailfence,	/* solve cipher proc */
    RestoreRailfence,	/* restore proc */
    RailfenceLocateTip,	/* locate proc */
    RailfenceSubstitute,	/* sub proc */
    RailfenceUndo,	/* undo proc */
    NULL,		/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

static int
CreateRailfence(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    RailfenceItem *railPtr = (RailfenceItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    railPtr->header.period = 0;
    railPtr->maxColLen = 0;
    railPtr->numRails = 0;
    railPtr->colLength = (int *)NULL;
    railPtr->key = (int *)NULL;

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, RailfenceCmd, itemPtr,
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
DeleteRailfence(ClientData clientData)
{
    RailfenceItem *railPtr = (RailfenceItem *)clientData;

    if (railPtr->key) {
	ckfree((char *)railPtr->key);
    }

    if (railPtr->colLength) {
	ckfree((char *)(railPtr->colLength));
    }

    DeleteCipher(clientData);
}

static int
SetRailfence(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
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
	if (itemPtr->ciphertext)
	    ckfree(itemPtr->ciphertext);
	itemPtr->ciphertext = c;

	if (itemPtr->ciphertext == NULL) {
	    Tcl_SetResult(interp, "Error mallocing memory for new cipher", TCL_VOLATILE);
	    return TCL_ERROR;
	}

	itemPtr->length = length;
	itemPtr->period = 0;

	Tcl_ValidateAllMemory(__FILE__, __LINE__);

	RailfenceInitKey(itemPtr, itemPtr->period);

	Tcl_ValidateAllMemory(__FILE__, __LINE__);

	Tcl_SetResult(interp, itemPtr->ciphertext, TCL_STATIC);
    }

    return valid;
}

static int
RailfenceUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int offset)
{
    RailfenceInitKey(itemPtr, itemPtr->period);

    return TCL_OK;
}

static int
RailfenceSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, const char *offset, int col)
{
    RailfenceItem *railPtr = (RailfenceItem *)itemPtr;

    col--;

    if (col < 0 || col > itemPtr->period) {
	Tcl_SetResult(interp, "Bad column.", TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (*offset < '1' || (*offset-'1') > itemPtr->period) {
	Tcl_SetResult(interp, "Bad value for column.", TCL_VOLATILE);
	return TCL_ERROR;
    }

    railPtr->key[col] = *offset - '1';

    RailfenceAdjustKey(itemPtr);

    Tcl_SetResult(interp, ct, TCL_VOLATILE);
    return TCL_OK;
}

static char *
GetRailfence(Tcl_Interp *interp, CipherItem *itemPtr)
{
    return RailfenceTransform(itemPtr, itemPtr->ciphertext, DECODE);
}

static char *
RailfenceTransform(CipherItem *itemPtr, const char *text, int mode) {
    RailfenceItem *railPtr = (RailfenceItem *)itemPtr;
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

	orderCount[railPtr->key[col]]++;
	/*
	 * Locate the col'th column(s) in the key
	 */
	for(i=0, numCols=0; i < itemPtr->period; i++) {
	    if (railPtr->key[i] == col) {
		colArr[numCols++] = i;
	    }
	}

	temp_pos = pos;
	for(i=0; i < numCols; i++) {
	    startPos[colArr[i]] = pos;
	    temp_pos += railPtr->colLength[colArr[i]];
	}
	pos = temp_pos;
    }

    for (col=0; col < itemPtr->length ; col++) {
	result[col] = '_';
    }

    for(col=0; col < itemPtr->period; col++) {
	newCol = railPtr->key[col];

	for(row=0; row < railPtr->colLength[col]; row++) {
	    int newIndex = row * itemPtr->period + orderArr[newCol] + newCol;
	    int oldIndex = startPos[col] + row * orderCount[newCol] + orderArr[newCol];
	    newIndex = col + row * itemPtr->period;

	    /*
	    fprintf(stdout, "map %d (%c) -> %d\n", oldIndex,
		    railPtr->header.ciphertext[oldIndex], newIndex);
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

    return result;
}

static void
RailfenceAdjustKey(CipherItem *itemPtr)
{
    RailfenceItem *railPtr = (RailfenceItem *)itemPtr;
    int *foundArr;
    int *newArr;
    int i, minVal, curVal, maxVal, threshhold;

    if (itemPtr->period < 1) return;

    foundArr = (int *)ckalloc(sizeof(int) * itemPtr->period);
    newArr = (int *)ckalloc(sizeof(int) * itemPtr->period);

    curVal = 0;
    threshhold = 0;

    minVal = maxVal = railPtr->key[0];

    for(i=0; i < itemPtr->period; i++) {
	foundArr[i] = 0;
	if (railPtr->key[i] < minVal)
	    minVal = railPtr->key[i];
	if (railPtr->key[i] > maxVal)
	    maxVal = railPtr->key[i];
    }

    for(i=0; i < itemPtr->period; i++) {
	foundArr[railPtr->key[i]]++;
	newArr[i] = railPtr->key[i];
    }

    while (curVal < itemPtr->period) {
	minVal = maxVal;

	for(i=0; i < itemPtr->period; i++) {
	    if (railPtr->key[i] >= threshhold && railPtr->key[i] < minVal) {
		minVal = railPtr->key[i];
	    }
	}

	for(i=0; i < itemPtr->period; i++) {
	    if (railPtr->key[i] == minVal) {
		newArr[i] = curVal;
	    }
	}

	threshhold = minVal + 1;
	curVal += foundArr[minVal];
    }
 
    for(i=0; i < itemPtr->period; i++) {
	railPtr->key[i] = newArr[i];
    }

    ckfree((char *)foundArr);
    ckfree((char *)newArr);
}

static int
RestoreRailfence(Tcl_Interp *interp, CipherItem *itemPtr, const char *key, const char *junk)
{
    RailfenceItem *railPtr = (RailfenceItem *)itemPtr;
    int i;

    for(i=0; i < railPtr->header.period; i++) {
	if (key[i] < 1 || key[i] > railPtr->header.period) {
	    Tcl_SetResult(interp, "Invalid character in order", TCL_VOLATILE);
	    return TCL_ERROR;
	}
    }
    for(i=0; i < railPtr->header.period; i++)
	railPtr->key[i] = key[i];

    return TCL_OK;
}

static int
SolveRailfence(Tcl_Interp *interp, CipherItem *itemPtr, char *maxkey)
{
    RailfenceItem *railPtr = (RailfenceItem *)itemPtr;
    double value=0.0;
    double maxValue=0.0;
    char *pt=(char *)NULL;
    int *maxKey;
    int i, j;

    if (railPtr->numRails == 0) {
	Tcl_SetResult(interp,
		"Can't do anything until the number of rails has been set",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp,
		"Can't do anything until the ciphertext has been set",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    maxKey = (int *)ckalloc(sizeof(int)*itemPtr->period);
    for(i=0; i < itemPtr->period; i++) {
	maxKey[i] = railPtr->key[i];
    }

    /*
     * Loop through every starting position for the current period
     * and check the digram values.
     */

    for(i=0; i < railPtr->numRails; i++) {
	value=0.0;
	RailfenceSetKey(itemPtr, i, 1);
	pt = GetRailfence(interp, itemPtr);

	if (pt) {
	    if (DefaultScoreValue(interp, pt, &value)
                    != TCL_OK) {
		return TCL_ERROR;
	    }
	    if (value > maxValue) {
		maxValue = value;
		for(j=0; j < itemPtr->period; j++) {
		    maxKey[j] = railPtr->key[j];
		}
	    }
	    ckfree(pt);
	} else {
	    Tcl_SetResult(interp, "Unknown error encounted during solve",
		    TCL_STATIC);
	    return TCL_ERROR;
	}
    }

    for(i=0; i < railPtr->numRails; i++) {
	value=0.0;
	RailfenceSetKey(itemPtr, i, -1);
	pt = GetRailfence(interp, itemPtr);

	if (pt) {
	    if (DefaultScoreValue(interp, pt, &value)
                    != TCL_OK) {
		return TCL_ERROR;
	    }
	    if (value > maxValue) {
		maxValue = value;
		for(j=0; j < itemPtr->period; j++) {
		    maxKey[j] = railPtr->key[j];
		}
	    }
	    ckfree(pt);
	} else {
	    Tcl_SetResult(interp, "Unknown error encounted during solve",
		    TCL_STATIC);
	    return TCL_ERROR;
	}

    }

    for(i=0; i < itemPtr->period; i++) {
	railPtr->key[i] = maxKey[i];
    }
    RailfenceAdjustKey(itemPtr);

    maxkey[i] = '\0';

    ckfree((char *)maxKey);

    Tcl_ResetResult(interp);

    return TCL_OK;
}

static void
RailfenceInitKey(CipherItem *itemPtr, int period)
{
    RailfenceItem *railPtr = (RailfenceItem *)itemPtr;
    int		i;
    int	*cycle;

    if (railPtr->colLength)
	ckfree((char *)(railPtr->colLength));

    if (railPtr->key)
	ckfree((char *)(railPtr->key));

    railPtr->key = (int *)NULL;
    railPtr->colLength = (int *)NULL;
    railPtr->header.period = period;
    if (period)
	railPtr->numRails = (period + 2) / 2;
    else
	railPtr->numRails = 0;

    if (period) {
	railPtr->key=(int *)ckalloc(sizeof(int)*(period+1));
	railPtr->colLength=(int *)ckalloc(sizeof(int)*(period+1));
	cycle = (int *)ckalloc(sizeof(int) * period * 2);
	railPtr->numRails = (period + 2) / 2;

	for(i=0; i < railPtr->numRails; i++) {
	    railPtr->key[i] = i;
	}

	RailfenceSetKey(itemPtr, 0, 1);

	railPtr->maxColLen =
	    (itemPtr->length%period == 0)?(itemPtr->length / period):(itemPtr->length/period + 1);

	for(i=0; i < itemPtr->period; i++) {
	    if ((unsigned int)(period*(railPtr->maxColLen-1)+i) < itemPtr->length)
		railPtr->colLength[i] = railPtr->maxColLen;
	    else
		railPtr->colLength[i] = railPtr->maxColLen - 1;
	}
	railPtr->key[period]=0;

	ckfree ((char *)cycle);
    }

    fflush(stdout);

    RailfenceAdjustKey(itemPtr);

    fflush(stdout);
}

static void
RailfenceSetKey(CipherItem *itemPtr, int start, int dir)
{
    RailfenceItem *railPtr = (RailfenceItem *)itemPtr;
    int curpos=0;
    int k=start;

    while (curpos < itemPtr->period) {
	railPtr->key[curpos] = k;

	k += dir;

	if (k < 0) {
	    dir = +1;
	    k = 1;
	} else if (k >= railPtr->numRails) {
	    dir = -1;
	    k = railPtr->numRails - 2;
	}

	curpos++;
    }

    RailfenceAdjustKey(itemPtr);
}

/*
 * We probably won't need this.
 */

static int
RailfenceLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, const char *tip, const char *start)
{
    Tcl_SetResult(interp, "No locate tip function defined for Railfence ciphers.",
	    TCL_VOLATILE);
    return TCL_ERROR;
}

static int
RailfenceSwapRails(Tcl_Interp *interp, CipherItem *itemPtr, int col1, int col2)
{
    RailfenceItem *railPtr = (RailfenceItem *)itemPtr;
    int i;
    int found_col1, found_col2;

    if (col1 < 1 ||
	col2 < 1 ||
	col1 > itemPtr->period ||
	col2 > itemPtr->period ||
	col1 == col2) {

	Tcl_SetResult(interp, "Bad column index", TCL_VOLATILE);
	return TCL_ERROR;
    }

    col1--, col2--;

    /*
     * Make sure the two rails actually exist.
     */
    for(i=0, found_col1=0, found_col2=0; i < itemPtr->period; i++) {
	if (railPtr->key[i] == col1)
	    found_col1 = 1;
	if (railPtr->key[i] == col2)
	    found_col2 = 1;
    }

    if (!found_col1 || !found_col2) {
	Tcl_SetResult(interp, "Invalid column", TCL_VOLATILE);
	return TCL_ERROR;
    }

    /*
     * We swap every occurence of each column with each other
     * which eliminates the need to call RailfenceSetKey()
     */

    for(i=0; i < itemPtr->period; i++) {
	if (railPtr->key[i] == col1) {
	    railPtr->key[i] = col2;
	} else if (railPtr->key[i] == col2) {
	    railPtr->key[i] = col1;
	}
    }

    /*
    t = railPtr->key[col1];
    railPtr->key[col1] = railPtr->key[col2];
    railPtr->key[col2] = t;
    */

    return TCL_OK;
}

/*
 * This routine will reset the key to a cyclic pattern (undoing any
 * changes made by swapping rails) and then set the start rail and
 * direction.
 */

static int
RailfenceMoveStart(Tcl_Interp *interp, CipherItem *itemPtr, int rail, int dir)
{
    RailfenceItem *railPtr = (RailfenceItem *)itemPtr;
    int i, offset;

    if (rail < 1 || rail > itemPtr->period) {
	Tcl_SetResult(interp, "Bad rail", TCL_VOLATILE);
	return TCL_ERROR;
    }

    rail--;
    offset = rail - railPtr->key[0];

    if (dir < 0) {
	for(i=0; i < railPtr->numRails; i++) {
	    railPtr->key[i] = (i + rail)%railPtr->numRails;
	}
    } else {
	for(i=0; i < railPtr->numRails; i++) {
	    railPtr->key[i] = (railPtr->numRails - 1 - i + rail)%railPtr->numRails;
	}
    }

    RailfenceSetKey(itemPtr, rail, dir);

    return TCL_OK;
}

int
RailfenceCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    RailfenceItem *railPtr = (RailfenceItem *)clientData;
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
	    sprintf(temp_str, "%d", railPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", itemPtr->period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!railPtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_VOLATILE);
	    } else {
		Tcl_SetResult(interp, railPtr->header.ciphertext, TCL_VOLATILE);
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
		temp_str[i] = railPtr->key[i]+'a';
	    }
	    temp_str[itemPtr->period] = '\0';

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

		if (argc != 2) {
		    Tcl_AppendResult(interp, "Usage:  ", cmd, " configure -period val", (char *)NULL);
		    return TCL_ERROR;
		}

		if (sscanf(argv[1], "%d", &period) != 1) {
		    Tcl_SetResult(interp, "Invalid period setting.", TCL_VOLATILE);
		    return TCL_ERROR;
		}
		/*
		 * Convert the current value of 'period', which is really
		 * the number of rails, to the real period.
		 */
		period = period * 2 - 2;

		if (period < 0 || period > itemPtr->length) {
		    Tcl_SetResult(interp, "Invalid period setting.", TCL_VOLATILE);
		    return TCL_ERROR;
		}

		RailfenceInitKey(itemPtr, period);
		Tcl_SetResult(interp, argv[1], TCL_VOLATILE);

		return TCL_OK;
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
    } else if (**argv == 'r' && (strncmp(*argv, "restore", 2) == 0)) {
	/*
	 * Accept a 4th argument even though we just ignore it.  This way
	 * all ciphers can be restored with the same number of arguments.
	 * Consistency is good.
	 */
	if (argc != 3 && argc != 4) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " restore ct pt", (char *)NULL);
	    return TCL_ERROR;
	}
	if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1], argv[2]) == TCL_ERROR) {
	    return TCL_ERROR;
	} else {
	    return TCL_OK;
	}
    } else if (**argv == 's' && (strncmp(*argv, "substitute", 2) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " substitute col val", (char *)NULL);
	    return TCL_ERROR;
	}
	if (sscanf(argv[1], "%d", &i) != 1) {
	    Tcl_AppendResult(interp, "Bad column number:  ", 
		    argv[1], (char *)NULL);
	    return TCL_ERROR;
	}
	return (itemPtr->typePtr->subProc)(interp, itemPtr, (char *)NULL, argv[2], i);
    } else if (**argv == 'm' && (strncmp(*argv, "move", 4) == 0)) {
	char dir;
	int posDir = 1;
	int rail = 0;
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " move rail dir", (char *)NULL);
	    return TCL_ERROR;
	}
	if (sscanf(argv[1], "%d", &rail) != 1) {
	    Tcl_AppendResult(interp, "Bad direction specification:  ", 
		    argv[1], (char *)NULL);
	    return TCL_ERROR;
	}

	if (sscanf(argv[2], "%c", &dir) != 1) {
	    Tcl_AppendResult(interp, "Bad direction specification:  ", 
		    argv[1], (char *)NULL);
	    return TCL_ERROR;
	} else {
	    if (dir == 'u') {
		posDir = 1;
	    } else if (dir == 'd') {
		posDir = -1;
	    } else {
		Tcl_AppendResult(interp, "Bad direction specification:  ", 
			argv[1], (char *)NULL);
		return TCL_ERROR;
	    }
	}
	return RailfenceMoveStart(interp, itemPtr, rail, posDir);
    } else if (**argv == 's' && (strncmp(*argv, "swap", 2) == 0)) {
	int col1, col2;
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " swap col1 col2",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	if (sscanf(argv[1], "%d", &col1) != 1) {
	    Tcl_SetResult(interp, "Bad column value.", TCL_VOLATILE);
	    return TCL_ERROR;
	}
	if (sscanf(argv[2], "%d", &col2) != 1) {
	    Tcl_SetResult(interp, "Bad column value.", TCL_VOLATILE);
	    return TCL_ERROR;
	}

	if (RailfenceSwapRails(interp, itemPtr, col1, col2) != TCL_OK) {
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
	(itemPtr->typePtr->undoProc)(interp, itemPtr, argv[1], (int) NULL);
	Tcl_SetResult(interp, "", TCL_VOLATILE);
	return TCL_OK;
    } else if (**argv == 'l' && (strncmp(*argv, "locate", 1) == 0)) {
	if (argc < 2 || argc > 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " locate pt ct", (char *)NULL);
	    return TCL_ERROR;
	}
	if (argc == 2)
	    return (itemPtr->typePtr->locateProc)(interp, itemPtr, argv[1], (char *)NULL);
	else 
	    return (itemPtr->typePtr->locateProc)(interp, itemPtr, argv[1], argv[2]);
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
	return TCL_ERROR;
    }

    return TCL_OK;
}

static int
EncodeMyszcowski(Tcl_Interp *interp, CipherItem *itemPtr, char *pt, char *key) {
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
    ct = RailfenceTransform(itemPtr, itemPtr->ciphertext, ENCODE);
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
