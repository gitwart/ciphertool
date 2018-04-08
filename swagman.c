/*
 * swagman.c --
 *
 *	This file implements the swagman cipher type.
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
#include <perm.h>

#include <cipherDebug.h>

static int  CreateSwagman	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
void DeleteSwagman		_ANSI_ARGS_((ClientData));
static char *GetSwagman		_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetSwagman		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestoreSwagman	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolveSwagman	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
int SwagmanCmd			_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));
static int SwagmanUndo		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int SwagmanSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int SwagmanLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static void SwagmanInitKey	_ANSI_ARGS_((CipherItem *, int));
static char *SwagmanCtToBlock	_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static char *SwagmanPtToBlock	_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int SwagmanSolveValue	_ANSI_ARGS_((Tcl_Interp *, ClientData,
	    			int *, int));
static int RecSolveSwagman	_ANSI_ARGS_((Tcl_Interp *, CipherItem *, int));
static int SwagmanSwapRows	_ANSI_ARGS_((Tcl_Interp *, CipherItem *, int,
	    			int));

typedef struct SwagmanItem {
    CipherItem header;

    char **key;
    int numSquares;

    char **maxSolKey;
    double maxSolVal;
} SwagmanItem;

/*
 * This will allow us to pass two pieces of information through
 * the permutation function's ClientData parameter.
 */

typedef struct SwagmanSolveItem {
    CipherItem *itemPtr;
    int depth;
} SwagmanSolveItem;

CipherType SwagmanType = {
    "swagman",
    ATOZ,
    sizeof(SwagmanItem),
    CreateSwagman,	/* create proc */
    DeleteSwagman,	/* delete proc */
    SwagmanCmd,	/* cipher command proc */
    GetSwagman,	/* get plaintext proc */
    SetSwagman,	/* show ciphertext proc */
    SolveSwagman,	/* solve cipher proc */
    RestoreSwagman,	/* restore proc */
    SwagmanLocateTip,/* locate proc */
    SwagmanSubstitute,	/* sub proc */
    SwagmanUndo,	/* undo proc */
    NULL,		/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

static int
CreateSwagman(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    SwagmanItem *swagPtr = (SwagmanItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    swagPtr->header.period = 0;
    swagPtr->key = (char **)NULL;
    swagPtr->numSquares = 0;
    swagPtr->maxSolVal = 0.0;
    swagPtr->maxSolKey = (char **)NULL;

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, SwagmanCmd, itemPtr,
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
DeleteSwagman(ClientData clientData)
{
    SwagmanItem *swagPtr = (SwagmanItem *)clientData;
    int i;

    if (swagPtr->key) {
	for(i=0; i < swagPtr->header.period; i++) {
	    ckfree((char *)(swagPtr->key[i]));
	}
	ckfree((char *)swagPtr->key);
    }

    DeleteCipher(clientData);
}

static void
SwagmanInitKey(CipherItem *itemPtr, int period)
{
    SwagmanItem *swagPtr = (SwagmanItem *)itemPtr;
    int i, j;

    if (period < 2 || itemPtr->length%period != 0) {
	return;
    }

    if (swagPtr->key) {
	for(i=0; i < itemPtr->period; i++) {
	    ckfree(swagPtr->key[i]);
	}
	ckfree((char *)swagPtr->key);
    }

    swagPtr->key = (char **)ckalloc(sizeof(char *) * period);
    for(i=0; i < period; i++) {
	swagPtr->key[i] = (char *)ckalloc(sizeof(char) * period);
	for(j=0; j < period; j++) {
	    swagPtr->key[i][j] = '\0';
	}
    }

    itemPtr->period = period;
    if (itemPtr->length % (period*period) == 0) {
	swagPtr->numSquares = (itemPtr->length / (period*period));
    } else {
	swagPtr->numSquares = (itemPtr->length / (period*period))+1;
    }
}

static int
SetSwagman(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
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
	    Tcl_SetResult(interp, "Error mallocing memory for new cipher", TCL_VOLATILE);
	    return TCL_ERROR;
	}

	itemPtr->length = length;
	SwagmanInitKey(itemPtr, itemPtr->period);

	Tcl_SetResult(interp, itemPtr->ciphertext, TCL_STATIC);
    }

    return valid;
}

static int
SwagmanUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int offset)
{
    SwagmanItem *swagPtr = (SwagmanItem *)itemPtr;
    int i, j;

    for(i=0; i < itemPtr->period; i++) {
	for(j=0; j < itemPtr->period; j++) {
	    swagPtr->key[i][j] = '\0';
	}
    }
    return TCL_OK;
}

static int
SwagmanSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, const char *pt, int offset)
{
    SwagmanItem *swagPtr = (SwagmanItem *)itemPtr;
    int row, col;

    /*
     * pt == row
     * ct == col
     * offset == val
     */

    row = *ct - '1';
    col = *pt - '1';

    if (row < 0 || row >= itemPtr->period) {
	Tcl_SetResult(interp, "Invalid row specification", TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (col < 0 || col >= itemPtr->period) {
	Tcl_SetResult(interp, "Invalid column specification", TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (offset < 0 || offset > itemPtr->period) {
	Tcl_SetResult(interp, "Invalid value specification", TCL_VOLATILE);
	return TCL_ERROR;
    }

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    swagPtr->key[row][col] = offset;

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    return TCL_OK;
}

static char *
GetSwagman(Tcl_Interp *interp, CipherItem *itemPtr)
{
    SwagmanItem *swagPtr = (SwagmanItem *)itemPtr;
    int		i;
    int		row;
    int		col;
    int		blocksize;
    int		rowLength;
    char	*result=(char *)NULL;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp, "Can't do anything until ciphertext has been set",
		TCL_VOLATILE);
	return (char *)NULL;
    }

    if (itemPtr->period <= 0) {
	Tcl_SetResult(interp, "Can't do anything until a block width has been set",
		TCL_VOLATILE);
	return (char *)NULL;
    }

    result=(char *)ckalloc(sizeof(char) * itemPtr->length + 1);

    for(i=0; i < itemPtr->length; i++) {
	result[i] = ' ';
    }

    blocksize = itemPtr->period*itemPtr->period;
    rowLength = itemPtr->length / itemPtr->period;

    for(row=0; row < itemPtr->period; row++) {
	for(col=0; col < itemPtr->period; col++) {
	    int keyVal;
	    int srcPos, destPos;
	    
	    keyVal = swagPtr->key[row][col];

	    if (keyVal) {
		/*
		 * Be very careful withthis indexing.  The ciphertext is read
		 * off by columns, but the plaintext is read off by rows.
		 */
		for(srcPos=col*itemPtr->period + (keyVal-1),
			destPos=row*rowLength + col;
			srcPos < itemPtr->length;
			srcPos += blocksize, destPos += itemPtr->period) {

		    if (srcPos > itemPtr->length || destPos > itemPtr->length) {
			fprintf(stderr, "Fatal indexing error! %s: line %d\n",
				__FILE__, __LINE__);
			abort();
		    }
		    result[destPos] = itemPtr->ciphertext[srcPos];
		}
	    }
	}
    }

    result[itemPtr->length] = '\0';

    return result;
}

static int
RestoreSwagman(Tcl_Interp *interp, CipherItem *itemPtr, const char *key, const char *dummy)
{
    SwagmanItem *swagPtr = (SwagmanItem *)itemPtr;
    int i;
    int row;
    int col;

    if (itemPtr->length <= 0) {
	Tcl_SetResult(interp, "Can't do anything until ciphertext has been set",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (itemPtr->period <= 0) {
	Tcl_SetResult(interp, "Can't do anything until a block width has been set",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (strlen(key) != itemPtr->period * itemPtr->period) {
	char tempStr[TCL_DOUBLE_SPACE*2+11];
	sprintf(tempStr, "%ld should be %d", strlen(key), itemPtr->period * itemPtr->period);
	Tcl_AppendResult(interp, "Invalid key length:  ",
	       tempStr,  ".  Invalid key was:  ", key, (char *)NULL);
	return TCL_ERROR;
    }

    for(i=0; i < itemPtr->period*itemPtr->period; i++) {
	if ( (key[i] < '0' || key[i] > '0' + itemPtr->period) &&
		key[i] != ' ') {
            SwagmanInitKey(itemPtr, itemPtr->period);
	    Tcl_SetResult(interp, "Invalid character in key", TCL_VOLATILE);
	    return TCL_ERROR;
	}
	row = i / itemPtr->period;
	col = i % itemPtr->period;

	if (key[i] == ' ') {
	    swagPtr->key[row][col] = '\0';
	} else {
	    swagPtr->key[row][col] = key[i] - '0';
	}
    }

    /*
     * We've already validated that the key contains valid characters.
     * Use a bitmap shifted by the key amount to track which letters
     * have been used.  Eg:
     * for i in 1 to period: used = 1<<key[i]
     * if used == 1|2|4|8.. then all are used
     *
     * This works fine if all elements of the key are set.  It fails
     * if any are left empty.
     */
    if (itemPtr->period <= sizeof(unsigned int)*8) {

        for (unsigned int i=0 ; i < itemPtr->period; i++) {
            unsigned int rowMap = 0,
                         colMap = 0;

            for (unsigned int j=0 ; j < itemPtr->period; j++) {
                if (rowMap & 1<<(swagPtr->key[j][i]-1)) {
                    char temp_str[128];
                    sprintf(temp_str, "Duplicate key value in row %d: %c",
                            j, swagPtr->key[j][i]+'0');

                    SwagmanInitKey(itemPtr, itemPtr->period);
                    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
                    return TCL_ERROR;
                }
                if (colMap & 1<<(swagPtr->key[i][j]-1)) {
                    char temp_str[128];
                    sprintf(temp_str, "Duplicate key value in row %d: %c",
                            j, swagPtr->key[i][j]+'0');

                    SwagmanInitKey(itemPtr, itemPtr->period);
                    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
                    return TCL_ERROR;
                }
                if (swagPtr->key[j][i]) {
                    rowMap |= 1<<(swagPtr->key[j][i]-1);
                }
                if (swagPtr->key[i][j]) {
                    colMap |= 1<<(swagPtr->key[i][j]-1);
                }
            }
        }
    }

    return TCL_OK;
}

static int
SolveSwagman(Tcl_Interp *interp, CipherItem *itemPtr, char *maxkey)
{
    SwagmanItem *swagPtr = (SwagmanItem *)itemPtr;
    int i, j;

    if (itemPtr->length <= 0) {
	Tcl_SetResult(interp, "Can't do anything until ciphertext has been set",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (itemPtr->period <= 0) {
	Tcl_SetResult(interp, "Can't do anything until a block width has been set",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    itemPtr->curIteration=0;
    swagPtr->maxSolVal=0.0;
    swagPtr->maxSolKey=(char **)ckalloc(sizeof(char *) * itemPtr->period);
    for(i=0; i < itemPtr->period; i++) {
	swagPtr->maxSolKey[i] = (char *)ckalloc(sizeof(char) * itemPtr->period);
	for(j=0; j < itemPtr->period; j++) {
	    swagPtr->maxSolKey[i][j] = 0;
	}
    }

    if (RecSolveSwagman(interp, itemPtr, 0) != TCL_OK) {
	for(i=0; i < itemPtr->period; i++) {
	    ckfree((char *)(swagPtr->maxSolKey[i]));
	}
	ckfree((char *)swagPtr->maxSolKey);
	swagPtr->maxSolKey = (char **)NULL;

	return TCL_ERROR;
    }

    for(i=0; i < itemPtr->period; i++) {
	for(j=0; j < itemPtr->period; j++) {
	    swagPtr->key[i][j] = swagPtr->maxSolKey[i][j];
	}
	ckfree((char *)(swagPtr->maxSolKey[i]));
    }
    ckfree((char *)swagPtr->maxSolKey);
    swagPtr->maxSolKey = (char **)NULL;

    return TCL_OK;
}

static int
RecSolveSwagman(Tcl_Interp *interp, CipherItem *itemPtr, int depth) {
    SwagmanSolveItem solveItem;

    solveItem.itemPtr = itemPtr;
    solveItem.depth = depth;

    if (_internalDoPermCmd((ClientData)(&solveItem),
	    interp,
	    itemPtr->period,
	    SwagmanSolveValue) != TCL_OK) {
	return TCL_ERROR;
    }

    return TCL_OK;
}

static int
SwagmanSolveValue(Tcl_Interp *interp, ClientData clientData, int *key, int length)
{
    SwagmanSolveItem *solveItem = (SwagmanSolveItem *)clientData;
    SwagmanItem *swagPtr = (SwagmanItem *)solveItem->itemPtr;
    CipherItem *itemPtr = solveItem->itemPtr;
    int depth = solveItem->depth;
    int i, j;

    /*
     * Add one to the generated key since our swagman keys use
     * zero to designate an empty space.
     */

    for(i=0; i < length; i++) {
	swagPtr->key[depth][i] = key[i]+1;
    }

    for(i=0; i < length; i++) {
	for(j=0; j < depth; j++) {
	    if (swagPtr->key[depth][i] == swagPtr->key[j][i]) {
		return TCL_OK;
	    }
	}
    }

    depth++;

    if (depth >= itemPtr->period) {
	char *pt = (char *)NULL;
	Tcl_DString dsPtr;
	double val;

	pt = GetSwagman(interp, itemPtr);
	itemPtr->curIteration++;

	if (pt && itemPtr->stepInterval && itemPtr->stepCommand
		&& (itemPtr->curIteration%itemPtr->stepInterval == 0)) {
	    int j;
	    char temp_str[128];

	    Tcl_DStringInit(&dsPtr);

	    Tcl_DStringAppendElement(&dsPtr, itemPtr->stepCommand);

	    sprintf(temp_str, "%ld", itemPtr->curIteration);
	    Tcl_DStringAppendElement(&dsPtr, temp_str);

	    Tcl_DStringStartSublist(&dsPtr);
	    for(i=0; i < itemPtr->period; i++) {
		for(j=0; j < itemPtr->period; j++) {
		    temp_str[j] = swagPtr->key[i][j] + '0';
		}
		temp_str[j] = '\0';
		Tcl_DStringAppendElement(&dsPtr, temp_str);
	    }
	    Tcl_DStringEndSublist(&dsPtr);

	    Tcl_DStringAppendElement(&dsPtr, pt);

	    if (Tcl_Eval(interp, Tcl_DStringValue(&dsPtr)) != TCL_OK) {
		ckfree(pt);
		Tcl_ResetResult(interp);
		Tcl_AppendResult(interp, "Bad command usage:  ",
			Tcl_DStringValue(&dsPtr), (char *)NULL);
		Tcl_DStringFree(&dsPtr);
		return TCL_ERROR;
	    }
	    Tcl_DStringFree(&dsPtr);
	}

	if (pt) {
	    if (DefaultScoreValue(interp, pt, &val)
                    != TCL_OK) {
		return TCL_ERROR;
	    }

	    if (val > swagPtr->maxSolVal) {
		int j;
		char temp_str[128];
		
		swagPtr->maxSolVal = val;

		Tcl_DStringInit(&dsPtr);

		Tcl_DStringAppendElement(&dsPtr, itemPtr->bestFitCommand);

		sprintf(temp_str, "%ld", itemPtr->curIteration);
		Tcl_DStringAppendElement(&dsPtr, temp_str);

		Tcl_DStringStartSublist(&dsPtr);
		for(i=0; i < itemPtr->period; i++) {
		    for(j=0; j < itemPtr->period; j++) {
			temp_str[j] = swagPtr->key[i][j] + '0';
			swagPtr->maxSolKey[i][j] = swagPtr->key[i][j];
		    }
		    temp_str[j] = '\0';
		    Tcl_DStringAppendElement(&dsPtr, temp_str);
		}
		Tcl_DStringEndSublist(&dsPtr);

		sprintf(temp_str, "%g", val);
		Tcl_DStringAppendElement(&dsPtr, temp_str);

		Tcl_DStringAppendElement(&dsPtr, pt);

		if (Tcl_Eval(interp, Tcl_DStringValue(&dsPtr)) != TCL_OK) {
		    ckfree(pt);
		    Tcl_ResetResult(interp);
		    Tcl_AppendResult(interp, "Bad command usage:  ",
			    Tcl_DStringValue(&dsPtr), (char *)NULL);
		    Tcl_DStringFree(&dsPtr);
		    return TCL_ERROR;
		}
		Tcl_DStringFree(&dsPtr);
	    }
	}

	if (pt) {
	    ckfree(pt);
	}
    } else {
	/*
	 * depth was already incremented above
	 */
	if (RecSolveSwagman(interp, itemPtr, depth) != TCL_OK) {
	    return TCL_ERROR;
	}
    }

    return TCL_OK;
}

static int
SwagmanLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, const char *tip, const char *start)
{
    Tcl_SetResult(interp,
	    "No locate tip function defined for Swagman ciphers.",
	    TCL_VOLATILE);
    return TCL_ERROR;
}

static char *
SwagmanCtToBlock(Tcl_Interp *interp, CipherItem *itemPtr)
{
    char *word=(char *)NULL;
    int row, col, k;
    Tcl_DString dsPtr;

    word = (char *)ckalloc(sizeof(char) * (itemPtr->period+1));
    if (!word) {
	Tcl_SetResult(interp, "Error mallocing space for blocks\n", TCL_VOLATILE);
	return (char *)NULL;
    }

    Tcl_DStringInit(&dsPtr);

    for(row=0; row < itemPtr->period; row++) {
	col=0;
	Tcl_DStringStartSublist(&dsPtr);
	while(col < itemPtr->length/itemPtr->period) {
	    for(k=0; k < itemPtr->period && col<itemPtr->length/itemPtr->period; k++, col++) {
		word[k] = itemPtr->ciphertext[row+col*itemPtr->period];

		/*
		if (!swagPtr->key[row][k]) {
		    word[k] -= ' ';
		}
		*/
	    }
	    word[k] = '\0';
	    Tcl_DStringAppendElement(&dsPtr, word);
	}
	Tcl_DStringEndSublist(&dsPtr);
    }

    ckfree(word);

    word = (char *)ckalloc(sizeof(char) * (Tcl_DStringLength(&dsPtr) + 1));
    strcpy(word, Tcl_DStringValue(&dsPtr));

    return word;
}

static char *
SwagmanPtToBlock(Tcl_Interp *interp, CipherItem *itemPtr)
{
    char *word=(char *)NULL;
    char *pt=(char *)NULL;
    int row, col, k;
    Tcl_DString dsPtr;

    word = (char *)ckalloc(sizeof(char) * (itemPtr->period+1));

    if (!word) {
	Tcl_SetResult(interp,
		"Error mallocing space for blocks\n",
		TCL_VOLATILE);
	return (char *)NULL;
    }

    pt = GetSwagman(interp, itemPtr);
    if (!pt) {
	return (char *)NULL;
    }

    Tcl_DStringInit(&dsPtr);

    for(row=0; row < itemPtr->period; row++) {
	col=0;
	Tcl_DStringStartSublist(&dsPtr);
	while(col < itemPtr->length/itemPtr->period) {
	    for(k=0; k < itemPtr->period && col<itemPtr->length/itemPtr->period; k++, col++) {
		word[k] = pt[row*itemPtr->length/itemPtr->period+col];
	    }
	    word[k] = '\0';
	    Tcl_DStringAppendElement(&dsPtr, word);
	}
	Tcl_DStringEndSublist(&dsPtr);
    }

    ckfree(word);
    ckfree(pt);

    word = (char *)ckalloc(sizeof(char) * (Tcl_DStringLength(&dsPtr) + 1));
    strcpy(word, Tcl_DStringValue(&dsPtr));

    return word;
}

static int
SwagmanSwapRows	(Tcl_Interp *interp, CipherItem *itemPtr, int row1, int row2)
{
    SwagmanItem *swagPtr = (SwagmanItem *)itemPtr;
    int i, tempRow;

    if (itemPtr->period <= 0) {
	Tcl_SetResult(interp, "Can't do anything until a block width has been set",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (row1 < 1 || row2 < 1 || row1 > itemPtr->period || row2 > itemPtr->period) {
	Tcl_SetResult(interp, "Invalid row in swagman swap", TCL_VOLATILE);
	return TCL_ERROR;
    }

    row1--;
    row2--;

    for(i=0; i < itemPtr->period; i++) {
	tempRow = swagPtr->key[row1][i];
	swagPtr->key[row1][i] = swagPtr->key[row2][i];
	swagPtr->key[row2][i] = tempRow;
    }

    return TCL_OK;
}

int
SwagmanCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    SwagmanItem *swagPtr = (SwagmanItem *)clientData;
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
	    sprintf(temp_str, "%d", swagPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", itemPtr->period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ctblock", 8) == 0) {
	    if (!swagPtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_VOLATILE);
	    } else {
		char *t = SwagmanCtToBlock(interp, itemPtr);
		if (t) {
		    Tcl_SetResult(interp, t, TCL_VOLATILE);
		    ckfree(t);
		} else {
		    return TCL_ERROR;
		}
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ptblock", 8) == 0) {
	    if (!swagPtr->header.ciphertext) {
		Tcl_SetResult(interp, "No Ciphertext", TCL_VOLATILE);
	    } else {
		char *t = SwagmanPtToBlock(interp, itemPtr);
		if (t) {
		    Tcl_SetResult(interp, t, TCL_VOLATILE);
		    ckfree(t);
		} else {
		    Tcl_SetResult(interp, "", TCL_VOLATILE);
		}
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!swagPtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_VOLATILE);
	    } else {
		Tcl_SetResult(interp, swagPtr->header.ciphertext, TCL_VOLATILE);
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
	    if (! itemPtr->period) {
		Tcl_ResetResult(interp);
		return TCL_OK;
	    }

	    for(i=0; i < itemPtr->period; i++) {
		int j;
		for(j=0; j < itemPtr->period; j++) {
		    if (swagPtr->key[i][j]) {
			temp_str[j+i*itemPtr->period] =
				swagPtr->key[i][j] + '0';
		    } else {
			temp_str[j+i*itemPtr->period] = ' ';
		    }
		}
	    }
	    temp_str[itemPtr->period*itemPtr->period] = '\0';
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);

	    return TCL_OK;
	} else if (strncmp(argv[1], "-type", 5) == 0) {
	    Tcl_SetResult(interp, itemPtr->typePtr->type, TCL_STATIC);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-width", 6) == 0) {
	    sprintf(temp_str, "%d", itemPtr->period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-height", 7) == 0) {
	    sprintf(temp_str, "%d", itemPtr->period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
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
	    if (strncmp(*argv, "-stepinterval", 12) == 0) {
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
	    } else if (strncmp(*argv, "-period", 7) == 0) {
		int period;

		if (sscanf(argv[1], "%d", &period) != 1) {
		    Tcl_SetResult(interp, "Invalid width setting.",
			    TCL_VOLATILE);
		    return TCL_ERROR;
		}
		if (period < 0 || period > itemPtr->length || (itemPtr->length && itemPtr->length%period != 0)) {
		    Tcl_SetResult(interp, "Invalid width setting.",
			    TCL_VOLATILE);
		    return TCL_ERROR;
		}

		SwagmanInitKey(itemPtr, period);
		Tcl_SetObjResult(interp, Tcl_NewStringObj(argv[1], -1));
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
	int row1, row2;

	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd,
		    " swap row1 row2", (char *)NULL);
	    return TCL_ERROR;
	} else {
	    if (sscanf(argv[1], "%d", &row1) != 1) {
		Tcl_SetResult(interp,
			"Invalid row value.  Value must be between 1 and block width.",
			TCL_VOLATILE);
		return TCL_ERROR;
	    }
	    if (sscanf(argv[2], "%d", &row2) != 1) {
		Tcl_SetResult(interp,
			"Invalid row value.  Value must be between 1 and block width.",
			TCL_VOLATILE);
		return TCL_ERROR;
	    }
	}

	return SwagmanSwapRows(interp, itemPtr, row1, row2);
    } else if (**argv == 'l' && (strncmp(*argv, "locate", 3) == 0)) {
	Tcl_SetResult(interp,
		"No locate tip function defined for swagman ciphers.",
		TCL_VOLATILE);
	return TCL_ERROR;
    } else if (**argv == 's' && (strncmp(*argv, "substitute", 3) == 0)) {
	int offset;

	if (argc == 3) {
	    offset = 0;
	} else if (argc != 4) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd,
		    " substitute row col ?val?", (char *)NULL);
	    return TCL_ERROR;
	} else {
	    if (sscanf(argv[3], "%d", &offset) != 1) {
		Tcl_SetResult(interp,
			"Invalid key value.  Value must be between 1 and block width.",
			TCL_VOLATILE);
		return TCL_ERROR;
	    }
	}

	return (itemPtr->typePtr->subProc)(interp, itemPtr, argv[1], argv[2], offset);
    } else if (**argv == 'r' && (strncmp(*argv, "restore", 7) == 0)) {
	if (argc != 2 && argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd,
		    " restore key ?junk?", (char *)NULL);
	    return TCL_ERROR;
	}
	return (itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1],
		(char *)NULL);
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
			" substitute row col ?val?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" swap row1 row2", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" undo row col", (char *)NULL);
	return TCL_ERROR;
    }
}
