/*
 * nicodemus.c --
 *
 *	This file implements the nicodemus cipher type.
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
#include <score.h>
#include <digram.h>
#include <perm.h>
#include <vigTypes.h>

#include <cipherDebug.h>

#define VIG_TYPE 0
#define VAR_TYPE 1
#define BEA_TYPE 2
#define GRN_TYPE 3
#define PRT_TYPE 4

static int  CreateNicodemus	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
void DeleteNicodemus		_ANSI_ARGS_((ClientData));
static char *GetNicodemus	_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetNicodemus	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestoreNicodemus	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolveNicodemus	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
int NicodemusCmd		_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));
static int NicodemusUndo	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int NicodemusSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int NicodemusLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static void NicodemusInitKey	_ANSI_ARGS_((CipherItem *, int));
static int NicodemusSwapColumns	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
	    			int, int));
static int NicodemusFitColumn	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
	    			int));
int NicodemusCheckValue		_ANSI_ARGS_((Tcl_Interp *, ClientData,
				int *, int));
static int EncodeNicodemus	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static char *NicodemusTransform	_ANSI_ARGS_((CipherItem *, const char *, int));

typedef struct NicodemusItem {
    CipherItem header;

    /*
     * Storage for the plaintext so that we don't have to reallocate
     * memory for every call to GetNicodemus.
     */
    char *pt;

    char *key;
    /*
     * order[a] = b means that the column that was originally in position
     * 'a' is now in position 'b', or the column labelled 'a' is now in
     * position 'b'.
     */
    int  *order;
    /*
     * revOrder[a] = b means that the column that was originally in position
     * 'b' is now in position 'a', or equivalently, the column labelled 'b'
     * is now in position 'a'.
     */
    int  *revOrder;

    /*
     * This stores the starting positions for the columns in the final
     * block.  The starting positions are relative to the first character
     * in this final block, not to the start of the ciphertext.
     */
    int  *startPos;

    int  *colLength;
    int  maxColLen;

    char encodingType;

    double  maxVal;
    char *maxKey;
    int  *maxOrder;
    char *fixedKey;
} NicodemusItem;

CipherType NicodemusType = {
    "nicodemus",
    ATOZ,
    sizeof(NicodemusItem),
    CreateNicodemus,	/* create proc */
    DeleteNicodemus,	/* delete proc */
    NicodemusCmd,	/* cipher command proc */
    GetNicodemus,	/* get plaintext proc */
    SetNicodemus,	/* show ciphertext proc */
    SolveNicodemus,/* solve cipher proc */
    RestoreNicodemus,	/* restore proc */
    NicodemusLocateTip,	/* locate proc */
    NicodemusSubstitute,/* sub proc */
    NicodemusUndo,	/* undo proc */
    EncodeNicodemus,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

static int
CreateNicodemus(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    NicodemusItem *nicPtr = (NicodemusItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    nicPtr->header.period = 0;
    nicPtr->key = (char *)NULL;
    nicPtr->maxKey = (char *)NULL;
    nicPtr->maxOrder = (int *)NULL;
    nicPtr->fixedKey = (char *)NULL;
    nicPtr->order = (int *)NULL;
    nicPtr->revOrder = (int *)NULL;
    nicPtr->maxVal = 0.0;
    nicPtr->encodingType = VIG_TYPE;
    nicPtr->maxColLen = 0;
    nicPtr->colLength = (int *)NULL;
    nicPtr->startPos = (int *)NULL;
    nicPtr->pt = (char *)NULL;

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, NicodemusCmd, itemPtr,
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
DeleteNicodemus(ClientData clientData)
{
    NicodemusItem *nicPtr = (NicodemusItem *)clientData;

    if (nicPtr->key) {
	ckfree(nicPtr->key);
    }

    if (nicPtr->fixedKey) {
	ckfree(nicPtr->fixedKey);
    }

    if (nicPtr->order) {
	ckfree((char *)(nicPtr->order));
    }

    if (nicPtr->revOrder) {
	ckfree((char *)(nicPtr->revOrder));
    }

    if (nicPtr->colLength) {
	ckfree((char *)(nicPtr->colLength));
    }

    if (nicPtr->startPos) {
	ckfree((char *)(nicPtr->startPos));
    }

    if (nicPtr->pt) {
	ckfree((char *)(nicPtr->pt));
    }

    DeleteCipher(clientData);
}

static int
SetNicodemus(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
{
    NicodemusItem *nicPtr = (NicodemusItem *)itemPtr;
    char	*c;
    int		valid = TCL_OK,
    		length=0;

    length = CountValidChars(itemPtr, ctext);
    c = ExtractValidChars(itemPtr, ctext);
    if (c == NULL) {
	Tcl_SetResult(interp, "Error mallocing memory for new cipher",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (nicPtr->pt) {
	ckfree((char *)(nicPtr->pt));
    }
    nicPtr->pt = (char *)ckalloc(sizeof(char) * length + 1);

    valid = TCL_OK;

    if (valid==TCL_OK) {
	itemPtr->length = length;
	if (itemPtr->ciphertext) {
	    ckfree(itemPtr->ciphertext);
	}
	itemPtr->ciphertext = c;

	itemPtr->length = length;

	Tcl_SetResult(interp, itemPtr->ciphertext, TCL_STATIC);

	if (itemPtr->period) {
	    NicodemusInitKey(itemPtr, itemPtr->period);
	}
    }

    return valid;
}

static int
NicodemusUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int offset)
{
    NicodemusItem *nicPtr = (NicodemusItem *)itemPtr;
    int		i;

    for(i=0; i < itemPtr->period; i++) {
	switch (nicPtr->encodingType) {
	    case VIG_TYPE: nicPtr->key[i] = VigenereGetKey('a', 'a');
		      break;
	    case VAR_TYPE: nicPtr->key[i] = VariantGetKey('a', 'a');
		      break;
	    case BEA_TYPE: nicPtr->key[i] = BeaufortGetKey('a', 'a');
		      break;
	    case PRT_TYPE: nicPtr->key[i] = PortaGetKey('a', 'a');
		      break;
	    default:
		      Tcl_SetResult(interp, "Invalid encoding type",
			      TCL_STATIC);
		      return BAD_SUB;
	}
	nicPtr->order[i] = i;
	nicPtr->revOrder[i] = i;
    }

    return TCL_OK;
}

static int
NicodemusSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, const char *pt, int offset)
{
    NicodemusItem *nicPtr = (NicodemusItem *)itemPtr;
    char	keyLetter;

    if (itemPtr->period == 0) {
	Tcl_SetResult(interp, "Period must be set before performing substitutions", TCL_STATIC);
	return BAD_SUB;
    }

    if (*ct < 'a' || *ct > 'z' || *pt < 'a' || *pt > 'z') {
	Tcl_SetResult(interp, "Invalid character", TCL_STATIC);
	return BAD_SUB;
    }

    if (offset < 0 || offset >= itemPtr->period) {
	Tcl_SetResult(interp, "Invalid offset.  Must be from 1 to period",
		TCL_STATIC);
	return BAD_SUB;
    }

    offset %= itemPtr->period;

    switch (nicPtr->encodingType) {
	case VIG_TYPE: keyLetter = VigenereGetKey(*ct, *pt);
		  break;
	case VAR_TYPE: keyLetter = VariantGetKey(*ct, *pt);
		  break;
	case BEA_TYPE: keyLetter = BeaufortGetKey(*ct, *pt);
		  break;
	case PRT_TYPE: keyLetter = PortaGetKey(*ct, *pt);
		  break;
	default:
		  Tcl_SetResult(interp, "Invalid encoding type", TCL_STATIC);
		  return BAD_SUB;
    }

    nicPtr->key[nicPtr->order[offset]] = keyLetter;

    Tcl_SetResult(interp, "", TCL_STATIC);
    return NEW_SUB;
}

static char *
GetNicodemus(Tcl_Interp *interp, CipherItem *itemPtr)
{
    if (itemPtr->length == 0) {
	Tcl_SetResult(interp, "Can't do anything until ciphertext has been set",
		TCL_STATIC);
	return (char *)NULL;
    }

    return NicodemusTransform(itemPtr, itemPtr->ciphertext, DECODE);
}

static char *
NicodemusTransform(CipherItem *itemPtr, const char *text, int mode) {
    NicodemusItem *nicPtr = (NicodemusItem *)itemPtr;
    int		i, col, row;
    char	pt;
    int		remainder,
    		blocksize;
    int		shift = 0;

    /*
     * Initialize the result string so that it's easier to detect bugs.
     */
    for (i=0; i < itemPtr->length; i++) {
	nicPtr->pt[i] = '_';
    }

    blocksize = itemPtr->period * 5;
    remainder = itemPtr->length % blocksize;

    nicPtr->startPos[nicPtr->order[0]] = 0;
    for (i=1; i < itemPtr->period; i++) {
	// Calculate the length of the previous column
	shift = remainder / itemPtr->period;
	if (remainder % itemPtr->period > nicPtr->order[i-1]) {
	    shift++;
	}
	nicPtr->startPos[nicPtr->order[i]] = nicPtr->startPos[nicPtr->order[i-1]] + shift;
    }
    /*
    for (i=0; i < itemPtr->period; i++) {
	fprintf(stdout, "startPos[%d] = %d\n", i, startPos[i]);
    }
    */

    for (i=0; i < itemPtr->length; i++) {
	int ctIndex = i;
	int ptIndex = i;

	/*
	 * We need to add a special case for the last set of rows which
	 * might not be in groups of 5.
	 */

	if (i + remainder < itemPtr->length) {
	    col = nicPtr->order[(i/5) % itemPtr->period];
	    row = i%5 + (i / blocksize) * 5;
	    /*
	    fprintf(stdout, "result[%d][%d] = %c\n", 
		    row, col, text[i]);
	    fflush(stdout);
	    */
	} else {
	    int index;

	    index = i % blocksize;
	    for (col=0; col < itemPtr->period && index >= nicPtr->startPos[nicPtr->order[col]]; col++);
	    col--;
	    col = nicPtr->order[col];
	    row = index - nicPtr->startPos[col] + (itemPtr->length / blocksize) * 5;
	    /*
	    fprintf(stdout, "remainder[%d][%d] = %c\n", 
		    row, col, text[i]);
	    fflush(stdout);
	    */
	}

	if (mode == DECODE) {
	    ptIndex = row*itemPtr->period + col;
	    ctIndex = i;
	} else {
	    ptIndex = i;
	    ctIndex = row*itemPtr->period + col;
	}

	if (ptIndex > itemPtr->length || ctIndex > itemPtr->length
		|| row < 0 || col < 0) {
	    fprintf(stderr, "char, row, col = %c, %d, %d\n", text[ctIndex], row, col);
	    fprintf(stderr, "Fatal indexing error! %s: line %d\n",
		    __FILE__, __LINE__);
	    abort();
	}

	switch (nicPtr->encodingType) {
	    case VIG_TYPE:
		if (mode == DECODE) {
		    pt = VigenereGetPt(nicPtr->key[col], text[ctIndex]);
		} else {
		    pt = VigenereGetCt(nicPtr->key[col], text[ctIndex]);
		}
		break;
	    case VAR_TYPE:
		if (mode == DECODE) {
		    pt = VariantGetPt(nicPtr->key[col], text[ctIndex]);
		} else {
		    pt = VariantGetCt(nicPtr->key[col], text[ctIndex]);
		}
		break;
	    case BEA_TYPE:
		if (mode == DECODE) {
		    pt = BeaufortGetPt(nicPtr->key[col], text[ctIndex]);
		} else {
		    pt = BeaufortGetCt(nicPtr->key[col], text[ctIndex]);
		}
		break;
	    case PRT_TYPE:
		if (mode == DECODE) {
		    pt = PortaGetPt(nicPtr->key[col], text[ctIndex]);
		} else {
		    pt = PortaGetCt(nicPtr->key[col], text[ctIndex]);
		}
		break;
	    default:
		abort();
	}
	/*
	fprintf(stdout, "conversion [%d][%d] %c (%c) = %c\n", 
		row, col, text[ctIndex],
		nicPtr->key[col], pt);
	fflush(stdout);
	*/
	if (!pt) {
	    pt = ' ';
	}

	nicPtr->pt[ptIndex] = pt;
    }

    nicPtr->pt[itemPtr->length] = '\0';

    return nicPtr->pt;
}

static int
RestoreNicodemus(Tcl_Interp *interp, CipherItem *itemPtr, const char *key, const char *order)
{
    NicodemusItem *nicPtr = (NicodemusItem *)itemPtr;
    int i;

    if (strlen(order) != itemPtr->period || strlen(key) != itemPtr->period) {
	Tcl_SetResult(interp,
		"Key and order must be the same length as the cipher period",
		TCL_STATIC);
	return TCL_ERROR;
    }

    for(i=0; i < itemPtr->period; i++) {
	if (order[i]-'a' < 0 || order[i]-'a' >= itemPtr->period) {
	    char temp_char[2];
	    temp_char[0] = order[i];
	    temp_char[1] = '\0';
	    Tcl_AppendResult(interp, "Invalid character in order:  '",
		    temp_char, "'", (char *)NULL);
	    return TCL_ERROR;
	}
	if (key[i] < 'a' || key[i] > 'z') {
	    char temp_char[2];
	    temp_char[0] = key[i];
	    temp_char[1] = '\0';
	    Tcl_AppendResult(interp, "Invalid character in key:  '",
		    temp_char, "'", (char *)NULL);
	    return TCL_ERROR;
	}
    }
    for(i=0; i < itemPtr->period; i++) {
	nicPtr->revOrder[i] = order[i]-'a';
	nicPtr->order[nicPtr->revOrder[i]] = i;
	nicPtr->key[i] = key[i];
    }

    return TCL_OK;
}

static int
SolveNicodemus(Tcl_Interp *interp, CipherItem *itemPtr, char *maxkey)
{
    NicodemusItem *nicPtr = (NicodemusItem *)itemPtr;
    int i;
    int	result;

    /*
     * Fit each column to find the best match against a standard english
     * distribution.
     */
    for(i=1; i <= itemPtr->period; i++) {
	NicodemusFitColumn(interp, itemPtr, i);
	nicPtr->fixedKey[i-1] = nicPtr->key[i-1];
    }

    /*
     * Now solve as an incomplete columnar.
     */

    if (nicPtr->maxKey) {
	ckfree(nicPtr->maxKey);
    }
    if (nicPtr->maxOrder) {
	ckfree((char *)(nicPtr->maxOrder));
    }
    nicPtr->maxKey = (char *)ckalloc(sizeof(char)*itemPtr->period);
    nicPtr->maxOrder = (int *)ckalloc(sizeof(int)*itemPtr->period);
    nicPtr->maxVal = 0.0;

    itemPtr->curIteration = 0;

    result = _internalDoPermCmd((ClientData)itemPtr, interp, itemPtr->period, NicodemusCheckValue);

    if (result == TCL_OK) {
	for(i=0; i < itemPtr->period; i++) {
	    nicPtr->key[i] = nicPtr->maxKey[i];
	    nicPtr->order[i] = nicPtr->maxOrder[i];
	    nicPtr->revOrder[nicPtr->order[i]] = i;
	}
    }

    ckfree(nicPtr->maxKey);
    ckfree((char *)(nicPtr->maxOrder));
    nicPtr->maxKey = (char *)NULL;
    nicPtr->maxOrder = (int *)NULL;

    if (result == TCL_OK) {
	Tcl_ResetResult(interp);
    }
    return result;
}

int
NicodemusCheckValue(Tcl_Interp *interp, ClientData clientData, int *key, int keylen)
{
    NicodemusItem *nicPtr = (NicodemusItem *)clientData;
    CipherItem *itemPtr = (CipherItem *)clientData;
    char	*pt = (char *)NULL;
    int		i;
    double	value;

    for(i=0; i < keylen; i++) {
	nicPtr->key[i] = nicPtr->fixedKey[key[i]];
	nicPtr->revOrder[i] = key[i];
	nicPtr->order[nicPtr->revOrder[i]] = i;
    }
    
    pt = GetNicodemus(interp, (CipherItem *)clientData);

    if (pt) {
	Tcl_DString dsPtr;
	char temp_str[128];
	if (DefaultScoreValue(interp, pt, &value) != TCL_OK) {
	    return TCL_ERROR;
	}
	itemPtr->curIteration++;

	if (value > nicPtr->maxVal) {
	    nicPtr->maxVal = value;
	    for(i=0; i < keylen; i++) {
		nicPtr->maxKey[i] = nicPtr->key[i];
		nicPtr->maxOrder[i] = nicPtr->order[i];
	    }

	    if (itemPtr->bestFitCommand) {
		Tcl_DStringInit(&dsPtr);
		Tcl_DStringAppendElement(&dsPtr, itemPtr->bestFitCommand);

		sprintf(temp_str, "%ld", itemPtr->curIteration);
		Tcl_DStringAppendElement(&dsPtr, temp_str);

		Tcl_DStringStartSublist(&dsPtr);

		for(i=0; i < itemPtr->period; i++) {
		    temp_str[i] = nicPtr->key[i];
		}
		temp_str[i] = '\0';
		Tcl_DStringAppendElement(&dsPtr, temp_str);

		for(i=0; i < itemPtr->period; i++) {
		    temp_str[i] = nicPtr->revOrder[i] + 'a';
		}
		temp_str[i] = '\0';
		Tcl_DStringAppendElement(&dsPtr, temp_str);

		Tcl_DStringEndSublist(&dsPtr);

		sprintf(temp_str, "%g", value);
		Tcl_DStringAppendElement(&dsPtr, temp_str);

		Tcl_DStringAppendElement(&dsPtr, pt);

		if (Tcl_Eval(interp, Tcl_DStringValue(&dsPtr)) != TCL_OK) {
		    ckfree(pt);
		    Tcl_DStringFree(&dsPtr);
		    return TCL_ERROR;
		}
		Tcl_DStringFree(&dsPtr);
	    }
	}

	if (itemPtr->stepInterval && itemPtr->curIteration % itemPtr->stepInterval == 0 && itemPtr->stepCommand && pt) {
	    char temp_str[128];

	    Tcl_DStringInit(&dsPtr);

	    Tcl_DStringAppendElement(&dsPtr, itemPtr->stepCommand);

	    sprintf(temp_str, "%ld", itemPtr->curIteration);
	    Tcl_DStringAppendElement(&dsPtr, temp_str);

	    Tcl_DStringStartSublist(&dsPtr);

	    for(i=0; i < itemPtr->period; i++) {
		temp_str[i] = nicPtr->key[i];
	    }
	    temp_str[i] = '\0';
	    Tcl_DStringAppendElement(&dsPtr, temp_str);

	    for(i=0; i < itemPtr->period; i++) {
		temp_str[i] = nicPtr->revOrder[i] + 'a';
	    }
	    temp_str[i] = '\0';
	    Tcl_DStringAppendElement(&dsPtr, temp_str);

	    Tcl_DStringEndSublist(&dsPtr);

	    Tcl_DStringAppendElement(&dsPtr, pt);

	    if (Tcl_Eval(interp, Tcl_DStringValue(&dsPtr)) != TCL_OK) {
		ckfree(pt);
		Tcl_DStringFree(&dsPtr);
		return TCL_ERROR;
	    }
	    Tcl_DStringFree(&dsPtr);
	}
    }

    return TCL_OK;
}

static void
NicodemusInitKey(CipherItem *itemPtr, int period)
{
    NicodemusItem *nicPtr = (NicodemusItem *)itemPtr;
    int		i;

    if (nicPtr->key) {
	ckfree(nicPtr->key);
    }

    if (nicPtr->fixedKey) {
	ckfree(nicPtr->fixedKey);
    }

    if (nicPtr->order) {
	ckfree((char *)(nicPtr->order));
    }

    if (nicPtr->revOrder) {
	ckfree((char *)(nicPtr->revOrder));
    }

    if (nicPtr->colLength) {
	ckfree((char *)(nicPtr->colLength));
    }

    if (nicPtr->startPos) {
	ckfree((char *)(nicPtr->startPos));
    }

    nicPtr->key = (char *)NULL;
    nicPtr->fixedKey = (char *)NULL;
    nicPtr->order = (int *)NULL;
    nicPtr->revOrder = (int *)NULL;
    nicPtr->colLength = (int *)NULL;
    nicPtr->startPos = (int *)NULL;
    itemPtr->period = period;

    if (period) {
	nicPtr->key=ckalloc(sizeof(char)*period+1);
	nicPtr->fixedKey=ckalloc(sizeof(char)*period+1);
	nicPtr->order=(int *)ckalloc(sizeof(int)*(period+1));
	nicPtr->revOrder=(int *)ckalloc(sizeof(int)*(period+1));
	nicPtr->colLength=(int *)ckalloc(sizeof(int)*(period+1));
	nicPtr->startPos=(int *)ckalloc(sizeof(int)*(period+1));
	for(i=0; i < itemPtr->period; i++) {
	    switch (nicPtr->encodingType) {
		case VIG_TYPE: nicPtr->key[i] = VigenereGetKey('a', 'a');
			  break;
		case VAR_TYPE: nicPtr->key[i] = VariantGetKey('a', 'a');
			  break;
		case BEA_TYPE: nicPtr->key[i] = BeaufortGetKey('a', 'a');
			  break;
		case PRT_TYPE: nicPtr->key[i] = PortaGetKey('a', 'a');
			  break;
		default:
			  abort();
	    }
	    nicPtr->order[i] = i;
	    nicPtr->revOrder[i] = i;
	    nicPtr->maxColLen =
		    (itemPtr->length%period == 0)?(itemPtr->length / period):(itemPtr->length/period + 1);
	    if ((unsigned int)(period*(nicPtr->maxColLen-1)+i) < itemPtr->length) {
		nicPtr->colLength[i] = nicPtr->maxColLen;
	    } else {
		nicPtr->colLength[i] = nicPtr->maxColLen - 1;
	    }

	    /*
	    if (i == 0) {
		nicPtr->startPos[i] = 0;
	    } else {
		int nblocks = itemPtr->length / (itemPtr->period * 5);
		nicPtr->remainder[i] = nicPtr->startPos[i-1] + nicPtr->colLength[i-1] - nblocks * 5;
	    }
	    */
	}
	nicPtr->key[period]='\0';
	nicPtr->order[period]=0;
    }
}

/*
 * We probably won't need this.
 */

static int
NicodemusLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, const char *tip, const char *start)
{
    Tcl_SetResult(interp, "No locate tip function defined for nicodemus ciphers.",
	    TCL_STATIC);
    return TCL_ERROR;
}

static int
NicodemusFitColumn(Tcl_Interp *interp, CipherItem *itemPtr, int col)
{
    NicodemusItem *nicPtr = (NicodemusItem *)itemPtr;
    int i;
    char result[2];
    int value=0;
    int maxValue=0;
    int maxKeyLetter='a';
    int hist[26];
    char *pt;


    if (itemPtr->length == 0) {
	Tcl_SetResult(interp,
		"Can't do anything until the ciphertext has been set",
		TCL_STATIC);
	return TCL_ERROR;
    }

    col --;
    if (col < 0 || col >= itemPtr->period) {
	Tcl_SetResult(interp, "Bad column value", TCL_STATIC);
	return TCL_ERROR;
    }

    /*
     * Big cheat here.  Get the plaintext from GetNicodemus() and then
     * take every n'th letter.
     */

    for (nicPtr->key[col]='a'; nicPtr->key[col] <= 'z'; nicPtr->key[col]++) {
	pt = GetNicodemus(interp, itemPtr);
	if (!pt) {
	    Tcl_SetResult(interp,
		    "Unknown error getting plaintext in NicodemusFitColumn()",
		    TCL_STATIC);
	    return TCL_ERROR;
	}
	
	for(i=0; i < 26; i++) {
	    hist[i] = 0;
	}

	for(i=col; i < itemPtr->length; i++) {
	    hist[pt[i] - 'a']++;
	}

	value = alphHistFit(hist);
	if (value > maxValue) {
	    maxValue = value;
	    maxKeyLetter = nicPtr->key[col];
	}
    }

    nicPtr->key[col] = maxKeyLetter;
    result[0] = maxKeyLetter;
    result[1] = '\0';

    Tcl_SetResult(interp, result, TCL_VOLATILE);

    return TCL_OK;
}

static int
NicodemusSwapColumns(Tcl_Interp *interp, CipherItem *itemPtr, int col1, int col2)
{
    NicodemusItem *nicPtr = (NicodemusItem *)itemPtr;
    char t;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp,
		"Can't do anything until the ciphertext has been set",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (col1 < 1 ||
	col2 < 1 ||
	col1 > itemPtr->period ||
	col2 > itemPtr->period ||
	col1 == col2) {

	Tcl_SetResult(interp, "Bad column index", TCL_STATIC);
	return TCL_ERROR;
    }

    /*
    printf("Swapping columns %d and %d\n", col1, col2);
    */
    col1--, col2--;

    /*
    for(i=0; i < itemPtr->period && nicPtr->order[i] != col1; i++);
    col1 = i;
    for(i=0; i < itemPtr->period && nicPtr->order[i] != col2; i++);
    col2 = i;
    */

    if (col1 == itemPtr->period || col2 == itemPtr->period) {
	fprintf(stderr, "Columns not found!\n");
	abort();
    }

    t = nicPtr->order[col1];
    nicPtr->order[col1] = nicPtr->order[col2];
    nicPtr->order[col2] = t;

    nicPtr->revOrder[nicPtr->order[col1]] = col1;
    nicPtr->revOrder[nicPtr->order[col2]] = col2;

    t = nicPtr->key[nicPtr->order[col1]];
    nicPtr->key[nicPtr->order[col1]] = nicPtr->key[nicPtr->order[col2]];
    nicPtr->key[nicPtr->order[col2]] = t;

    /*
    printf("order = ");
    for(i=0; i < itemPtr->period; i++) {
	printf("%d ", nicPtr->order[i]);
    }
    printf("\n");
    printf("key   = ");
    for(i=0; i < itemPtr->period; i++) {
	printf("%d ", nicPtr->key[i]);
    }
    printf("\n\n");
    */

    return TCL_OK;
}

static int
NicodemusSetPeriod(Tcl_Interp *interp, CipherItem *itemPtr, int period)
{
    char result[16];

    sprintf(result, "%d", period);

    if (period < 1) {
	Tcl_AppendResult(interp, "Bad period for cipher:  ",
		result, (char *)NULL);
	return TCL_ERROR;
    }

    if (itemPtr->period == period) {
	Tcl_SetResult(interp, result, TCL_VOLATILE);
	return TCL_OK;
    }

    NicodemusInitKey(itemPtr, period);

    itemPtr->period = period;

    return TCL_OK;
}

int
NicodemusCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    NicodemusItem *nicPtr = (NicodemusItem *)clientData;
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
	    sprintf(temp_str, "%d", itemPtr->length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", itemPtr->period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-plaintext", 9) == 0 ||
		   strncmp(argv[1], "-ptext", 3) == 0) {
	    tPtr = (itemPtr->typePtr->decipherProc)(interp, itemPtr);

	    /*
	     * This will happen if the cipher hadn't been completely
	     * initialized before attempting to get the plaintext.  For example,
	     * if the period had not been set.
	     */

	    if (!tPtr) {
		return TCL_ERROR;
	    }

	    Tcl_SetResult(interp, tPtr, TCL_VOLATILE);

	    return TCL_OK;
	} else if (strncmp(argv[1], "-keyword", 8) == 0) {
	    for(i=0; i < itemPtr->period; i++) {
		temp_str[i] = nicPtr->key[i];
	    }
	    temp_str[itemPtr->period] = '\0';
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);

	    return TCL_OK;
	} else if (strncmp(argv[1], "-key", 4) == 0) {
	    for(i=0; i < itemPtr->period; i++) {
		temp_str[i] = nicPtr->key[i];
	    }
	    temp_str[itemPtr->period] = '\0';

	    Tcl_AppendElement(interp, temp_str);

	    for(i=0; i < itemPtr->period; i++) {
		temp_str[i] = nicPtr->revOrder[i] + 'a';
		/*
		sprintf(temp_str+i, "%d", nicPtr->revOrder[i]+1);
		*/
	    }
	    temp_str[itemPtr->period] = '\0';

	    Tcl_AppendElement(interp, temp_str);

	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!itemPtr->ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_STATIC);
	    } else {
		Tcl_SetResult(interp, itemPtr->ciphertext, TCL_VOLATILE);
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-type", 5) == 0) {
	    Tcl_SetResult(interp, itemPtr->typePtr->type, TCL_STATIC);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-encoding", 2) == 0) {
	    switch (nicPtr->encodingType) {
		case VIG_TYPE: Tcl_SetResult(interp, "vigenere", TCL_STATIC);
			       break;
		case VAR_TYPE: Tcl_SetResult(interp, "variant", TCL_STATIC);
			       break;
		case BEA_TYPE: Tcl_SetResult(interp, "beaufort", TCL_STATIC);
			       break;
		case PRT_TYPE: Tcl_SetResult(interp, "porta", TCL_STATIC);
			       break;
		default: Tcl_SetResult(interp, "", TCL_STATIC);
			       break;
	    }
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
	    if (strncmp(*argv, "-ciphertext", 10) == 0 ||
		strncmp(*argv, "-ctext", 3) == 0) {
		if ((itemPtr->typePtr->setctProc)(interp, itemPtr, argv[1]) != TCL_OK) {
		    return TCL_ERROR;
		}
	    } else if (strncmp(*argv, "-period", 7) == 0) {

		if (sscanf(argv[1], "%d", &i) != 1) {
		    Tcl_AppendResult(interp, "Bad period.  Integer expected:  ",
			    argv[1], (char *)NULL);
		    return TCL_ERROR;
		}
		if (NicodemusSetPeriod(interp, itemPtr, i) != TCL_OK) {
		    return TCL_ERROR;
		}
	    } else if (strncmp(*argv, "-encoding", 2) == 0) {
		if (strcmp(argv[1], "vigenere") == 0) {
		    nicPtr->encodingType = VIG_TYPE;
		} else if (strcmp(argv[1], "variant") == 0) {
		    nicPtr->encodingType = VAR_TYPE;
		} else if (strcmp(argv[1], "beaufort") == 0) {
		    nicPtr->encodingType = BEA_TYPE;
		} else if (strcmp(argv[1], "porta") == 0) {
		    nicPtr->encodingType = PRT_TYPE;
		} else {
		    Tcl_AppendResult(interp, "Unknown encoding type '", argv[1],
			    "'.  Must be one of vigenere, variant, beaufort, porta",
			    (char *)NULL);
		    return TCL_ERROR;
		}
		Tcl_SetObjResult(interp, Tcl_NewStringObj(argv[1], -1));
	    } else if (strncmp(*argv, "-language", 8) == 0) {
		itemPtr->language = cipherSelectLanguage(argv[1]);
		Tcl_SetResult(interp, cipherGetLanguage(itemPtr->language),
			TCL_VOLATILE);
	    } else if (strncmp(*argv, "-stepinterval", 12) == 0) {
		if (argc < 2) {
		    Tcl_AppendResult(interp, "Usage:  ", cmd, " configure -stepinterval val", (char *)NULL);
		    return TCL_ERROR;
		}

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
	    } else {
		sprintf(temp_str, "Unknown option %s", *argv);
		Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
		return TCL_ERROR;
	    }
	    argc-=2, argv+=2;
	}
	return TCL_OK;
    } else if (**argv == 'r' && (strncmp(*argv, "restore", 2) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " restore key order", 
		    (char *)NULL);
	    return TCL_ERROR;
	}
	if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1], argv[2]) == TCL_ERROR) {
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
	int valid;
	if (argc != 4) {
	    Tcl_AppendResult(interp,
		    "Usage:  ", cmd,
		    " substitute ct pt offset",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	if (strlen(argv[1]) != strlen(argv[2])) {
	    Tcl_SetResult(interp,
		    "ciphertext and plaintext must be the same length",
		    TCL_STATIC);
	    return TCL_ERROR;
	}
	if (sscanf(argv[3], "%d", &i) != 1) {
	    Tcl_AppendResult(interp, "Bad column number:  ", 
		    argv[3], (char *)NULL);
	    return TCL_ERROR;
	}
	
	/*
	 * Users start with column 1, C starts with column 0
	 */

	i = i - 1;

	valid = (itemPtr->typePtr->subProc)(interp, itemPtr, argv[1], argv[2],
		i);
	if (valid == BAD_SUB) {
	    return TCL_ERROR;
	} else {
	    return TCL_OK;
	}
    } else if (**argv == 'f' && (strncmp(*argv, "fit", 3) == 0)) {
	int col;
	if (argc != 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " fit column",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	if (sscanf(argv[1], "%d", &col) != 1) {
	    Tcl_AppendResult(interp, "Invalid column setting:  ", 
		    argv[1], (char *)NULL, TCL_VOLATILE);
	    return TCL_ERROR;
	}
	if (NicodemusFitColumn(interp, itemPtr, col) != TCL_OK) {
	    return TCL_ERROR;
	}

	return TCL_OK;
    } else if (**argv == 's' && (strncmp(*argv, "swap", 2) == 0)) {
	int col1, col2;
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " swap col1 col2",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	if (sscanf(argv[1], "%d", &col1) != 1) {
	    Tcl_SetResult(interp, "Bad column value.", TCL_STATIC);
	    return TCL_ERROR;
	}
	if (sscanf(argv[2], "%d", &col2) != 1) {
	    Tcl_SetResult(interp, "Bad column value.", TCL_STATIC);
	    return TCL_ERROR;
	}

	if (NicodemusSwapColumns(interp, itemPtr, col1, col2) != TCL_OK) {
	    return TCL_ERROR;
	}

	return TCL_OK;
    } else if (**argv == 's' && (strncmp(*argv, "solve", 2) == 0)) {
	if( (itemPtr->typePtr->solveProc)(interp, itemPtr, temp_str) != TCL_OK) {
	    return TCL_ERROR;
	} else {
	    Tcl_ResetResult(interp);
	    return TCL_OK;
	}
    } else if (**argv == 'u' && (strncmp(*argv, "undo", 1) == 0)) {
	/*
	 * The final argument to NicodemusUndo is ignored.  Send it a dummy
	 * value of '0'
	 */
	if ( (itemPtr->typePtr->undoProc)(interp, itemPtr, argv[1], 0) != TCL_OK) {
	    /*
	     * This should not be able to happen.
	     */
	    fprintf(stderr, "Internal cipher error:  nicodemus undo proc returned !TCL_OK\n");
	    abort();
	    return TCL_ERROR;
	}
	Tcl_SetResult(interp, "", TCL_STATIC);
	return TCL_OK;
    } else if (**argv == 'l' && (strncmp(*argv, "locate", 1) == 0)) {
	Tcl_SetResult(interp,
		"No locate tip function defined for nicodemus ciphers.",
		TCL_STATIC);
	return TCL_ERROR;
    } else {
	Tcl_AppendResult(interp, "Unknown option ", *argv, (char *)NULL);
	Tcl_AppendResult(interp, "\nMust be one of:  ", cmd,
			" cget ?option?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" configure ?option value?", (char *)NULL);
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
}

static int
EncodeNicodemus(Tcl_Interp *interp, CipherItem *itemPtr, const char *pt, const char *key) {
    char *ct = (char *)NULL;
    int count;
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

    if (strlen(argv[0]) != itemPtr->period || strlen(argv[1]) != itemPtr->period) {
	Tcl_SetResult(interp,
		"Length of key does not match the period.", TCL_STATIC);
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, pt) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }
    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[0], argv[1]) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }
    ct = NicodemusTransform(itemPtr, itemPtr->ciphertext, ENCODE);
    if (ct == (char *)NULL) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }
    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, ct) != TCL_OK) {
	ckfree((char *)argv);
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

#undef VIG_TYPE
#undef VAR_TYPE
#undef BEA_TYPE
#undef GRN_TYPE
#undef PRT_TYPE
