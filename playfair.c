/*
 * playfair.c --
 *
 *	This file implements the 6x6 playfair cipher type.
 *
 * Copyright (c) 2003-2004 Michael Thomas <wart@kobold.org>
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

#define INVALID_KEY_INDEX -1

typedef struct PlayfairItem {
    CipherItem header;

    int keyPeriod;
    int keyLen;
    int alphabetLen;

    char **key;
    char *keyValPos;

    char **maxSolKey;
    int maxSolVal;
} PlayfairItem;

static int  CreatePlayfair	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
void  DeletePlayfair		_ANSI_ARGS_((ClientData));
static int  CreateBigPlayfair	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
static char *GetPlayfair	_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetPlayfair		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestorePlayfair	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolvePlayfair	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
int PlayfairCmd		_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));
static int PlayfairUndo	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int PlayfairSubstitute _ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int PlayfairLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int PlayfairSwapCols	_ANSI_ARGS_((Tcl_Interp *, CipherItem *, int,
	    			int));
static int PlayfairSwapRows	_ANSI_ARGS_((Tcl_Interp *, CipherItem *, int,
	    			int));
static void DecodePair	_ANSI_ARGS_((PlayfairItem *, char, char,
				char *, char *, int));
static int PlayfairSetPeriod	_ANSI_ARGS_((Tcl_Interp *, CipherItem *, int));
static int PlayfairLetterToKeyIndex _ANSI_ARGS_((PlayfairItem *, char));
static int EncodePlayfair	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static char *DecodePlayfair	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static char *PlayfairAddNulls   _ANSI_ARGS_((const char *, int));

CipherType PlayfairType = {
    "playfair",
    ATOZ,
    sizeof(PlayfairItem),
    CreatePlayfair,	/* create proc */
    DeletePlayfair,	/* delete proc */
    PlayfairCmd,	/* cipher command proc */
    GetPlayfair,	/* get plaintext proc */
    SetPlayfair,	/* show ciphertext proc */
    SolvePlayfair,	/* solve cipher proc */
    RestorePlayfair,	/* restore proc */
    PlayfairLocateTip,	/* locate proc */
    PlayfairSubstitute,	/* sub proc */
    PlayfairUndo,	/* undo proc */
    EncodePlayfair,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

CipherType BigplayfairType = {
    "bigplayfair",
    ATOZONETONINE,
    sizeof(PlayfairItem),
    CreateBigPlayfair,	/* create proc */
    DeletePlayfair,	/* delete proc */
    PlayfairCmd,	/* cipher command proc */
    GetPlayfair,	/* get plaintext proc */
    SetPlayfair,	/* show ciphertext proc */
    SolvePlayfair,	/* solve cipher proc */
    RestorePlayfair,	/* restore proc */
    PlayfairLocateTip,	/* locate proc */
    PlayfairSubstitute,	/* sub proc */
    PlayfairUndo,	/* undo proc */
    EncodePlayfair,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

static int
CreateBigPlayfair(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    PlayfairItem *playPtr = (PlayfairItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;
    int		j;

    playPtr->keyPeriod = 6;
    playPtr->keyLen = 36;
    playPtr->alphabetLen = 36;
    playPtr->header.period = 0;
    playPtr->maxSolVal = 0;
    playPtr->maxSolKey = (char **)NULL;
    playPtr->key = (char **)ckalloc(sizeof(char *) * playPtr->keyPeriod);
    for(i=0; i < playPtr->keyPeriod; i++) {
	playPtr->key[i] = (char *)ckalloc(sizeof(char) * playPtr->keyPeriod);
	for(j=0; j < playPtr->keyPeriod; j++) {
	    playPtr->key[i][j] = '\0';
	}
    }
    playPtr->keyValPos = (char *)ckalloc(sizeof(char *) * playPtr->keyLen + 1);
    for(i=0; i < playPtr->alphabetLen; i++) {
	playPtr->keyValPos[i] = 0;
    }

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, PlayfairCmd, itemPtr,
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
CreatePlayfair(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    PlayfairItem *playPtr = (PlayfairItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;
    int		j;

    playPtr->keyPeriod = 5;
    playPtr->keyLen = 25;
    playPtr->alphabetLen = 26;
    playPtr->header.period = 0;
    playPtr->maxSolVal = 0;
    playPtr->maxSolKey = (char **)NULL;
    playPtr->key = (char **)ckalloc(sizeof(char *) * playPtr->keyPeriod);
    for(i=0; i < playPtr->keyPeriod; i++) {
	playPtr->key[i] = (char *)ckalloc(sizeof(char) * playPtr->keyPeriod);
	for(j=0; j < playPtr->keyPeriod; j++) {
	    playPtr->key[i][j] = '\0';
	}
    }
    playPtr->keyValPos = (char *)ckalloc(sizeof(char *) * playPtr->alphabetLen + 1);
    for(i=0; i < playPtr->alphabetLen; i++) {
	playPtr->keyValPos[i] = 0;
    }

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, PlayfairCmd, itemPtr,
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
DeletePlayfair(ClientData clientData)
{
    PlayfairItem *playPtr = (PlayfairItem *)clientData;
    int i;

    if (playPtr->key != NULL) {
	for (i=0; i < playPtr->keyPeriod; i++) {
	    ckfree(playPtr->key[i]);
	}
	ckfree((char *)playPtr->key);
    }

    if (playPtr->keyValPos != NULL) {
	ckfree(playPtr->keyValPos);
    }

    DeleteCipher(clientData);
}

static int
SetPlayfair(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
{
    char	*c;
    int		length=0;

    length = CountValidChars(itemPtr, ctext);
    c = ExtractValidChars(itemPtr, ctext);

    if (!c) {
	Tcl_SetResult(interp, "No valid characters found in ciphertext",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (length%2) {
	ckfree(c);
	Tcl_AppendResult(interp, itemPtr->typePtr->type,
		" ciphers must contain an even number of characters",
		(char *)NULL);
	return TCL_ERROR;
    }

    itemPtr->length = length;
    if (itemPtr->ciphertext) {
	ckfree(itemPtr->ciphertext);
    }
    itemPtr->ciphertext = c;

    if (itemPtr->ciphertext == NULL) {
	Tcl_SetResult(interp, "Error mallocing memory for new cipher", 
		TCL_STATIC);
	return TCL_ERROR;
    }

    itemPtr->length = length;

    Tcl_SetResult(interp, itemPtr->ciphertext, TCL_STATIC);

    return TCL_OK;
}

static int
PlayfairUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int offset)
{
    PlayfairItem *playPtr = (PlayfairItem *)itemPtr;
    int i, j;

    if (! ct) {
	for(i=0; i < playPtr->keyPeriod; i++) {
	    for(j=0; j < playPtr->keyPeriod; j++) {
		playPtr->key[i][j] = '\0';
	    }
	}
	for(i=0; i < playPtr->alphabetLen; i++) {
	    playPtr->keyValPos[i] = 0;
	}
    } else {
	while (*ct) {
	    int keyVal;
	    int keyValIndex = PlayfairLetterToKeyIndex(playPtr, *ct);

	    if ( keyValIndex == INVALID_KEY_INDEX) {
		Tcl_SetResult(interp, "Invalid key value", TCL_STATIC);
		return TCL_ERROR;
	    }

	    keyVal = playPtr->keyValPos[keyValIndex];

	    if (keyVal) {
		keyVal--;
		playPtr->key[keyVal/playPtr->keyPeriod][keyVal%playPtr->keyPeriod]='\0';
	    }

	    ct++;
	}
    }

    return TCL_OK;
}

static int
PlayfairSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, const char *pt, int offset)
{
    PlayfairItem *playPtr = (PlayfairItem *)itemPtr;
    int row, col;
    int keyValIndex = INVALID_KEY_INDEX;

    /*
     * pt == row
     * ct == col
     * offset == val
     */

    row = *ct - '1';
    col = *pt - '1';

    if (row < 0 || row >= playPtr->keyPeriod) {
	Tcl_SetResult(interp, "Invalid row specification", TCL_STATIC);
	return TCL_ERROR;
    }

    if (col < 0 || col >= playPtr->keyPeriod) {
	Tcl_SetResult(interp, "Invalid column specification", TCL_STATIC);
	return TCL_ERROR;
    }

    if ( (keyValIndex = PlayfairLetterToKeyIndex(playPtr, (char) offset)) == INVALID_KEY_INDEX) {
	Tcl_SetResult(interp, "Invalid key value", TCL_STATIC);
	return TCL_ERROR;
    }

    playPtr->keyValPos[keyValIndex] = row*playPtr->keyPeriod+col+1;
    playPtr->key[row][col] = offset;

    return TCL_OK;
}

static char *
GetPlayfair(Tcl_Interp *interp, CipherItem *itemPtr)
{
    if (itemPtr->length == 0) {
	Tcl_SetResult(interp, "Can't do anything until ciphertext has been set",
		TCL_STATIC);
	return (char *)NULL;
    }

    return DecodePlayfair(interp, itemPtr, itemPtr->ciphertext, DECODE);
}

/*
 * Utility function for encoding/decoding a playfair cipher.
 */
static char *
DecodePlayfair(Tcl_Interp *interp, CipherItem *itemPtr, const char *text, int mode) {
    int		i;
    char	pt1 = '\0';
    char	pt2 = '\0';
    char	*result=(char *)ckalloc(sizeof(char) * itemPtr->length * 2 + 1);
    char	ct1 = '\0';
    char	ct2 = '\0';
    int         numNulls = 0;

    if (itemPtr->period > 0) {
	int block;
	int nblocks = itemPtr->length / (itemPtr->period * 2);
	if (itemPtr->length % (itemPtr->period*2) != 0) {
	    nblocks++;
	}
	for (block=0; block < nblocks; block++) {
	    int blockLen = ((itemPtr->length + numNulls) - block * itemPtr->period * 2) / 2;
            int nullsInBlock = 0;
	    if (blockLen > itemPtr->period) {
		blockLen = itemPtr->period;
	    }
	    for (i=0; i < blockLen; i++) {
		int index1 = block * 2 * itemPtr->period + i;
		int index2 = index1 + blockLen;
                int ctIndex1 = index1 - (numNulls - nullsInBlock);
                int ctIndex2 = ctIndex1 + blockLen - nullsInBlock;

		pt1 = '\0';
		pt2 = '\0';
		ct1 = text[ctIndex1];
		ct2 = text[ctIndex2];
                /*
                 * Throw an error if we're decoding and discover a pair
                 * of identical letters
                 */
                if (ct1 == ct2 && mode == DECODE) {
                    Tcl_SetResult(interp,
                            "Invalid double letters found in ciphertext",
                            TCL_STATIC);
                    ckfree(result);
                    return (char *)NULL;
                }

		DecodePair((PlayfairItem *)itemPtr,
			ct1, ct2,
			&pt1, &pt2,
			mode);

		if (pt1 == '\0') {
		    pt1 = ' ';
		}
		if (pt2 == '\0') {
		    pt2 = ' ';
		}

		result[index1] = pt1;
		result[index2] = pt2;
	    }
	}
    } else {
	for(i=0; i < itemPtr->length; i+=2) {
	    pt1 = '\0';
	    pt2 = '\0';
	    if (text[i] == text[i+1]) {
		Tcl_SetResult(interp,
			"Invalid double letters found in ciphertext",
			TCL_STATIC);
		ckfree(result);
		return (char *)NULL;
	    }
	    DecodePair((PlayfairItem *)itemPtr,
		    text[i], text[i+1],
		    &pt1, &pt2,
		    mode);
	    if (pt1 == '\0') {
		pt1 = ' ';
	    }
	    if (pt2 == '\0') {
		pt2 = ' ';
	    }

	    result[i] = pt1;
	    result[i+1] = pt2;
	}
    }
    result[itemPtr->length + numNulls] = '\0';

    return result;
}

static int
PlayfairLetterToKeyIndex(PlayfairItem *playPtr, char c) {
    if (c >= 'a' && c <= 'z') {
	return c-'a';
    } else if (c >= '0' && c <= '9' && playPtr->keyLen == 36) {
	return c-'0'+26;
    } else {
	return INVALID_KEY_INDEX;
    }
}

static void
DecodePair(PlayfairItem *playPtr, char in1, char in2, char *out1, char *out2, int mode) {
    int	let1_row;
    int	let1_col;
    int	let2_row;
    int	let2_col;
    int keyPosIndex1 = PlayfairLetterToKeyIndex(playPtr, in1);
    int keyPosIndex2 = PlayfairLetterToKeyIndex(playPtr, in2);
    /*
     * Caution:  Don't use these values until keyPosIndex1/2 have been
     * validated.  These values are invalid if keyPosIndex1/2 are
     * INVALID_KEY_INDEX
     */
    int keyPos1 = playPtr->keyValPos[keyPosIndex1];
    int keyPos2 = playPtr->keyValPos[keyPosIndex2];

    if (keyPosIndex1 == INVALID_KEY_INDEX || keyPosIndex2 == INVALID_KEY_INDEX) {
	*out1 = '\0';
	*out2 = '\0';
    } else if ((keyPos1 == keyPos2) && keyPos1 && keyPos2) {
	*out1 = '\0';
	*out2 = '\0';
    } else if (keyPos1 && keyPos2) {
	keyPos1--;
	keyPos2--;

	let1_row = keyPos1/playPtr->keyPeriod;
	let1_col = keyPos1%playPtr->keyPeriod;
	let2_row = keyPos2/playPtr->keyPeriod;
	let2_col = keyPos2%playPtr->keyPeriod;

	if (let1_row == let2_row) {
	    if (mode == DECODE) {
		*out1 = playPtr->key[let1_row][((let1_col-1)+playPtr->keyPeriod)%playPtr->keyPeriod];
		*out2 = playPtr->key[let2_row][((let2_col-1)+playPtr->keyPeriod)%playPtr->keyPeriod];
	    } else {
		*out1 = playPtr->key[let1_row][((let1_col+1)+playPtr->keyPeriod)%playPtr->keyPeriod];
		*out2 = playPtr->key[let2_row][((let2_col+1)+playPtr->keyPeriod)%playPtr->keyPeriod];
	    }
	} else if (let1_col == let2_col) {
	    if (mode == DECODE) {
		*out1 = playPtr->key[((let1_row-1)+playPtr->keyPeriod)%playPtr->keyPeriod][let1_col];
		*out2 = playPtr->key[((let2_row-1)+playPtr->keyPeriod)%playPtr->keyPeriod][let2_col];
	    } else {
		*out1 = playPtr->key[((let1_row+1)+playPtr->keyPeriod)%playPtr->keyPeriod][let1_col];
		*out2 = playPtr->key[((let2_row+1)+playPtr->keyPeriod)%playPtr->keyPeriod][let2_col];
	    }
	} else {
	    /*
	     * Encoding and decoding are reciprocal operations when the
	     * letters aren't in the same row or column.
	     */
	    *out1 = playPtr->key[let1_row][let2_col];
	    *out2 = playPtr->key[let2_row][let1_col];
	}

	if (!*out1) {
	    *out1 = ' ';
	}
	if (!*out2) {
	    *out2 = ' ';
	}
    }
}

static int
RestorePlayfair(Tcl_Interp *interp, CipherItem *itemPtr, const char *key, const char *dummy)
{
    PlayfairItem *playPtr = (PlayfairItem *)itemPtr;
    int i;
    int row;
    int col;
    char used[playPtr->alphabetLen];

    if (itemPtr->length <= 0) {
	Tcl_SetResult(interp, "Can't do anything until ciphertext has been set",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (strlen(key) != playPtr->keyLen) {
	char temp_str[TCL_DOUBLE_SPACE];
	sprintf(temp_str, "%ld", strlen(key));
	Tcl_AppendResult(interp, "Invalid key length ",
		temp_str,
		(char *)NULL);
	return TCL_ERROR;
    }

    for(i=0; i < playPtr->alphabetLen; i++) {
	playPtr->keyValPos[i] = 0;
        used[i] = '\0';
    }

    for(i=0; i < playPtr->keyPeriod*playPtr->keyPeriod; i++) {
	int keyValIndex = PlayfairLetterToKeyIndex(playPtr, key[i]);
	if ( keyValIndex == INVALID_KEY_INDEX && (key[i] != ' ')) {
	    Tcl_SetResult(interp, "Invalid character in key", TCL_STATIC);
	    return TCL_ERROR;
	}
	row = i / playPtr->keyPeriod;
	col = i % playPtr->keyPeriod;

	if (key[i] == ' ') {
	    playPtr->key[row][col] = '\0';
	} else {
	    playPtr->key[row][col] = key[i];
	    playPtr->keyValPos[keyValIndex] = i+1;
	}
    }

    /*
     * Look for duplicates in the key
     */
    for(i=0; i < playPtr->keyLen; i++) {
	int keyValIndex;

	row = i / playPtr->keyPeriod;
	col = i % playPtr->keyPeriod;
        keyValIndex = PlayfairLetterToKeyIndex(playPtr, playPtr->key[row][col]);

	if (playPtr->key[row][col] && used[keyValIndex]) {
            char badChar[2];
            badChar[0] = playPtr->key[row][col];
            badChar[1] = '\0';

            Tcl_ResetResult(interp);
            Tcl_AppendResult(interp, "Duplicate character in key: ", badChar, (char *)NULL);
            return TCL_ERROR;
	}
        used[keyValIndex] = 1;
    }

    return TCL_OK;
}

static int
SolvePlayfair(Tcl_Interp *interp, CipherItem *itemPtr, char *maxkey)
{
    Tcl_AppendResult(interp, "Solving ",
	    itemPtr->typePtr->type,
	    " ciphers is not yet implemented.",
	    (char *)NULL);
    return TCL_ERROR;
}

static int
PlayfairLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, const char *tip, const char *start)
{
    Tcl_AppendResult(interp,
	    "No locate tip function defined for ",
	    itemPtr->typePtr->type,
	    " ciphers.",
	    (char *)NULL);
    return TCL_ERROR;
}

static int
PlayfairSwapCols(Tcl_Interp *interp, CipherItem *itemPtr, int col1, int col2)
{
    PlayfairItem *playPtr = (PlayfairItem *)itemPtr;
    int i, tempCol, row, col;

    if (col1 < 1 || col2 < 1 || col1 > playPtr->keyPeriod || col2 > playPtr->keyPeriod) {
	Tcl_AppendResult(interp, "Invalid column in ",
	       itemPtr->typePtr->type,
	       " swap", (char *)NULL);
	return TCL_ERROR;
    }

    col1--;
    col2--;

    for(i=0; i < playPtr->keyPeriod; i++) {
	tempCol = playPtr->key[i][col1];
	playPtr->key[i][col1] = playPtr->key[i][col2];
	playPtr->key[i][col2] = tempCol;
    }

    for(i=0; i < playPtr->alphabetLen; i++) {
	playPtr->keyValPos[i] = 0;
    }

    for(row=0; row < playPtr->keyPeriod; row++) {
	for(col=0; col < playPtr->keyPeriod; col++) {
	    int keyPos = row*playPtr->keyPeriod+col;

	    if (playPtr->key[row][col]) {
		int keyValPos = PlayfairLetterToKeyIndex(playPtr, playPtr->key[row][col]);
		if (keyValPos != INVALID_KEY_INDEX) {
		    playPtr->keyValPos[keyValPos] = keyPos+1;
		}
	    }
	}
    }

    return TCL_OK;
}

static int
PlayfairSwapRows(Tcl_Interp *interp, CipherItem *itemPtr, int row1, int row2)
{
    PlayfairItem *playPtr = (PlayfairItem *)itemPtr;
    int i, tempRow, row, col;

    if (row1 < 1 || row2 < 1 || row1 > playPtr->keyPeriod || row2 > playPtr->keyPeriod) {
	Tcl_AppendResult(interp, "Invalid row in ",
	       itemPtr->typePtr->type,
	       " swap", (char *)NULL);
	return TCL_ERROR;
    }

    row1--;
    row2--;

    for(i=0; i < playPtr->keyPeriod; i++) {
	tempRow = playPtr->key[row1][i];
	playPtr->key[row1][i] = playPtr->key[row2][i];
	playPtr->key[row2][i] = tempRow;
    }

    for(i=0; i < playPtr->alphabetLen; i++) {
	playPtr->keyValPos[i] = 0;
    }

    for(row=0; row < playPtr->keyPeriod; row++) {
	for(col=0; col < playPtr->keyPeriod; col++) {
	    int keyPos = row*playPtr->keyPeriod+col;

	    if (playPtr->key[row][col]) {
		int keyValPos = PlayfairLetterToKeyIndex(playPtr, playPtr->key[row][col]);
		if (keyValPos != INVALID_KEY_INDEX) {
		    playPtr->keyValPos[keyValPos] = keyPos+1;
		}
	    }
	}
    }

    return TCL_OK;
}

int
PlayfairCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    PlayfairItem *playPtr = (PlayfairItem *)clientData;
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
	    sprintf(temp_str, "%d", playPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", itemPtr->period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!playPtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_STATIC);
	    } else {
		Tcl_SetResult(interp, playPtr->header.ciphertext, TCL_VOLATILE);
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
	    for(i=0; i < playPtr->keyPeriod; i++) {
		int j;
		for(j=0; j < playPtr->keyPeriod; j++) {
		    if (playPtr->key[i][j]) {
			temp_str[j+i*playPtr->keyPeriod] = playPtr->key[i][j];
		    } else {
			temp_str[j+i*playPtr->keyPeriod] = ' ';
		    }
		}
	    }
	    temp_str[playPtr->keyPeriod*playPtr->keyPeriod] = '\0';
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
	    if (strncmp(*argv, "-stepinterval", 12) == 0) {
		if (sscanf(argv[1], "%d", &i) != 1) {
		    Tcl_SetResult(interp, "Invalid interval.", TCL_STATIC);
		    return TCL_ERROR;
		}

		if (i < 0 ) {
		    Tcl_SetResult(interp, "Invalid interval.", TCL_STATIC);
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
	    } else if (strncmp(*argv, "-period", 6) == 0) {
		int period;
		if (sscanf(argv[1], "%d", &period) != 1) {
		    Tcl_AppendResult(interp, "Bad period.  Integer expected:  ",
			    argv[1], (char *)NULL);
		    return TCL_ERROR;
		}
		Tcl_SetObjResult(interp, Tcl_NewStringObj(argv[1], -1));

		return PlayfairSetPeriod(interp, itemPtr, period);
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
    } else if (**argv == 'e' && (strncmp(*argv, "encode", 1) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " encode pt key",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	return (itemPtr->typePtr->encodeProc)(interp, itemPtr, argv[1], argv[2]);
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
			TCL_STATIC);
		return TCL_ERROR;
	    }
	    if (sscanf(argv[2], "%d", &col1) != 1) {
		Tcl_AppendResult(interp,
			"Invalid row/column value ", argv[2], ".",
			(char *)NULL);
		return TCL_ERROR;
	    }
	    if (sscanf(argv[3], "%d", &col2) != 1) {
		Tcl_AppendResult(interp,
			"Invalid row/column value ", argv[3], ".",
			(char *)NULL);
		return TCL_ERROR;
	    }
	}
	if (strcmp(argv[1], "row") == 0) {
	    return PlayfairSwapRows(interp, itemPtr, col1, col2);
	} else {
	    return PlayfairSwapCols(interp, itemPtr, col1, col2);
	}
    } else if (**argv == 'l' && (strncmp(*argv, "locate", 3) == 0)) {
	Tcl_AppendResult(interp,
		"No locate tip function defined for ",
	        itemPtr->typePtr->type, " ciphers.", (char *)NULL);
	return TCL_ERROR;
    } else if (**argv == 's' && (strncmp(*argv, "substitute", 3) == 0)) {
	if (argc != 4) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd,
		    " substitute row col val", (char *)NULL);
	    return TCL_ERROR;
	}

	return (itemPtr->typePtr->subProc)(interp, itemPtr, argv[1], argv[2], argv[3][0]);
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
PlayfairSetPeriod(Tcl_Interp *interp, CipherItem *itemPtr, int period) {
    int i;

    if (period < 0) {
	Tcl_SetResult(interp, "Period must be greater than zero.",
		TCL_STATIC);
	return TCL_ERROR;
    }
    /*
     * Due to restrictions on how playfair ciphers are constructed, we should
     * never see a pair of double-letters in the ciphertext, where the first
     * letter is in an even position.
     * 
     * Note:  This is not valid for seriated playfair ciphers.  Seriated
     * playfair ciphers can't have double letters in the same column.
     */

    if (period == 0) {
	for(i=0; i < itemPtr->length-1; i+=2) {
	    if (itemPtr->ciphertext[i] == itemPtr->ciphertext[i+1]) {
		Tcl_SetResult(interp,
			"Invalid double letters found in ciphertext",
			TCL_STATIC);
			return TCL_ERROR;
	    }
	}
    } else {
	int block;
	int nblocks = itemPtr->length / period;
	if (itemPtr->length % period != 0) {
	    nblocks++;
	}
	for (block=0; block < nblocks; block++) {
	    int blockLen = (itemPtr->length - (block) * period * 2) / 2;
	    if (blockLen > period) {
		blockLen = period;
	    }
	    for (i=0; i < blockLen; i++) {

		int index1 = block * 2 * period + i;
		int index2 = index1 + blockLen;

		if (itemPtr->ciphertext[index1] == itemPtr->ciphertext[index2]) {
		    char temp_str[TCL_DOUBLE_SPACE*2+2];
		    sprintf(temp_str, "%d, %d", index1, index2);
		    Tcl_AppendResult(interp,
			    "Invalid double letters found in ciphertext at positions ",
			    temp_str,
			    (char *)NULL);

		    return TCL_ERROR;
		}
	    }
	}
    }

    itemPtr->period = period;
    return TCL_OK;
}

static int
EncodePlayfair(Tcl_Interp *interp, CipherItem *itemPtr, const char *pt, const char *key) {
    PlayfairItem *playPtr = (PlayfairItem *)itemPtr;
    char *ct = (char *)NULL;
    char *newPt = (char *)NULL;
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

    if (strlen(argv[0]) != playPtr->keyLen) {
	Tcl_SetResult(interp, "Invalid length of key.", TCL_STATIC);
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    newPt = PlayfairAddNulls(pt, itemPtr->period);

    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, newPt) != TCL_OK) {
	ckfree((char *)argv);
	ckfree((char *)newPt);
	return TCL_ERROR;
    }
    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[0], (char *)NULL) != TCL_OK) {
	ckfree((char *)argv);
	ckfree((char *)newPt);
	return TCL_ERROR;
    }
    ct = DecodePlayfair(interp, itemPtr, newPt, ENCODE);
    if (ct == (char *)NULL) {
	ckfree((char *)argv);
	ckfree((char *)newPt);
	return TCL_ERROR;
    }
    /*
     * Free up the null-adjusted plaintext that is not needed anymore.
     */
    ckfree((char *)newPt);

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

static char *
PlayfairAddNulls(const char *pt, int period) {
    /*
     * Create a new buffer that's twice the size of the plaintext to
     * account for any extra inserted null characters.
     */
    char *newPt = (char *)ckalloc(sizeof(char) * strlen(pt) * 2);
    int curPos = 0;
    int i = 0;
    int ptLength = strlen(pt);
    int numNulls = 0;

    if (period == 0) {
        for (i=0; pt[i]; i++) {
            if (pt[i] == pt[i+1]) {
                numNulls++;
            }
        }
        if ((i+numNulls)%2 != 0) {
            numNulls++;
        }

        for (i=0; pt[i]; i++, curPos++) {
            newPt[curPos] = pt[i];
            if (curPos%2 == 0 && pt[i] == pt[i+1]) {
                if (pt[i] == 'x') {
                    /* Use 'q' as a cryptographic null in case the
                     * double letter is the character that we usually
                     * use as a cryptographic null.
                     */
                    newPt[++curPos] = 'q';
                } else {
                    newPt[++curPos] = 'x';
                }
            }
        }
        if (curPos%2 == 1) {
            if (newPt[curPos-1] == 'x') {
                /* Use 'q' as a cryptographic null in case the
                 * double letter is the character that we usually
                 * use as a cryptographic null.
                 */
                newPt[curPos++] = 'q';
            } else {
                newPt[curPos++] = 'x';
            }
        }
        newPt[curPos] = '\0';
    } else {
        int addedNull=0;
	int block;
	int nblocks = ptLength / (period * 2);
	if (ptLength % (period*2) != 0) {
	    nblocks++;
	}

        for (i=0; i < ptLength; i++) {
            newPt[i] = pt[i];
        }
        newPt[i] = '\0';

        do {
            addedNull = 0;
            nblocks = (ptLength+numNulls) / (period * 2);
            if ((ptLength+numNulls) % (period*2) != 0) {
                nblocks++;
            }

            for (block=0; block < nblocks && !addedNull; block++) {
                int blockLen = (((ptLength + numNulls) - block * period * 2) + 1) / 2;
                if (blockLen >= period) {
                    blockLen = period;
                }
                for (i=0; i < blockLen && !addedNull; i++) {
                    int index1 = block * 2 * period + i;
                    int index2 = index1 + blockLen;
                    char ct1 = newPt[index1];
                    char ct2 = newPt[index2];

                    /*
                     * Add a cryptographic null if we're encoding and discover
                     * a pair of identical letters.
                     */
                    if (ct1 == ct2 || index2 >= strlen(newPt)) {
                        int j=0;
                        if (ct1 == 'x') {
                            ct2 = 'q';
                        } else {
                            ct2 = 'x';
                        }
                        numNulls++;
                        addedNull = 1;

                        for (j=ptLength+numNulls; j >= index2; j--) {
                            newPt[j+1] = newPt[j];
                        }
                        newPt[index2] = ct2;
                    }
                }
            }
        } while (addedNull);

        newPt[ptLength + numNulls] = '\0';
    }

    return newPt;
}

#undef INVALID_KEY_INDEX
