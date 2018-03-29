/*
 * grille.c --
 *
 *	This file implements the grille cipher type.
 *
 * Copyright (c) 1999-2000 Michael Thomas <wart@kobold.org>
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
#include <math.h>

#include <cipherDebug.h>

static int  CreateGrille	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
void DeleteGrille		_ANSI_ARGS_((ClientData));
static char *GetGrille		_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static char *GetStaticGrille	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
static int  SetGrille		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestoreGrille	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolveGrille		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
int GrilleCmd			_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));
static int GrilleUndo		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int GrilleSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int GrilleIntSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				int, int, int));
static int GrilleLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *));
static int GrilleInitKey	_ANSI_ARGS_((Tcl_Interp *, CipherItem *, int));
static int RecSolveGrille	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *, int));

#define STANDARD	1
#define INVERSE		2

#define GRILLE_BLANK	0
#define GRILLE_FIRST	1
#define GRILLE_SECOND	2
#define GRILLE_THIRD	3
#define GRILLE_FOURTH	4

typedef struct GrilleItem {
    CipherItem header;

    int grilleType;	/* Either a standard or inverse grille */

    char **key;		/* Array of "holes" */
    int numSquares;	/* Always 1 for now */

    double maxSolVal;	/* Best solution value */
    char **maxKey;	/* Best solution key */
} GrilleItem;

CipherType GrilleType = {
    "grille",
    ATOZ,
    sizeof(GrilleItem),
    CreateGrille,	/* create proc */
    DeleteGrille,	/* delete proc */
    GrilleCmd,		/* cipher command proc */
    GetGrille,		/* get plaintext proc */
    SetGrille,		/* show ciphertext proc */
    SolveGrille,	/* solve cipher proc */
    RestoreGrille,	/* restore proc */
    GrilleLocateTip,	/* locate proc */
    GrilleSubstitute,	/* sub proc */
    GrilleUndo,		/* undo proc */
    NULL,		/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

static int
CreateGrille(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    GrilleItem *grilPtr = (GrilleItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    grilPtr->header.period = 0;
    grilPtr->key = (char **)NULL;
    grilPtr->numSquares = 0;
    grilPtr->grilleType = STANDARD;

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, GrilleCmd, itemPtr,
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
DeleteGrille(ClientData clientData)
{
    GrilleItem *grilPtr = (GrilleItem *)clientData;
    int i;

    if (grilPtr->key) {
	for(i=0; i < grilPtr->header.period; i++) {
	    ckfree(grilPtr->key[i]);
	}
	ckfree((char *)grilPtr->key);
    }

    DeleteCipher(clientData);
}

static int
GrilleInitKey(Tcl_Interp *interp, CipherItem *itemPtr, int period)
{
    GrilleItem *grilPtr = (GrilleItem *)itemPtr;
    int i, j;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp,
		"Can't do anything until the ciphertext has been set",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (grilPtr->key) {
	for(i=0; i < itemPtr->period; i++) {
	    ckfree(grilPtr->key[i]);
	}
	ckfree((char *)grilPtr->key);
    }

    grilPtr->key = (char **)ckalloc(sizeof(char *) * period);
    for(i=0; i < period; i++) {
	grilPtr->key[i] = (char *)ckalloc(sizeof(char) * period);
	for(j=0; j < period; j++) {
	    grilPtr->key[i][j] = GRILLE_BLANK;
	}
    }

    itemPtr->period = period;
    /*
    if (itemPtr->length % (period*period) == 0) {
	grilPtr->numSquares = (itemPtr->length / (period*period));
    } else {
	grilPtr->numSquares = (itemPtr->length / (period*period))+1;
    }
    */

    return TCL_OK;
}

static int
SetGrille(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
{
    char	*c;
    int		valid = TCL_OK,
    		length=0,
		period;
    Tcl_Obj *intObj;

    length = CountValidChars(itemPtr, ctext);
    c = ExtractValidChars(itemPtr, ctext);

    if (length == 0) {
	Tcl_SetResult(interp, "No valid characters found in ciphertext",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    valid = TCL_OK;

    period = (int)sqrt(length);
    if (period * period != length) {
	intObj = Tcl_NewIntObj(length);
	ckfree(c);

	Tcl_AppendResult(interp,
		"Invalid cipher length '",
		Tcl_GetString(intObj), 
		"'.  Length must be a perfect square.",
		(char *)NULL);

	Tcl_DecrRefCount(intObj);
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
	    itemPtr->length = 0;
	    return TCL_ERROR;
	}

	itemPtr->length = length;
	if (GrilleInitKey(interp, itemPtr, period) != TCL_OK) {
	    ckfree(itemPtr->ciphertext);
	    itemPtr->ciphertext = (char *)NULL;
	    itemPtr->length = 0;

	    return TCL_ERROR;
	}

	Tcl_SetResult(interp, itemPtr->ciphertext, TCL_STATIC);
    }

    return valid;
}

static int
GrilleUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *junk, int null)
{
    GrilleItem *grilPtr = (GrilleItem *)itemPtr;
    int i;
    int j;

    for(i=0; i < itemPtr->period; i++) {
	for(j=0; j < itemPtr->period; j++) {
	    grilPtr->key[i][j] = GRILLE_BLANK;
	}
    }

    return TCL_OK;
}

static int
GrilleSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *row, const char *col, int orientation)
{
    int 	rowVal;
    int 	colVal;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp,
		"Can't do anything until the ciphertext has been set",
		TCL_VOLATILE);
	return BAD_SUB;
    }

    /*
     * Validate the inputs
     */

    if (sscanf(row, "%d", &rowVal) != 1) {
	Tcl_AppendResult(interp,
		"Invalid row (", row, ") in substitution.", (char *)NULL,
		TCL_VOLATILE);
	return BAD_SUB;
    }
    if (sscanf(col, "%d", &colVal) != 1) {
	Tcl_AppendResult(interp,
		"Invalid column (", col, ") in substitution.", (char *)NULL,
		TCL_VOLATILE);
	return BAD_SUB;
    }

    if (itemPtr->period % 2 == 1) {
        if (rowVal*2 - 1 == itemPtr->period && colVal * 2 - 1 == itemPtr->period) {
            Tcl_SetResult(interp,
                    "Can't substitute for the middle space in an odd-width grille.",
                    TCL_STATIC);
            return BAD_SUB;
        }
    }

    rowVal--;
    colVal--;
    orientation--;

    return GrilleIntSubstitute(interp, itemPtr, rowVal, colVal, orientation);
}

static int
GrilleIntSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, int rowVal, int colVal, int orientation)
{
    GrilleItem *grilPtr = (GrilleItem *)itemPtr;
    int		valid_sub = NEW_SUB;
    int		period = itemPtr->period;
    int		tempVal;

    if (rowVal < 0 || rowVal >= itemPtr->period) {
	Tcl_SetResult(interp, "Invalid row setting", TCL_VOLATILE);
	return BAD_SUB;
    }

    if (colVal < 0 || colVal >= itemPtr->period) {
	Tcl_SetResult(interp, "Invalid column setting", TCL_VOLATILE);
	return BAD_SUB;
    }

    if (orientation < 0 || orientation > 3) {
	Tcl_SetResult(interp, "Invalid orientation setting", TCL_VOLATILE);
	return BAD_SUB;
    }

    if (grilPtr->key[rowVal][colVal] != GRILLE_BLANK) {
	valid_sub = ALT_SUB;
    }

    if (orientation == 0) {
	/*
	 * This is the default.
	 */
    } else if (orientation == 1) {
	tempVal = rowVal;
	rowVal = (period-1) - colVal;
	colVal = tempVal;
    } else if (orientation == 2) {
	rowVal = (period-1) - rowVal;
	colVal = (period-1) - colVal;
    } else if (orientation == 3) {
	tempVal = rowVal;
	rowVal = colVal;
	colVal = (period-1) - tempVal;
    }

    if (grilPtr->key[rowVal][colVal] == GRILLE_FIRST) {
	    grilPtr->key[rowVal][colVal] = GRILLE_BLANK;
	    grilPtr->key[colVal][(period-1)-rowVal] = GRILLE_BLANK;
	    grilPtr->key[(period-1)-rowVal][(period-1)-colVal] = GRILLE_BLANK;
	    grilPtr->key[(period-1)-colVal][rowVal] = GRILLE_BLANK;
    } else {
	    grilPtr->key[rowVal][colVal] = GRILLE_FIRST;
	    grilPtr->key[colVal][(period-1)-rowVal] = GRILLE_SECOND;
	    grilPtr->key[(period-1)-rowVal][(period-1)-colVal] = GRILLE_THIRD;
	    grilPtr->key[(period-1)-colVal][rowVal] = GRILLE_FOURTH;
    }

    return valid_sub;
}

static char *
GetGrille(Tcl_Interp *interp, CipherItem *itemPtr)
{
    char	*result=(char *)ckalloc(sizeof(char) * itemPtr->length + 1);
    int		i;

    for(i=0; i < itemPtr->length; i++) {
	result[i] = ' ';
    }

    GetStaticGrille(interp, itemPtr, result);

    return result;
}

static char *
GetStaticGrille(Tcl_Interp *interp, CipherItem *itemPtr, char *result)
{
    GrilleItem *grilPtr = (GrilleItem *)itemPtr;
    int		col, row;
    int		period=itemPtr->period;
    int		startPos[4];

    if (itemPtr->length % 2 == 1) {
        startPos[0] = 0;
        startPos[1] = (itemPtr->length - 1) / 4;
        startPos[2] = (itemPtr->length - 1) / 4 * 2;
        startPos[3] = (itemPtr->length - 1) / 4 * 3;
    } else {
        startPos[0] = 0;
        startPos[1] = itemPtr->length / 4;
        startPos[2] = itemPtr->length / 4 * 2;
        startPos[3] = itemPtr->length / 4 * 3;
    }

    for(row=0; row < period; row++) {
	for(col=0; col < period; col++) {
	    int keyVal = grilPtr->key[row][col];

	    if (keyVal != GRILLE_BLANK) {
		keyVal--;
		if (startPos[keyVal] > itemPtr->length) {
		    fprintf(stderr, "Fatal indexing error! %s: line %d\n",
			    __FILE__, __LINE__);
		    abort();
		}
		result[startPos[keyVal]] = itemPtr->ciphertext[row*period+col];
		startPos[keyVal]++;
	    }
	}
    }

    /* Grille ciphers with an odd width use the center space as the
     * last letter in the ciphertext.
     */
    if (itemPtr->length % 2 == 1) {
        result[itemPtr->length - 1]
                = itemPtr->ciphertext[(int) itemPtr->length / 2];
    }

    result[itemPtr->length] = '\0';

    return result;
}

static int
RestoreGrille(Tcl_Interp *interp, CipherItem *itemPtr, const char *key, const char *dummy)
{
    GrilleItem *grilPtr = (GrilleItem *)itemPtr;
    int		i;
    int		j;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp,
		"Can't do anything until ciphertext has been set",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (strlen(key) != itemPtr->period*itemPtr->period) {
	Tcl_SetResult(interp,
		"Key length must match the ciphertext length",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    for(i=0; i < strlen(key); i++) {
	if (key[i]-'0' != GRILLE_BLANK &&
		key[i]-'0' != GRILLE_FIRST &&
		key[i]-'0' != GRILLE_SECOND &&
		key[i]-'0' != GRILLE_THIRD &&
		key[i]-'0' != GRILLE_FOURTH) {
	    Tcl_SetResult(interp,
		    "Invalid character found in key",
		    TCL_VOLATILE);
	    return TCL_ERROR;
	}
    }

    /*
     * Clear the key
     */

    for(i=0; i < itemPtr->period; i++) {
	for(j=0; j < itemPtr->period; j++) {
	    grilPtr->key[i][j] = GRILLE_BLANK;
	}
    }

    /*
     * Perform substitutions wherever we see a hole in the key
     */

    for(i=0; i < itemPtr->period; i++) {
	for(j=0; j < itemPtr->period; j++) {
	    int keyVal = key[i*itemPtr->period+j];
	    keyVal -= '0';

	    if (keyVal == 1) {
		if (GrilleIntSubstitute(interp, itemPtr, i, j, 0) == BAD_SUB) {
		    Tcl_SetResult(interp, "Bad key detected during restore",
			    TCL_VOLATILE);
		    return TCL_ERROR;
		}
	    }
	}
    }

    return TCL_OK;
}

static int
SolveGrille(Tcl_Interp *interp, CipherItem *itemPtr, char *maxkey)
{
    GrilleItem	*grilPtr = (GrilleItem *)itemPtr;
    char	*baseKey=(char *)NULL;
    int		i, j;
    char	*tempPt = (char *)NULL;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp,
		"Can't do anything until ciphertext has been set",
		TCL_STATIC);
	return TCL_ERROR;
    }

    tempPt = (char *)ckalloc(sizeof(char) * itemPtr->length + 1);
    for(i=0; i < itemPtr->length; i++) {
	tempPt[i] = ' ';
    }
    tempPt[itemPtr->length] = '\0';

    baseKey = (char *)ckalloc(sizeof(char) * itemPtr->length / 4);
    itemPtr->curIteration = 0;
    grilPtr->maxSolVal = 0.0;
    grilPtr->maxKey = (char **)ckalloc(sizeof(char *) * itemPtr->period);
    for(i=0; i < itemPtr->period; i++) {
	grilPtr->maxKey[i] = (char *)ckalloc(sizeof(char) * itemPtr->period);
	for(j=0; j < itemPtr->period; j++) {
	    grilPtr->maxKey[i][j] = GRILLE_BLANK;
	}
    }

    if (RecSolveGrille(interp, itemPtr, baseKey, tempPt, 0) != TCL_OK) {
	ckfree(tempPt);
	ckfree(baseKey);
	return TCL_ERROR;
    }

    /*
     * Copy the best key found into the item's key
     */

    for(i=0; i < itemPtr->period; i++) {
	for(j=0; j < itemPtr->period; j++) {
	    maxkey[i*itemPtr->period+j] = grilPtr->maxKey[i][j];
	    grilPtr->key[i][j] = grilPtr->maxKey[i][j];
	}
    }

    for(i=0; i < itemPtr->period; i++) {
	ckfree(grilPtr->maxKey[i]);
    }
    ckfree((char *)grilPtr->maxKey);
    grilPtr->maxKey = (char **)NULL;
    if (tempPt) {
	ckfree(tempPt);
    }
    if (baseKey) {
	ckfree(baseKey);
    }

    return TCL_OK;
}

static int
RecSolveGrille(Tcl_Interp *interp, CipherItem *itemPtr, char *baseKey, char *pt, int index)
{
    GrilleItem	*grilPtr = (GrilleItem *)itemPtr;
    int i;

    if (index >= itemPtr->length/4) {
	double ptValue=0.0;
	int row;
	int col;

	GetStaticGrille(interp, itemPtr, pt);
	if (DefaultScoreValue(interp, pt, &ptValue)
                != TCL_OK) {
	    return TCL_ERROR;
	}
	itemPtr->curIteration++;

	if (pt && itemPtr->stepInterval && itemPtr->stepCommand && itemPtr->curIteration%itemPtr->stepInterval == 0) {
	    Tcl_DString dsPtr;
	    char temp_str[128];

	    Tcl_DStringInit(&dsPtr);

	    Tcl_DStringAppendElement(&dsPtr, itemPtr->stepCommand);

	    sprintf(temp_str, "%ld", itemPtr->curIteration);
	    Tcl_DStringAppendElement(&dsPtr, temp_str);

	    Tcl_DStringStartSublist(&dsPtr);

	    for(i=0; i < itemPtr->length / 4; i++) {
		sprintf(temp_str, "%c", baseKey[i]+'0');
		Tcl_DStringAppendElement(&dsPtr, temp_str);
	    }
	    /*
	     * This prints the entire key.  It's a little too verbose for
	     * normal use.
	    for(row=0; row < itemPtr->period; row++) {
		for(col=0; col < itemPtr->period; col++) {
		    sprintf(temp_str, "%c", 
			    grilPtr->key[row][col]+'0');
		    Tcl_DStringAppendElement(&dsPtr, temp_str);
		}
	    }
	    */
	    Tcl_DStringEndSublist(&dsPtr);

	    Tcl_DStringAppendElement(&dsPtr, pt);

	    if (Tcl_Eval(interp, Tcl_DStringValue(&dsPtr)) != TCL_OK) {
		Tcl_ResetResult(interp);
		Tcl_AppendResult(interp, "Bad command usage:  ", Tcl_DStringValue(&dsPtr), (char *)NULL);
		Tcl_DStringFree(&dsPtr);
		return TCL_ERROR;
	    }
	    Tcl_DStringFree(&dsPtr);
	}

	if (ptValue > grilPtr->maxSolVal) {
	    Tcl_DString dsPtr;
	    char temp_str[128];

	    Tcl_DStringInit(&dsPtr);

	    if (itemPtr->bestFitCommand) {
		Tcl_DStringAppendElement(&dsPtr, itemPtr->bestFitCommand);
	    }

	    sprintf(temp_str, "%ld", itemPtr->curIteration);
	    Tcl_DStringAppendElement(&dsPtr, temp_str);

	    grilPtr->maxSolVal = ptValue;
	    for(row=0; row < itemPtr->period; row++) {
		for(col=0; col < itemPtr->period; col++) {
		    grilPtr->maxKey[row][col] = grilPtr->key[row][col];
		}
	    }

	    Tcl_DStringStartSublist(&dsPtr);
	    for(i=0; i < itemPtr->length / 4; i++) {
		sprintf(temp_str, "%c", baseKey[i]+'0');
		Tcl_DStringAppendElement(&dsPtr, temp_str);
	    }
	    /*
	    for(row=0; row < itemPtr->period; row++) {
		for(col=0; col < itemPtr->period; col++) {
		    sprintf(temp_str, "%c", 
			    grilPtr->key[row][col]+'0');
		    Tcl_DStringAppendElement(&dsPtr, temp_str);
		}
	    }
	    */
	    Tcl_DStringEndSublist(&dsPtr);

	    sprintf(temp_str, "%g", ptValue);
	    Tcl_DStringAppendElement(&dsPtr, temp_str);

	    Tcl_DStringAppendElement(&dsPtr, pt);

	    if (itemPtr->bestFitCommand) {
		if (Tcl_Eval(interp, Tcl_DStringValue(&dsPtr)) != TCL_OK) {
		    Tcl_ResetResult(interp);
		    Tcl_AppendResult(interp, "Bad command usage:  ", Tcl_DStringValue(&dsPtr), (char *)NULL);

		    Tcl_DStringFree(&dsPtr);
		    return TCL_ERROR;
		}
	    }

	    Tcl_DStringFree(&dsPtr);
	}

	/*
	if (pt) {
	    ckfree(pt);
	}
	*/

	return TCL_OK;
    } else {
	int baseRow;
	int baseCol;
	int period=itemPtr->period;

	baseRow=index/(period/2);
	baseCol=index%(period/2);

	baseKey[index] = GRILLE_FIRST;
	grilPtr->key[baseRow][baseCol] = GRILLE_FIRST;
	grilPtr->key[baseCol][(period-1)-baseRow] = GRILLE_SECOND;
	grilPtr->key[(period-1)-baseRow][(period-1)-baseCol] = GRILLE_THIRD;
	grilPtr->key[(period-1)-baseCol][baseRow] = GRILLE_FOURTH;
	if (RecSolveGrille(interp, itemPtr, baseKey, pt, index+1) != TCL_OK) {
	    return TCL_ERROR;
	}

	baseKey[index] = GRILLE_SECOND;
	grilPtr->key[baseRow][baseCol] = GRILLE_SECOND;
	grilPtr->key[baseCol][(period-1)-baseRow] = GRILLE_THIRD;
	grilPtr->key[(period-1)-baseRow][(period-1)-baseCol] = GRILLE_FOURTH;
	grilPtr->key[(period-1)-baseCol][baseRow] = GRILLE_FIRST;
	if (RecSolveGrille(interp, itemPtr, baseKey, pt, index+1) != TCL_OK) {
	    return TCL_ERROR;
	}

	baseKey[index] = GRILLE_THIRD;
	grilPtr->key[baseRow][baseCol] = GRILLE_THIRD;
	grilPtr->key[baseCol][(period-1)-baseRow] = GRILLE_FOURTH;
	grilPtr->key[(period-1)-baseRow][(period-1)-baseCol] = GRILLE_FIRST;
	grilPtr->key[(period-1)-baseCol][baseRow] = GRILLE_SECOND;
	if (RecSolveGrille(interp, itemPtr, baseKey, pt, index+1) != TCL_OK) {
	    return TCL_ERROR;
	}

	baseKey[index] = GRILLE_FOURTH;
	grilPtr->key[baseRow][baseCol] = GRILLE_FOURTH;
	grilPtr->key[baseCol][(period-1)-baseRow] = GRILLE_FIRST;
	grilPtr->key[(period-1)-baseRow][(period-1)-baseCol] = GRILLE_SECOND;
	grilPtr->key[(period-1)-baseCol][baseRow] = GRILLE_THIRD;
	if (RecSolveGrille(interp, itemPtr, baseKey, pt, index+1) != TCL_OK) {
	    return TCL_ERROR;
	}
    }

    return TCL_OK;
}

static int
GrilleLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, char *tip, char *start)
{
    Tcl_SetResult(interp, "No locate tip function defined for Grille ciphers.",
	    TCL_VOLATILE);
    return TCL_ERROR;
}

int
GrilleCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    GrilleItem *grilPtr = (GrilleItem *)clientData;
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
	    sprintf(temp_str, "%d", grilPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", itemPtr->period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!grilPtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_VOLATILE);
	    } else {
		Tcl_SetResult(interp, grilPtr->header.ciphertext, TCL_VOLATILE);
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ptblock", 8) == 0) {
	    Tcl_DString dsPtr;
	    int		row;
	    int		col;

	    if (itemPtr->length == 0) {
		Tcl_SetResult(interp,
			"Can't do anything until ciphertext has been set",
			TCL_VOLATILE);
		return TCL_ERROR;
	    }

	    Tcl_DStringInit(&dsPtr);

	    /*
	     * Loop from GRILLE_FIRST to GRILLE_FOURTH to get all of the
	     * plaintext blocks.
	     */

	    for(i=1; i <= 4; i++) {
		for(row=0; row < itemPtr->period; row++) {
		    for(col=0; col < itemPtr->period; col++) {
			if (grilPtr->key[row][col] == i) {
			    temp_str[row*itemPtr->period+col] = 
				itemPtr->ciphertext[row*itemPtr->period+col];
			} else {
			    temp_str[row*itemPtr->period+col] = ' ';
			}
		    }
		}
		temp_str[itemPtr->length] = '\0';
		Tcl_DStringAppendElement(&dsPtr, temp_str);
	    }
	    Tcl_DStringResult(interp, &dsPtr);
	    Tcl_DStringFree(&dsPtr);
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
	    int row;
	    int col;

	    for(row=0; row < itemPtr->period; row++) {
		for(col=0; col < itemPtr->period; col++) {
		    temp_str[row*itemPtr->period + col] =
			    grilPtr->key[row][col] + '0';
		}
	    }
	    temp_str[itemPtr->length] = '\0';

	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);

	    return TCL_OK;
	} else if (strncmp(argv[1], "-type", 5) == 0) {
	    Tcl_SetResult(interp, itemPtr->typePtr->type, TCL_STATIC);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 7) == 0) {
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
	    if (strncmp(*argv, "-period", 7) == 0) {
		/*
		 * Silently ignore any attempts to set the period
		 */

		Tcl_SetResult(interp, "", TCL_VOLATILE);
		return TCL_OK;
	    } else if (strncmp(*argv, "-ciphertext", 10) == 0 ||
		strncmp(*argv, "-ctext", 3) == 0) {
		if ((itemPtr->typePtr->setctProc)(interp, itemPtr, argv[1]) != TCL_OK) {
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
    } else if (**argv == 's' && (strncmp(*argv, "substitute", 3) == 0)) {
	int orientation = 1;
	if (argc != 3 && argc != 4) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd,
		    " substitute row col ?orientation?", (char *)NULL);
	    return TCL_ERROR;
	}
	if (argc == 4) {
	    if (sscanf(argv[3], "%d", &orientation) != 1) {
		Tcl_AppendResult(interp, "Invalid orientation ", argv[3],
		       (char *)NULL, TCL_VOLATILE);
		return TCL_ERROR;
	    }
	}

	if ((itemPtr->typePtr->subProc)(interp, itemPtr, argv[1],
		argv[2], orientation) == BAD_SUB) {
	    return TCL_ERROR;
	} else {
	    return TCL_OK;
	}
    } else if (**argv == 'r' && (strncmp(*argv, "restore", 7) == 0)) {
	if (argc != 2 && argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd,
		    " restore key ?junk?", (char *)NULL);
	    return TCL_ERROR;
	}
	return (itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1],
		(char *)NULL);
    } else if (**argv == 'u' && (strncmp(*argv, "undo", 7) == 0)) {
	if (argc != 1) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " undo", (char *)NULL);
	    return TCL_ERROR;
	}
	return (itemPtr->typePtr->undoProc)(interp, itemPtr, (char *)NULL, 0);
    } else if (**argv == 's' && (strncmp(*argv, "solve", 5) == 0)) {
	if (argc != 1) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " solve", (char *)NULL);
	    return TCL_ERROR;
	}
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
			" substitute row col", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" undo", (char *)NULL);
	return TCL_ERROR;
    }

    return TCL_OK;
}

#undef STANDARD
#undef INVERSE
