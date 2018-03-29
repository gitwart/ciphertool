/*
 * nitrams.c --
 *
 *	This file implements the nihilist transposition  cipher type.
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
#include <math.h>
#include <perm.h>

#include <cipherDebug.h>

static int  CreateNitrans	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
void DeleteNitrans		_ANSI_ARGS_((ClientData));
static char *GetNitrans		_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetNitrans		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestoreNitrans	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolveNitrans	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
int NitransCmd			_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));
static int NitransUndo		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static void NitransInitKey	_ANSI_ARGS_((CipherItem *));
static int NitransSwapVals	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
	    			int, int));
int NitransCheckSolutionValue  _ANSI_ARGS_((Tcl_Interp *, ClientData,
	    			int *, int));
static int NitransShiftColumn	_ANSI_ARGS_((Tcl_Interp *, CipherItem *, int,
	    			int));
static int EncodeNitrans	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static char *NitransTransform	_ANSI_ARGS_((CipherItem *, const char *, int));

#define VERTICAL	1
#define HORIZONTAL	2

typedef struct NitransItem {
    CipherItem header;

    char *key;		/* Nitrans used to write in the orignal plaintext */
    char *maxKey;	/* Nitrans used to write in the orignal plaintext */

    double maxVal;

    int readDir;
} NitransItem;

CipherType NitransType = {
    "nitrans",
    "abcdefghijklmnopqrstuvwxyz-0123456789",
    sizeof(NitransItem),
    CreateNitrans,	/* create proc */
    DeleteNitrans,	/* delete proc */
    NitransCmd,		/* cipher command proc */
    GetNitrans,		/* get plaintext proc */
    SetNitrans,		/* show ciphertext proc */
    SolveNitrans,	/* solve cipher proc */
    RestoreNitrans,	/* restore proc */
    (LocateTipProc *)NULL,	/* locate proc */
    (SubstituteProc *)NULL,	/* sub proc */
    NitransUndo,	/* undo proc */
    EncodeNitrans,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

static int
CreateNitrans(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    NitransItem *nitransPtr = (NitransItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    nitransPtr->header.period = 0;
    nitransPtr->key = (char *)NULL;
    nitransPtr->maxKey = (char *)NULL;
    nitransPtr->maxVal = 0.0;
    nitransPtr->readDir = VERTICAL;

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, NitransCmd, itemPtr,
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
DeleteNitrans(ClientData clientData)
{
    NitransItem *nitransPtr = (NitransItem *)clientData;

    if (nitransPtr->key != NULL) {
	ckfree(nitransPtr->key);
    }

    DeleteCipher(clientData);
}

static int
SetNitrans(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
{
    char	*c;
    int		valid = TCL_OK,
    		width = 0,
    		length=0;

    length = CountValidChars(itemPtr, ctext);
    c = ExtractValidChars(itemPtr, ctext);

    if (!c) {
	Tcl_SetResult(interp, "No valid characters found in ciphertext",
		TCL_STATIC);
	return TCL_ERROR;
    }

    width = sqrt(length);
    if (width * width != length) {
	ckfree(c);

	Tcl_SetResult(interp,
		"Invalid cipher length.  Length must be a perfect square.",
		TCL_STATIC);
	return TCL_ERROR;
    }

    valid = TCL_OK;

    if (valid==TCL_OK) {
	if (itemPtr->ciphertext) {
	    ckfree(itemPtr->ciphertext);
	}
	itemPtr->ciphertext = c;

	if (itemPtr->ciphertext == NULL) {
	    Tcl_SetResult(interp,
		    "Error mallocing memory for new cipher",
		    TCL_STATIC);
	    return TCL_ERROR;
	}

	itemPtr->length = length;
	itemPtr->period = width;

	NitransInitKey(itemPtr);

	Tcl_SetResult(interp, itemPtr->ciphertext, TCL_STATIC);
    }

    return valid;
}

static int
NitransUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int offset)
{
    NitransInitKey(itemPtr);
    return TCL_OK;
}

static void
NitransInitKey(CipherItem *itemPtr)
{
    NitransItem *nitransPtr = (NitransItem *)itemPtr;
    int i;

    if (nitransPtr->key) {
	ckfree(nitransPtr->key);
    }
    nitransPtr->key = (char *)NULL;

    if (itemPtr->period) {
	nitransPtr->key = (char *)ckalloc(sizeof(char) * itemPtr->period);

	for(i=0; i < itemPtr->period; i++) {
	    nitransPtr->key[i] = i;
	}
    }
}

static int
NitransSwapVals(Tcl_Interp *interp, CipherItem *itemPtr, int val1, int val2)
{
    NitransItem *nitransPtr = (NitransItem *)itemPtr;
    int		i;
    int		tcol1;
    int		tcol2;

    if (itemPtr->period < 1) {
	Tcl_SetResult(interp,
		"Can't swap columns/rows until ciphertext has been set",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (val1 < 0 || val2 < 0 || val1 == val2
	    || val2 >= itemPtr->period || val2 >= itemPtr->period) {
	Tcl_SetResult(interp, "Invalid column", TCL_STATIC);
	return TCL_ERROR;
    }

    for(tcol1 = 0; nitransPtr->key[tcol1] != val1; tcol1++);
    for(tcol2 = 0; nitransPtr->key[tcol2] != val2; tcol2++);

    i = nitransPtr->key[tcol1];
    nitransPtr->key[tcol1] = nitransPtr->key[tcol2];
    nitransPtr->key[tcol2] = i;

    return TCL_OK;
}

static int
NitransShiftColumn(Tcl_Interp *interp, CipherItem *itemPtr, int col, int amount)
{
    NitransItem *nitransPtr = (NitransItem *)itemPtr;
    int i;
    int start=col;
    int tempKeyVal;

    if (itemPtr->ciphertext == (char *)NULL) {
	Tcl_SetResult(interp,
		"Can't do anything until ciphertext has been set",
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
	if (col == nitransPtr->key[i]) {
	    start = i;
	}
    }

    if (start + amount < 0) {
	Tcl_SetResult(interp, "Can't shift backwards past the first column.", TCL_STATIC);
	return TCL_ERROR;
    }

    tempKeyVal = nitransPtr->key[start];
    if (amount < 0) {
	for (i=0; i > amount; i--) {
	    int startIndex = (start + i + itemPtr->period)%itemPtr->period;
	    int endIndex = (start + i - 1 + itemPtr->period)%itemPtr->period;

	    nitransPtr->key[startIndex] = nitransPtr->key[endIndex];
	}
    } else {
	for (i=0; i < amount; i++) {
	    int startIndex = (start + i + itemPtr->period)%itemPtr->period;
	    int endIndex = (start + i + 1 + itemPtr->period)%itemPtr->period;

	    nitransPtr->key[startIndex] = nitransPtr->key[endIndex];
	}
    }

    nitransPtr->key[start+i] = tempKeyVal;

    return TCL_OK;
}

static int
RestoreNitrans(Tcl_Interp *interp, CipherItem *itemPtr, const char *key, const char *dummy)
{
    NitransItem *nitransPtr = (NitransItem *)itemPtr;
    int		i;
    int		j;

    if (itemPtr->ciphertext == (char *)NULL) {
	Tcl_SetResult(interp,
		"Can't do anything until ciphertext has been set",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (strlen(key) != itemPtr->period) {
	Tcl_SetResult(interp, "Length of key does not match period",
		TCL_STATIC);
	return TCL_ERROR;
    }

    for(i=0; i < itemPtr->period; i++) {
	if (key[i] < 'a' || key[i] > 'z') {
	    Tcl_SetResult(interp, "Invalid character in key", TCL_STATIC);
	    return TCL_ERROR;
	}
	if (key[i] >= itemPtr->period + 'a') {
	    Tcl_SetResult(interp, "key character out of range", TCL_STATIC);
	    return TCL_ERROR;
	}
	for(j=0; j < itemPtr->period; j++) {
	    if (key[j] == key[i] && i != j) {
		Tcl_SetResult(interp, "duplicate key characters not allowed",
			TCL_STATIC);
		return TCL_ERROR;
	    }
	}
    }
    for(i=0; i < itemPtr->period; i++) {
	nitransPtr->key[i] = key[i] - 'a';
    }

    return TCL_OK;
}

static char *
GetNitrans(Tcl_Interp *interp, CipherItem *itemPtr)
{
    return NitransTransform(itemPtr, itemPtr->ciphertext, DECODE);
}

static char *
NitransTransform(CipherItem *itemPtr, const char *text, int mode) {
    NitransItem *nitransPtr = (NitransItem *)itemPtr;
    int		i;
    char	*result=(char *)ckalloc(sizeof(char) * itemPtr->length + 1);
    int		newCol, oldCol;
    int		newRow, oldRow;

    for(i=0; i < itemPtr->length; i++) {
	result[i] = '_';
    }

    for(i=0; i < itemPtr->length; i++) {
	if (nitransPtr->readDir == HORIZONTAL) {
	    oldCol = i % itemPtr->period;
	    oldRow = i / itemPtr->period;
	} else {
	    oldCol = i / itemPtr->period;
	    oldRow = i % itemPtr->period;
	}

	for(newCol=0; nitransPtr->key[newCol] != oldCol; newCol++);
	for(newRow=0; nitransPtr->key[newRow] != oldRow; newRow++);

	if (mode == DECODE) {
	    result[newRow * itemPtr->period + newCol] = text[i];
	} else {
	    result[i] = text[newRow * itemPtr->period + newCol];
	}
    }
    result[itemPtr->length] = '\0';

    return result;
}

int
NitransCheckSolutionValue(Tcl_Interp *interp, ClientData clientData, int *key, int keylen)
{
    NitransItem *nitransPtr = (NitransItem *)clientData;
    CipherItem *itemPtr = (CipherItem *)clientData;
    char *pt=(char *)NULL;
    int *tKey=(int *)NULL;
    int i;
    double value;
    Tcl_DString dsPtr;

    if (keylen != nitransPtr->header.period) {
        /*
         * This should never be able to happen.
         */
	Tcl_SetResult(interp, "Key length != period!", TCL_STATIC);
	return TCL_ERROR;
    }

    tKey = (int *)ckalloc(sizeof(int) * keylen);

    for(i=0; i < keylen; i++) {
	tKey[i] = nitransPtr->key[i];
    }

    for(i=0; i < keylen; i++) {
	nitransPtr->key[i] = tKey[key[i]];
    }

    itemPtr->curIteration++;

    pt = GetNitrans(interp, (CipherItem *)nitransPtr);

    if (DefaultScoreValue(interp, pt, &value) != TCL_OK) {
        /* TODO:  Test */
	return TCL_ERROR;
    }

    if ((itemPtr->stepInterval
		&& itemPtr->curIteration % itemPtr->stepInterval == 0
		&& itemPtr->stepCommand && pt)) {
	char temp_str[128];

	Tcl_DStringInit(&dsPtr);

	Tcl_DStringAppendElement(&dsPtr, itemPtr->stepCommand);

	sprintf(temp_str, "%ld", itemPtr->curIteration);
	Tcl_DStringAppendElement(&dsPtr, temp_str);

	Tcl_DStringStartSublist(&dsPtr);
	for(i=0; i < keylen; i++) {
	    sprintf(temp_str, "%d", nitransPtr->key[i]);
	    Tcl_DStringAppendElement(&dsPtr, temp_str);
	}
	Tcl_DStringEndSublist(&dsPtr);

	Tcl_DStringAppendElement(&dsPtr, pt);

	if (Tcl_Eval(interp, Tcl_DStringValue(&dsPtr)) != TCL_OK) {
	    ckfree(pt);
            Tcl_DStringFree(&dsPtr);
	    return TCL_ERROR;
	}
	Tcl_DStringFree(&dsPtr);
    }

    if (value > nitransPtr->maxVal) {
	char temp_str[128];

	nitransPtr->maxVal = value;
	for(i=0; i < keylen; i++) {
	    nitransPtr->maxKey[i] = nitransPtr->key[i];
	}

	if (itemPtr->bestFitCommand) {
            Tcl_DStringInit(&dsPtr);
	    Tcl_DStringAppendElement(&dsPtr, itemPtr->bestFitCommand);

            sprintf(temp_str, "%ld", itemPtr->curIteration);
            Tcl_DStringAppendElement(&dsPtr, temp_str);

            Tcl_DStringStartSublist(&dsPtr);
            for(i=0; i < keylen; i++) {
                sprintf(temp_str, "%d", nitransPtr->maxKey[i]);
                Tcl_DStringAppendElement(&dsPtr, temp_str);
            }
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

    for(i=0; i < keylen; i++) {
	nitransPtr->key[i] = tKey[i];
    }

    ckfree(pt);
    ckfree((char *)tKey);
    return TCL_OK;
}

static int
SolveNitrans(Tcl_Interp *interp, CipherItem *itemPtr, char *maxkey)
{
    NitransItem *nitransPtr = (NitransItem *)itemPtr;
    int i, result;
    char *result_key = (char *)NULL;

    if (itemPtr->ciphertext == (char *)NULL) {
	Tcl_SetResult(interp,
		"Can't do anything until ciphertext has been set",
		TCL_STATIC);
	return TCL_ERROR;
    }

    itemPtr->curIteration = 0;
    nitransPtr->maxVal = 0;
    if (nitransPtr->maxKey) {
	ckfree((char *)nitransPtr->maxKey);
    }

    nitransPtr->maxKey = (char *)ckalloc(sizeof(char)*itemPtr->period);
    result_key = (char *)ckalloc(sizeof(char)*itemPtr->period + 1);

    nitransPtr->readDir = VERTICAL;
    result = _internalDoPermCmd((ClientData)itemPtr,
	    interp, itemPtr->period, NitransCheckSolutionValue);

    /*
     * Now apply the best key
     */

    if (result == TCL_OK) {
	for(i=0; i < itemPtr->period; i++) {
	    nitransPtr->key[i] = nitransPtr->maxKey[i];
            result_key[i] = nitransPtr->key[i] + 'a';
	}
        result_key[i] = '\0';

        Tcl_SetResult(interp, result_key, TCL_DYNAMIC);
    }

    return result;
}

int
NitransCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    NitransItem *nitransPtr = (NitransItem *)clientData;
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
	    sprintf(temp_str, "%d", nitransPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", itemPtr->period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!nitransPtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_STATIC);
	    } else {
		Tcl_SetResult(interp, nitransPtr->header.ciphertext, TCL_VOLATILE);
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ptblock", 8) == 0) {
	    int j;
	    tPtr = (itemPtr->typePtr->decipherProc)(interp, itemPtr);

	    for(i=0; i < itemPtr->period; i++) {
		for(j=0; j < itemPtr->period; j++) {
		    temp_str[j] = tPtr[i*itemPtr->period+j];
		}
		temp_str[itemPtr->period] = '\0';
		Tcl_AppendElement(interp, temp_str);
	    }

	    ckfree(tPtr);

	    return TCL_OK;
	} else if (strncmp(argv[1], "-plaintext", 9) == 0 ||
		   strncmp(argv[1], "-ptext", 3) == 0) {
	    tPtr = (itemPtr->typePtr->decipherProc)(interp, itemPtr);

	    Tcl_SetResult(interp, tPtr, TCL_DYNAMIC);

	    return TCL_OK;
	} else if (strncmp(argv[1], "-key", 4) == 0) {
	    for(i=0; i < itemPtr->period; i++) {
		temp_str[i] = nitransPtr->key[i] + 'a';
            }
	    temp_str[i] = '\0';

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
	} else if (strncmp(argv[1], "-read", 5) == 0) {
            if (nitransPtr->readDir == VERTICAL) {
                Tcl_SetResult(interp, "vertical", TCL_STATIC);
            } else if (nitransPtr->readDir == HORIZONTAL) {
                Tcl_SetResult(interp, "horizontal", TCL_STATIC);
            } else {
                Tcl_SetResult(interp, "Unknown nitrans read direction!", TCL_STATIC);
                return TCL_ERROR;
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
	    if (strncmp(*argv, "-ciphertext", 10) == 0 ||
		strncmp(*argv, "-ctext", 3) == 0) {
		if ((itemPtr->typePtr->setctProc)(interp, itemPtr, argv[1]) != TCL_OK) {
		    return TCL_ERROR;
		}
	    } else if (strncmp(*argv, "-period", 14) == 0) {
		/*
		 * Attempting to set the period of a nitrans cipher is a noop.
                 * This could throw an error, but why bother?
		 */
		return TCL_OK;
	    } else if (strncmp(*argv, "-bestfitcommand", 14) == 0) {
		CipherSetBestFitCmd(itemPtr, argv[1]);
	    } else if (strncmp(*argv, "-stepcommand", 14) == 0) {
		CipherSetStepCmd(itemPtr, argv[1]);
	    } else if (strncmp(*argv, "-stepinterval", 12) == 0) {
		if (sscanf(argv[1], "%d", &i) != 1) {
		    Tcl_SetResult(interp, "Invalid interval.", TCL_STATIC);
		    return TCL_ERROR;
		}

		if (i < 0 ) {
		    Tcl_SetResult(interp, "Invalid interval.", TCL_STATIC);
		    return TCL_ERROR;
		}

		itemPtr->stepInterval = i;
	    } else if (strncmp(*argv, "-read", 5) == 0) {
		if (strncmp(argv[1], "vertical", 4) == 0) {
		    nitransPtr->readDir = VERTICAL;
		} else if (strncmp(argv[1], "horizontal", 5) == 0) {
		    nitransPtr->readDir = HORIZONTAL;
		} else {
		    Tcl_AppendResult(interp, "Invalid direction.  Must be one of vertical or horizontal", (char *)NULL);
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
    } else if (**argv == 'e' && (strncmp(*argv, "encode", 1) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " encode pt key",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	return (itemPtr->typePtr->encodeProc)(interp, itemPtr, argv[1], argv[2]);
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

	if (NitransShiftColumn(interp, itemPtr, col, amount) != TCL_OK) {
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

	if (NitransSwapVals(interp, itemPtr, col1, col2) != TCL_OK) {
	    return TCL_ERROR;
	}
    } else if (**argv == 's' && (strncmp(*argv, "solve", 5) == 0)) {
	if (argc != 1) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " solve",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	return (itemPtr->typePtr->solveProc)(interp, itemPtr, temp_str);
    } else if (**argv == 'u' && (strncmp(*argv, "undo", 5) == 0)) {
	if (argc != 1) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " undo",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	return (itemPtr->typePtr->undoProc)(interp, itemPtr, (char *)NULL,
		0);
    } else if (**argv == 'r' && (strncmp(*argv, "restore", 2) == 0)) {
	if (argc != 2 && argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " restore key",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	return (itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1],
		(char *)NULL);
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
			" shift col amount", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" swap col1 col2", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" undo", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" encode pt key", (char *)NULL);
	return TCL_ERROR;
    }

    return TCL_OK;
}

static int
EncodeNitrans(Tcl_Interp *interp, CipherItem *itemPtr, const char *pt, const char *key) {
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

    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, pt) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    /*
     * The period of a nitrans cipher is set at the same time that the
     * ciphertext is set.  We have to postpone checking the length of the
     * key until after this.
     */
    if (strlen(argv[0]) != itemPtr->period) {
	Tcl_SetResult(interp,
		"Length of key does not match the period.", TCL_STATIC);
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[0], (char *)NULL) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }
    ct = NitransTransform(itemPtr, itemPtr->ciphertext, ENCODE);
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

#undef VERTICAL
#undef HORIZONTAL
