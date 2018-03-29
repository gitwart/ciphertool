/*
 * phillips.c --
 *
 *	This file implements the phillips cipher type.
 *
 * Copyright (c) 1998-2005 Michael Thomas <wart@kobold.org>
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

#define PERIOD 5
#define DEFAULT_NUM_BLOCKS 8
#define MAX_NUM_BLOCKS 20

static int  CreatePhillips	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
void DeletePhillips		_ANSI_ARGS_((ClientData));
static char *GetPhillips	_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetPhillips		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestorePhillips	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolvePhillips	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
int PhillipsCmd			_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));
static int PhillipsUndo		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int PhillipsSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int PhillipsLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int PhillipsSwapCols	_ANSI_ARGS_((Tcl_Interp *, CipherItem *, int,
	    			int));
static int EncodePhillips	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static char *PhillipsTransform	_ANSI_ARGS_((CipherItem *, const char *, int));

typedef struct PhillipsItem {
    CipherItem header;

    /*
     * The key for a phillips cipher is the keyblock for the first square.
     * We derive the other 7 squares only when needed, ie, when we need
     * to extract the plaintext.
     */
    char key[PERIOD][PERIOD];
    char keyValPos[PERIOD*PERIOD+1];

    int numBlocks;

    char *pt;

    char **maxSolKey;
    int maxSolVal;
} PhillipsItem;

CipherType PhillipsType = {
    "phillips",
    ATOZ,
    sizeof(PhillipsItem),
    CreatePhillips,	/* create proc */
    DeletePhillips,	/* delete proc */
    PhillipsCmd,	/* cipher command proc */
    GetPhillips,	/* get plaintext proc */
    SetPhillips,	/* show ciphertext proc */
    SolvePhillips,	/* solve cipher proc */
    RestorePhillips,	/* restore proc */
    PhillipsLocateTip,	/* locate proc */
    PhillipsSubstitute,	/* sub proc */
    PhillipsUndo,	/* undo proc */
    EncodePhillips,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

static int
CreatePhillips(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    PhillipsItem *philPtr = (PhillipsItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;
    int		j;

    philPtr->header.period = 0;
    philPtr->maxSolVal = 0;
    philPtr->maxSolKey = (char **)NULL;
    philPtr->numBlocks = DEFAULT_NUM_BLOCKS;
    philPtr->pt = (char *)NULL;
    for(i=0; i < PERIOD; i++) {
	for(j=0; j < PERIOD; j++) {
	    philPtr->key[i][j] = '\0';
	}
    }
    for(i=0; i < 26; i++) {
	philPtr->keyValPos[i] = 0;
    }

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, PhillipsCmd, itemPtr,
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
DeletePhillips(ClientData clientData)
{
    PhillipsItem *philPtr = (PhillipsItem *)clientData;

    if (philPtr->pt != NULL) {
	ckfree(philPtr->pt);
    }

    DeleteCipher(clientData);
}

static int
SetPhillips(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
{
    PhillipsItem *philPtr = (PhillipsItem *)itemPtr;
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

	if (philPtr->pt) {
	    ckfree(philPtr->pt);
	}
	philPtr->pt = (char *)ckalloc(sizeof(char) * length + 1);

	if (itemPtr->ciphertext == NULL || philPtr->pt == NULL) {
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
PhillipsUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int offset)
{
    PhillipsItem *philPtr = (PhillipsItem *)itemPtr;
    int i, j;

    if (! ct) {
	for(i=0; i < PERIOD; i++) {
	    for(j=0; j < PERIOD; j++) {
		philPtr->key[i][j] = '\0';
	    }
	}
	for(i=0; i < 26; i++) {
	    philPtr->keyValPos[i] = 0;
	}
    } else {
	while (*ct) {
	    int keyVal;

	    if (*ct < 'a' || *ct > 'z') {
		Tcl_SetResult(interp, "Invalid key value", TCL_VOLATILE);
		return TCL_ERROR;
	    }

	    keyVal = philPtr->keyValPos[*ct-'a'];

	    if (keyVal) {
		keyVal--;
		philPtr->key[keyVal/PERIOD][keyVal%PERIOD]='\0';
	    }

	    ct++;
	}
    }

    return TCL_OK;
}

static int
PhillipsSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, const char *pt, int offset)
{
    PhillipsItem *philPtr = (PhillipsItem *)itemPtr;
    int row, col;

    /*
     * pt == row
     * ct == col
     * offset == val
     */

    row = *ct - '1';
    col = *pt - '1';

    if (row < 0 || row >= PERIOD) {
	Tcl_SetResult(interp, "Invalid row specification", TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (col < 0 || col >= PERIOD) {
	Tcl_SetResult(interp, "Invalid column specification", TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (offset < 'a' || offset > 'z') {
	Tcl_SetResult(interp, "Invalid key value", TCL_VOLATILE);
	return TCL_ERROR;
    }

    philPtr->key[row][col] = offset;
    philPtr->keyValPos[offset-'a'] = row*PERIOD+col+1;

    return TCL_OK;
}

static char *
GetPhillips(Tcl_Interp *interp, CipherItem *itemPtr)
{
    if (itemPtr->length == 0) {
	Tcl_SetResult(interp, "Can't do anything until ciphertext has been set",
		TCL_STATIC);
	return (char *)NULL;
    }

    return PhillipsTransform(itemPtr, itemPtr->ciphertext, DECODE);
}

/*
 * Encode/decode a phillips cipher.  The memory for the result string
 * is managed by the cipher, so don't try to free it yourself!
 */
static char *
PhillipsTransform(CipherItem *itemPtr, const char *text, int mode) {
    PhillipsItem *philPtr = (PhillipsItem *)itemPtr;
    int		i;
    int keyRowToBlock[20][5] = {{0, 1, 2, 3, 4},
			       {1, 0, 2, 3, 4},
			       {2, 0, 1, 3, 4},
			       {3, 0, 1, 2, 4},
			       {4, 0, 1, 2, 3},
			       {4, 1, 0, 2, 3},
			       {4, 2, 0, 1, 3},
			       {4, 3, 0, 1, 2},
			       {3, 4, 0, 1, 2},
			       {3, 4, 1, 0, 2},
			       {3, 4, 2, 0, 1},
			       {2, 4, 3, 0, 1},
			       {2, 3, 4, 0, 1},
			       {2, 3, 4, 1, 0},
			       {1, 3, 4, 2, 0},
			       {1, 2, 4, 3, 0},
			       {1, 2, 3, 4, 0},
			       {0, 2, 3, 4, 1},
			       {0, 1, 3, 4, 2},
			       {0, 1, 2, 4, 3}};

    int blockRowToKey[20][5] = {{0, 1, 2, 3, 4},
			        {1, 0, 2, 3, 4},
			        {1, 2, 0, 3, 4},
			        {1, 2, 3, 0, 4},
			        {1, 2, 3, 4, 0},
			        {2, 1, 3, 4, 0},
			        {2, 3, 1, 4, 0},
			        {2, 3, 4, 1, 0},
			        {2, 3, 4, 0, 1},
			        {3, 2, 4, 0, 1},
			        {3, 4, 2, 0, 1},
			        {3, 4, 0, 2, 1},
			        {3, 4, 0, 1, 2},
			        {4, 3, 0, 1, 2},
			        {4, 0, 3, 1, 2},
			        {4, 0, 1, 3, 2},
			        {4, 0, 1, 2, 3},
			        {0, 4, 1, 2, 3},
			        {0, 1, 4, 2, 3},
			        {0, 1, 2, 4, 3}};


    for(i=0; i < itemPtr->length; i++) {
	char	ct = text[i];
	char	pt = ' ';
	int	block = 0;
	int	keyPos = philPtr->keyValPos[ct-'a'];
	int	ctKeyCol;
	int	ptKeyCol;
	int	ctKeyRow;
	int	ptKeyRow;
	int	ctBlockRow;
	int	ptBlockRow;

	if (keyPos) {
	    block = (i/5)%philPtr->numBlocks;
	    keyPos--;
	    ctKeyCol = keyPos%5;
	    ctKeyRow = keyPos/5;

	    if (mode == DECODE) {
		ptKeyCol = ctKeyCol - 1;
		if (ptKeyCol < 0) {
		    ptKeyCol = 4;
		}
	    } else {
		ptKeyCol = ctKeyCol + 1;
		if (ptKeyCol > 4) {
		    ptKeyCol = 0;
		}
	    }

	    ctBlockRow = keyRowToBlock[block][ctKeyRow];

	    if (mode == DECODE) {
		ptBlockRow = ctBlockRow - 1;
		if (ptBlockRow < 0) {
		    ptBlockRow = 4;
		}
	    } else {
		ptBlockRow = ctBlockRow + 1;
		if (ptBlockRow > 4) {
		    ptBlockRow = 0;
		}
	    }
	    ptKeyRow = blockRowToKey[block][ptBlockRow];

	    pt = philPtr->key[ptKeyRow][ptKeyCol];
	    if (!pt) {
		pt = ' ';
	    }
	}

	philPtr->pt[i] = pt;
    }
    philPtr->pt[itemPtr->length] = '\0';

    return philPtr->pt;
}

static int
RestorePhillips(Tcl_Interp *interp, CipherItem *itemPtr, const char *key, const char *dummy)
{
    PhillipsItem *philPtr = (PhillipsItem *)itemPtr;
    int i;
    int row;
    int col;

    if (itemPtr->length <= 0) {
	Tcl_SetResult(interp, "Can't do anything until ciphertext has been set",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (strlen(key) != PERIOD * PERIOD) {
	Tcl_SetResult(interp, "Invalid key length.", TCL_VOLATILE);
	return TCL_ERROR;
    }

    for(i=0; i < PERIOD*PERIOD; i++) {
	philPtr->keyValPos[i] = 0;
    }

    for(i=0; i < PERIOD*PERIOD; i++) {
	if ( (key[i] < 'a' || key[i] > 'z') && (key[i] != ' ')) {
	    Tcl_SetResult(interp, "Invalid character in key", TCL_VOLATILE);
	    return TCL_ERROR;
	}
	row = i / PERIOD;
	col = i % PERIOD;

	if (key[i] == ' ') {
	    philPtr->key[row][col] = '\0';
	} else {
	    philPtr->key[row][col] = key[i];
	    philPtr->keyValPos[key[i]-'a'] = i+1;
	}
    }

    return TCL_OK;
}

static int
SolvePhillips(Tcl_Interp *interp, CipherItem *itemPtr, char *maxkey)
{
    Tcl_SetResult(interp, "Solving phillips ciphers is not yet implemented.",
	    TCL_VOLATILE);
    return TCL_ERROR;
}

static int
PhillipsLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, const char *tip, const char *start)
{
    Tcl_SetResult(interp,
	    "No locate tip function defined for phillips ciphers.",
	    TCL_VOLATILE);
    return TCL_ERROR;
}

static int
PhillipsSwapCols(Tcl_Interp *interp, CipherItem *itemPtr, int col1, int col2)
{
    PhillipsItem *philPtr = (PhillipsItem *)itemPtr;
    int i, tempCol, row, col;

    if (col1 < 1 || col2 < 1 || col1 > PERIOD || col2 > PERIOD) {
	Tcl_SetResult(interp, "Invalid column in phillips swap", TCL_VOLATILE);
	return TCL_ERROR;
    }

    col1--;
    col2--;

    for(i=0; i < PERIOD; i++) {
	tempCol = philPtr->key[i][col1];
	philPtr->key[i][col1] = philPtr->key[i][col2];
	philPtr->key[i][col2] = tempCol;
    }

    for(i=0; i < 26; i++) {
	philPtr->keyValPos[i] = 0;
    }

    for(row=0; row < PERIOD; row++) {
	for(col=0; col < PERIOD; col++) {
	    int keyPos = row*PERIOD+col;

	    if (philPtr->key[keyPos]) {
		philPtr->keyValPos[philPtr->key[row][col]-'a'] = keyPos+1;
	    }
	}
    }

    return TCL_OK;
}

int
PhillipsCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    PhillipsItem *philPtr = (PhillipsItem *)clientData;
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
	    sprintf(temp_str, "%d", philPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", PERIOD);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-blocks", 6) == 0) {
	    sprintf(temp_str, "%d", philPtr->numBlocks);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!philPtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_VOLATILE);
	    } else {
		Tcl_SetResult(interp, philPtr->header.ciphertext, TCL_VOLATILE);
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
	    for(i=0; i < PERIOD; i++) {
		int j;
		for(j=0; j < PERIOD; j++) {
		    if (philPtr->key[i][j]) {
			temp_str[j+i*PERIOD] = philPtr->key[i][j];
		    } else {
			temp_str[j+i*PERIOD] = ' ';
		    }
		}
	    }
	    temp_str[PERIOD*PERIOD] = '\0';
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
	    } else if (strncmp(*argv, "-blocks", 7) == 0) {
		if (sscanf(argv[1], "%d", &i) != 1) {
		    Tcl_AppendResult(interp,
                            "Bad number of blocks.  Integer expected:  ",
			    argv[1], (char *)NULL);
		    return TCL_ERROR;
		}
		if (i <= 0 || i > MAX_NUM_BLOCKS) {
		    Tcl_AppendResult(interp,
                            "Number of phillips blocks must be between 1 and 20.  found:  ",
			    argv[1], (char *)NULL);
		    return TCL_ERROR;
		}
                philPtr->numBlocks = i;
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
    } else if (**argv == 'e' && (strncmp(*argv, "encode", 1) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " encode pt key",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	return (itemPtr->typePtr->encodeProc)(interp, itemPtr, argv[1], argv[2]);
    } else if (**argv == 's' && (strncmp(*argv, "swap", 4) == 0)) {
	int col1, col2;

	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd,
		    " swap col1 col2", (char *)NULL);
	    return TCL_ERROR;
	} else {
	    if (sscanf(argv[1], "%d", &col1) != 1) {
		Tcl_SetResult(interp,
			"Invalid column value.  Value must be between 1 and 5.",
			TCL_VOLATILE);
		return TCL_ERROR;
	    }
	    if (sscanf(argv[2], "%d", &col2) != 1) {
		Tcl_SetResult(interp,
			"Invalid column value.  Value must be between 1 and 5.",
			TCL_VOLATILE);
		return TCL_ERROR;
	    }
	}

	return PhillipsSwapCols(interp, itemPtr, col1, col2);
    } else if (**argv == 'l' && (strncmp(*argv, "locate", 3) == 0)) {
	Tcl_SetResult(interp,
		"No locate tip function defined for phillips ciphers.",
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
	if (argc != 2 && argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd,
		    " restore key ?junk?", (char *)NULL);
	    return TCL_ERROR;
	}
	return (itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1],
		(char *)NULL);
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
EncodePhillips(Tcl_Interp *interp, CipherItem *itemPtr, const char *pt, const char *key) {
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

    if (strlen(argv[0]) != 25) {
	Tcl_SetResult(interp, "Invalid length of key.", TCL_STATIC);
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
    ct = PhillipsTransform(itemPtr, itemPtr->ciphertext, ENCODE);
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

#undef PERIOD
