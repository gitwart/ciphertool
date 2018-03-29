/*
 * digrafid.c --
 *
 *	This file implements the digrafid cipher type.
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

#include <cipherDebug.h>

int DigrafidCmd		_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));

#define KEY0	'0'
#define KEY1	'1'
#define KEY2	'2'
#define KEY3	'3'
#define KEY4	'4'
#define KEY5	'5'
#define KEY6	'6'
#define KEY7	'7'
#define KEY8	'8'
#define KEY9	'9'
#define KEYLEN	27
#define EMPTY	-1

#define SQUARE1		0
#define SQUARE2		1

/*
 * Prototypes for procedures only referenced in this file.
 */

static int  CreateDigrafid	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
static char *GetDigrafid	_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetDigrafid	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestoreDigrafid	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolveDigrafid	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
static int DigrafidUndo	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int DigrafidSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int DigrafidLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int DigrafidKeyvalToDigram	_ANSI_ARGS_((CipherItem *, char *,
				char *));
static char *DigrafidLetterToKeyval _ANSI_ARGS_((CipherItem *, char, int));
static int DigrafidKeycharToInt	_ANSI_ARGS_((char));
static int DigrafidKeyPairToIndex	_ANSI_ARGS_((int, int));
static int DigrafidSetPeriod	_ANSI_ARGS_((Tcl_Interp *, CipherItem *, int));
static char *GetDigrafidText	_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int EncodeDigrafid	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));

/*
 * This structure contains the data associated with a single digrafid cipher.
 */

typedef struct DigrafidItem {
    CipherItem header;

    /*
     * The key settings for the first keysquare  The first index for
     * the next two members refers to one of the two keysquares.
     */
    char key[2][27];
    char ptkey[3][KEYLEN+14]; /* The indices are the key values (11, 23, etc.)
			   The values are the letters that the values stand
			   for. */
    char ctkey[3][KEYLEN];/* The indices are the letters, the values are the
			   key values that letters correspond to 
			   (11, 2_, etc).  Note that these need not be
			   full key values, as in the case of '2_'.*/

    char *keyConv[50];	/* Mapping from a unique key index to a row/column
			   pair. */

    char centerSquare[3][3];

} DigrafidItem;

/*
 * This structure joins the data for an digrafid cipher with common routines
 * used to manipulate it.
 */

CipherType DigrafidType = {
    "digrafid",
    "abcdefghijklmnopqrstuvwxyz#",
    sizeof(DigrafidItem),
    CreateDigrafid,	/* create proc */
    DeleteCipher,	/* delete proc */
    DigrafidCmd,	/* cipher command proc */
    GetDigrafid,	/* get plaintext proc */
    SetDigrafid,	/* show ciphertext proc */
    SolveDigrafid,	/* solve cipher proc */
    RestoreDigrafid,	/* restore proc */
    DigrafidLocateTip,	/* locate proc */
    DigrafidSubstitute,	/* sub proc */
    DigrafidUndo,	/* undo proc */
    EncodeDigrafid,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

/*
 * CreateDigrafid --
 *
 *	Create a new digrafid cipher item.
 *
 * Results:
 *
 *	If the cipher could not be created successfully, the routine will
 *	return TCL_ERROR.  Otherwise it will return TCL_OK.
 *
 * Side effects:
 *
 *	Memory is allocated for a new cipher structure.  The structure is
 *	filled in with default values.
 */

static int
CreateDigrafid(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    DigrafidItem *digPtr = (DigrafidItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    digPtr->header.period = 0;

    digPtr->keyConv[0] = "00";
    digPtr->keyConv[1] = "01";
    digPtr->keyConv[2] = "02";
    digPtr->keyConv[3] = "03";
    digPtr->keyConv[4] = "04";
    digPtr->keyConv[5] = "05";
    digPtr->keyConv[6] = "06";
    digPtr->keyConv[7] = "07";
    digPtr->keyConv[8] = "08";
    digPtr->keyConv[9] = "09";
    digPtr->keyConv[10] = "10";
    digPtr->keyConv[11] = "11";
    digPtr->keyConv[12] = "12";
    digPtr->keyConv[13] = "13";
    digPtr->keyConv[14] = "14";
    digPtr->keyConv[15] = "15";
    digPtr->keyConv[16] = "16";
    digPtr->keyConv[17] = "17";
    digPtr->keyConv[18] = "18";
    digPtr->keyConv[19] = "19";
    digPtr->keyConv[20] = "20";
    digPtr->keyConv[21] = "21";
    digPtr->keyConv[22] = "22";
    digPtr->keyConv[23] = "23";
    digPtr->keyConv[24] = "24";
    digPtr->keyConv[25] = "25";
    digPtr->keyConv[26] = "26";
    digPtr->keyConv[27] = "27";
    digPtr->keyConv[28] = "28";
    digPtr->keyConv[29] = "29";
    digPtr->keyConv[30] = "30";
    digPtr->keyConv[31] = "31";
    digPtr->keyConv[32] = "32";
    digPtr->keyConv[33] = "33";
    digPtr->keyConv[34] = "34";
    digPtr->keyConv[35] = "35";
    digPtr->keyConv[36] = "36";
    digPtr->keyConv[37] = "37";
    digPtr->keyConv[38] = "38";
    digPtr->keyConv[39] = "39";
    digPtr->keyConv[40] = "40";
    digPtr->keyConv[41] = "41";
    digPtr->keyConv[42] = "42";
    digPtr->keyConv[43] = "43";
    digPtr->keyConv[44] = "44";
    digPtr->keyConv[45] = "45";
    digPtr->keyConv[46] = "46";
    digPtr->keyConv[47] = "47";
    digPtr->keyConv[48] = "48";
    digPtr->keyConv[49] = "49";

    digPtr->centerSquare[0][0] = '1';
    digPtr->centerSquare[0][1] = '2';
    digPtr->centerSquare[0][2] = '3';
    digPtr->centerSquare[1][0] = '4';
    digPtr->centerSquare[1][1] = '5';
    digPtr->centerSquare[1][2] = '6';
    digPtr->centerSquare[2][0] = '7';
    digPtr->centerSquare[2][1] = '8';
    digPtr->centerSquare[2][2] = '9';

    for(i=0; i < KEYLEN; i++) {
	digPtr->ctkey[SQUARE1][i] = '\0';
	digPtr->ctkey[SQUARE2][i] = '\0';
    }
    for (i=0; i < KEYLEN+14; i++) {
	digPtr->ptkey[SQUARE1][i] = EMPTY;
	digPtr->ptkey[SQUARE2][i] = EMPTY;
    }

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, DigrafidCmd, itemPtr,
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

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    return TCL_OK;
}

int
DigrafidCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    DigrafidItem *digPtr = (DigrafidItem *)clientData;
    CipherItem	*itemPtr = (CipherItem *)clientData;
    char	temp_str[256];
    const char	*cmd;
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
	    sprintf(temp_str, "%d", digPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", digPtr->header.period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!digPtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_VOLATILE);
	    } else {
		Tcl_SetResult(interp, digPtr->header.ciphertext, TCL_VOLATILE);
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
	} else if (strncmp(argv[1], "-digrafidtext", 9) == 0 ||
		   strncmp(argv[1], "-dtext", 3) == 0) {
	    tPtr = GetDigrafidText(interp, itemPtr);

	    if (!tPtr) {
		return TCL_ERROR;
	    }

	    Tcl_SetResult(interp, tPtr, TCL_DYNAMIC);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-keyword", 2) == 0) {
	    int row;
	    int col;
	    int temp_str_pos=0;
	    for(row=1; row <= 3; row++) {
		for(col=1; col <= 9; col++) {
		    int keyIndex = DigrafidKeyPairToIndex(row, col);
		    char keyLetter = digPtr->ptkey[SQUARE1][keyIndex];

		    if (keyLetter != EMPTY) {
			temp_str[temp_str_pos++] = keyLetter;
		    } else {
			temp_str[temp_str_pos++] = ' ';
		    }
		}
	    }
	    temp_str[temp_str_pos] = '\0';

	    temp_str_pos=0;
	    Tcl_AppendElement(interp, temp_str);
	    for(row=1; row <= 3; row++) {
		for(col=1; col <= 9; col++) {
		    int keyIndex = DigrafidKeyPairToIndex(row, col);
		    char keyLetter = digPtr->ptkey[SQUARE2][keyIndex];

		    if (keyLetter != EMPTY) {
			temp_str[temp_str_pos++] = keyLetter;
		    } else {
			temp_str[temp_str_pos++] = ' ';
		    }
		}
	    }
	    temp_str[temp_str_pos] = '\0';

	    Tcl_AppendElement(interp, temp_str);
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
		int period;

		if (sscanf(argv[1], "%d", &period) != 1) {
		    Tcl_SetResult(interp, "Invalid period setting.",
			    TCL_VOLATILE);
		    return TCL_ERROR;
		}

		return DigrafidSetPeriod(interp, itemPtr, period);
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
    } else if (**argv == 'r' && (strncmp(*argv, "restore", 1) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " restore block1 block2",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	return (itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1], argv[2]);
    } else if (**argv == 'e' && (strncmp(*argv, "encode", 1) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " encode pt key",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	return (itemPtr->typePtr->encodeProc)(interp, itemPtr, argv[1], argv[2]);
    } else if (**argv == 's' && (strncmp(*argv, "substitute", 2) == 0)) {
	Tcl_AppendResult(interp,
		"No substitute function defined for ",
		itemPtr->typePtr->type,
		" ciphers",
		(char *)NULL);
	return TCL_ERROR;

	if (argc != 4) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " substitute row col pt",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	if (*argv[1] < '0' || *argv[1] > '5') {
	    Tcl_SetResult(interp,
		    "Invalid row value.  Value must be between 0 and 5.",
		    TCL_VOLATILE);
	    return TCL_ERROR;
	}
	if (*argv[2] < '0' || *argv[2] > '5') {
	    Tcl_SetResult(interp,
		    "Invalid column value.  Value must be between 0 and 5.",
		    TCL_VOLATILE);
	    return TCL_ERROR;
	}
	if (! IsValidChar(itemPtr, *argv[3])) {
	    Tcl_SetResult(interp, "Invalid letter value.", TCL_VOLATILE);
	    return TCL_ERROR;
	}

	/*
	 * *argv[1] and *argv[2] are now guaranteed to be a valid row/column
	 * value (ROW1, ROW3, etc.
	 */
	if ((itemPtr->typePtr->subProc)(interp, itemPtr, argv[1], argv[2], *argv[3]) == BAD_SUB) {
	    return TCL_ERROR;
	} else {
	    return TCL_OK;
	}
    } else if (**argv == 's' && (strncmp(*argv, "solve", 2) == 0)) {
	if ((itemPtr->typePtr->solveProc)(interp, itemPtr, temp_str) != TCL_OK)
	    return TCL_ERROR;

	Tcl_SetResult(interp, temp_str, TCL_VOLATILE);

	return TCL_OK;
    } else if (**argv == 'u' && (strncmp(*argv, "undo", 1) == 0)) {
	if (argc != 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " undo ct", (char *)NULL);
	    return TCL_ERROR;
	}
	if ((itemPtr->typePtr->undoProc)(interp, itemPtr, argv[1], 0) == TCL_OK) {
	    Tcl_SetResult(interp, "", TCL_VOLATILE);
	    return TCL_OK;
	} else {
	    return TCL_ERROR;
	}
    } else if (**argv == 'l' && (strncmp(*argv, "locate", 1) == 0)) {
	if (argc < 2 || argc > 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " locate pt ct",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	if (argc == 2) {
	    return (itemPtr->typePtr->locateProc)(interp, itemPtr, argv[1],
		    (char *)NULL);
	} else {
	    return (itemPtr->typePtr->locateProc)(interp, itemPtr, argv[1],
		    argv[2]);
	}
    } else {
	Tcl_AppendResult(interp, "Unknown option ", *argv, (char *)NULL);
	Tcl_AppendResult(interp, "\nMust be one of:  ", cmd,
			" cget ?option?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" configure ?option value?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" restore block1 block2", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" encode pt key", (char *)NULL);
	return TCL_ERROR;
    }
}

static int
SetDigrafid(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
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

	Tcl_SetResult(interp, itemPtr->ciphertext, TCL_STATIC);
    }

    return valid;
}

static int
DigrafidLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, const char *tip, const char *start)
{
    Tcl_AppendResult(interp,
	    "No locate tip function defined for ",
	    itemPtr->typePtr->type,
	    " ciphers",
	    (char *)NULL);
    return TCL_ERROR;
}

static int
DigrafidUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int dummy)
{
    Tcl_AppendResult(interp,
	    "No undo function defined for ",
	    itemPtr->typePtr->type,
	    " ciphers",
	    (char *)NULL);
    return TCL_ERROR;
}

static int
DigrafidSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *row, const char *col, int value)
{
    Tcl_AppendResult(interp,
	    "No substitute function defined for ",
	    itemPtr->typePtr->type,
	    " ciphers",
	    (char *)NULL);
    return BAD_SUB;
}

static int
DigrafidKeycharToInt(char c) {
    if (c == '#') {
	c = 26;
    } else {
	c -= 'a';
    }

    return c;
}

static int
DigrafidKeyPairToIndex(int row, int col)
{
    int keyIndex = 0;

    if (row < 0 || row > 3 || col < 0 || col > 9) {
	return 0;
    } else {
	return row * 10 + col;
    }

    return keyIndex;
}

static char *
GetDigrafidText(Tcl_Interp *interp, CipherItem *itemPtr) {
    DigrafidItem *digPtr = (DigrafidItem *)itemPtr;
    char	*dt=(char *)NULL;
    int		dtIndex = 0;
    int		i;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp, "Can't get digrafid text until the ciphertext has been set.", TCL_STATIC);
	return (char *)NULL;
    }

    dt=(char *)ckalloc(sizeof(char) * itemPtr->length / 2 * 3 + 1);

    for(i=0, dtIndex=0; i < itemPtr->length; i += 2) {
	char *ct1cell = DigrafidLetterToKeyval(itemPtr,
		itemPtr->ciphertext[i], SQUARE1);
	char *ct2cell = DigrafidLetterToKeyval(itemPtr,
		itemPtr->ciphertext[i+1], SQUARE2);


	if (ct1cell != NULL) {
	    dt[dtIndex++] = ct1cell[1];
	} else {
	    dt[dtIndex++] = '0';
	}

	if (ct1cell != NULL && ct2cell != NULL
		&& ct1cell[0] != KEY0 && ct2cell[0] != KEY0) {
	    dt[dtIndex++] = digPtr->centerSquare[ct1cell[0]-'1'][ct2cell[0]-'1'];
	} else {
	    dt[dtIndex++] = '0';
	}

	if (ct1cell != NULL) {
	    dt[dtIndex++] = ct2cell[1];
	} else {
	    dt[dtIndex++] = '0';
	}
    }
    dt[dtIndex] = '\0';

    return dt;
}

static char *
GetDigrafid(Tcl_Interp *interp, CipherItem *itemPtr)
{
    int		i;
    char	*pt=(char *)NULL;
    char	*digText = (char *)NULL;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp, "Can't do anything until ciphertext has been set",
		TCL_VOLATILE);
	return (char *)NULL;
    }

    if (itemPtr->period <= 0) {
	Tcl_SetResult(interp, "Can't do anything until a period has been set",
		TCL_VOLATILE);
	return (char *)NULL;
    }

    digText = (GetDigrafidText(interp, itemPtr));
    if (digText == NULL) {
	Tcl_SetResult(interp, "Error retrieving digrafid text", TCL_STATIC);
	return (char *)NULL;
    }

    pt=(char *)ckalloc(sizeof(char) * itemPtr->length+1);

    /*
     * Convert every digram to its plaintext equivalent.
     */

    for (i=0; i < itemPtr->length / 2; i++) {
	int blockNum = i / itemPtr->period;
	int blockStart = blockNum*itemPtr->period*3;
	int blockLength = itemPtr->period*3;
	int blockPeriod = itemPtr->period;
	char keyVal[4];
	
	if (itemPtr->length/2*3 - blockStart < blockLength) {
	    blockLength = itemPtr->length/2*3 - blockStart;
	    blockPeriod = blockLength / 3;
	}

	if (blockStart + i%itemPtr->period + 1*blockPeriod > itemPtr->length * 3) {
	    fprintf(stderr, "Invalid index\n");
	    abort();
	}

	keyVal[0] = digText[blockStart + i%itemPtr->period + 0*blockPeriod];
	keyVal[1] = digText[blockStart + i%itemPtr->period + 1*blockPeriod];
	keyVal[2] = digText[blockStart + i%itemPtr->period + 2*blockPeriod];
	keyVal[3] = '\0';
	(void)DigrafidKeyvalToDigram(itemPtr, keyVal, pt + i*2);
	if (pt[i*2] == '\0') {
	    pt[i*2] = ' ';
	}
	if (pt[i*2+1] == '\0') {
	    pt[i*2+1] = ' ';
	}
    }
    pt[i*2] = '\0';
    ckfree(digText);

    return pt;
}

static int
RestoreDigrafid(Tcl_Interp *interp, CipherItem *itemPtr, const char *square1, const char *square2)
{
    char keyLength[TCL_DOUBLE_SPACE];
    DigrafidItem *digPtr = (DigrafidItem *)itemPtr;
    int i;

    if (strlen(square1) != KEYLEN) {
	sprintf(keyLength, "%d", strlen(square1));
	Tcl_AppendResult(interp, "Key '", square1, "' has invalid length ", keyLength, (char *)NULL);
	return TCL_ERROR;
    }

    if (strlen(square2) != KEYLEN) {
	sprintf(keyLength, "%d", strlen(square2));
	Tcl_AppendResult(interp, "Key '", square2, "' has invalid length ", keyLength, (char *)NULL);
	return TCL_ERROR;
    }

    for(i=0; i < KEYLEN; i++) {
	int keyIndex = DigrafidKeyPairToIndex(i/9+1, i%9+1);

	if (! IsValidChar(itemPtr, square1[i]) || ! IsValidChar(itemPtr, square2[i])) {
	    Tcl_SetResult(interp, "Invalid character found in key",
		    TCL_VOLATILE);
	    return TCL_ERROR;
	}

	digPtr->ptkey[SQUARE1][keyIndex] = square1[i];
	digPtr->ptkey[SQUARE2][keyIndex] = square2[i];

	digPtr->ctkey[SQUARE1][DigrafidKeycharToInt(square1[i])] = keyIndex;
	digPtr->ctkey[SQUARE2][DigrafidKeycharToInt(square2[i])] = keyIndex;
    }

    Tcl_SetResult(interp, "", TCL_STATIC);
    return TCL_OK;
}

static int
SolveDigrafid(Tcl_Interp *interp, CipherItem *itemPtr, char *result)
{
    Tcl_SetResult(interp, "You cheat!", TCL_STATIC);
    return TCL_ERROR;
}

static char *
DigrafidLetterToKeyval(CipherItem *itemPtr, char letter, int squareID)
{
    DigrafidItem *digPtr = (DigrafidItem *)itemPtr;
    int keyIndex=0;

    if ((letter < 'a' || letter > 'z') && letter != '#') {
	return (char *)NULL;
    }

    keyIndex = DigrafidKeycharToInt(letter);

    if (digPtr->ctkey[squareID][keyIndex] == EMPTY) {
	return (char *)NULL;
    }

    return digPtr->keyConv[(int)(digPtr->ctkey[squareID][keyIndex])];
}

static int
DigrafidKeyvalToDigram(CipherItem *itemPtr, char *keyVal, char *result)
{
    DigrafidItem *digPtr = (DigrafidItem *)itemPtr;
    int letterRow;
    int letterCol;
    int letterIndex;

    result[0] = '\0';
    result[1] = '\0';

    if (!keyVal[0] || !keyVal[1] | !keyVal[2]) {
	return '\0';
    }

    if ( (keyVal[0] != KEY1 && keyVal[0] != KEY2 && keyVal[0] != KEY3
		&& keyVal[0] != KEY4 && keyVal[0] != KEY5 && keyVal[0] != KEY6
		&& keyVal[0] != KEY7 && keyVal[0] != KEY8 && keyVal[0] != KEY9)
	    || (keyVal[1] != KEY1 && keyVal[1] != KEY2 && keyVal[1] != KEY3
		&& keyVal[1] != KEY4 && keyVal[1] != KEY5 && keyVal[1] != KEY6
		&& keyVal[1] != KEY7 && keyVal[1] != KEY8 && keyVal[1] != KEY9)
	    || (keyVal[2] != KEY1 && keyVal[2] != KEY2 && keyVal[2] != KEY3
		&& keyVal[2] != KEY4 && keyVal[2] != KEY5 && keyVal[2] != KEY6
		&& keyVal[2] != KEY7 && keyVal[2] != KEY8 && keyVal[2] != KEY9)) {
	return '\0';
    }

    letterCol = (keyVal[0] - '0');
    letterRow = (keyVal[1] - '1') / 3 + 1;
    letterIndex = (letterRow * 10 + letterCol);

    if (digPtr->ptkey[SQUARE1][letterIndex] != EMPTY) {
	result[0] = digPtr->ptkey[SQUARE1][letterIndex];
    } else {
	result[0] = '\0';
    }

    letterCol = (keyVal[2] - '0');
    letterRow = (keyVal[1] - '1') % 3 + 1;
    letterIndex = (letterRow * 10 + letterCol);
    if (digPtr->ptkey[SQUARE2][letterIndex] != EMPTY) {
	result[1] = digPtr->ptkey[SQUARE2][letterIndex];
    } else {
	result[1] = '\0';
    }

    return '\0';
}

static int
DigrafidSetPeriod(Tcl_Interp *interp, CipherItem *itemPtr, int period)
{
    char result[16];

    sprintf(result, "%d", period);

    if (period < 2) {
	Tcl_AppendResult(interp, "Bad period for cipher:  ", result, (char *)NULL);
	return TCL_ERROR;
    }

    if (itemPtr->period == period) {
	Tcl_SetResult(interp, result, TCL_VOLATILE);
	return TCL_OK;
    }

    itemPtr->period = period;

    return TCL_OK;
}

static char *
EncodeDigrafidString(CipherItem *itemPtr, char *text) {
    DigrafidItem *digPtr = (DigrafidItem *)itemPtr;
    int		i;
    char	*ct=(char *)NULL;
    char	*digText = (char *)NULL;
    int		index = 0;
    int		textLength = strlen(text);

    digText = (char *)ckalloc(sizeof(char) * textLength / 2 * 3 + 1);
    for (i=0; i < itemPtr->length / 2 * 3 ; i++) {
	digText[i] = '-';
    }

    for (i=0; i < textLength/2; i++) {
	int blockNum = i / itemPtr->period;
	int blockStart = blockNum*itemPtr->period*3;
	int blockLength = itemPtr->period*3;
	int blockPeriod = itemPtr->period;
	int blockCol = i % itemPtr->period;
	char *ct1cell = DigrafidLetterToKeyval(itemPtr,
		text[i*2], SQUARE1);
	char *ct2cell = DigrafidLetterToKeyval(itemPtr,
		text[i*2+1], SQUARE2);
	
	if (itemPtr->length/2*3 - blockStart < blockLength) {
	    blockLength = textLength/2*3 - blockStart;
	    blockPeriod = blockLength / 3;
	}

	digText[blockStart + blockCol] = ct1cell[1];
	digText[blockStart + blockPeriod + blockCol] = digPtr->centerSquare[ct1cell[0]-'1'][ct2cell[0]-'1'];
	digText[blockStart + blockPeriod*2 + blockCol] = ct2cell[1];
    }

    ct=(char *)ckalloc(sizeof(char) * textLength+1);

    /*
     * Convert every trigram to its ciphertext equivalent.
     */

    for (i=0, index=0; i < textLength/2; i++) {
	char keyVal[4];
	int ct1cell[2];
	int ct2cell[2];

	keyVal[0] = digText[i*3];
	keyVal[1] = digText[i*3+1];
	keyVal[2] = digText[i*3+2];
	keyVal[3] = '\0';

	ct1cell[0] = (keyVal[1]-'1') / 3 + 1;
	ct1cell[1] = (keyVal[0]-'1') + 1;
	ct2cell[1] = (keyVal[2]-'1') + 1;
	ct2cell[0] = (keyVal[1]-'1') % 3 + 1;

	ct[index++] = digPtr->ptkey[SQUARE1][ct1cell[0]*10+ct1cell[1]];
	ct[index++] = digPtr->ptkey[SQUARE2][ct2cell[0]*10+ct2cell[1]];
    }
    ct[index] = '\0';
    ckfree(digText);

    return ct;
}

static int
EncodeDigrafid(Tcl_Interp *interp, CipherItem *itemPtr, const char *pt, const char *key) {
    char *ct = (char *)NULL;
    int count;
    char **argv;
    int i;

    if (Tcl_SplitList(interp, key, &count, &argv) != TCL_OK) {
	return TCL_ERROR;
    }

    if (itemPtr->period < 1) {
	ckfree((char *)argv);
	Tcl_SetResult(interp,
		"Can not encode digrafid until a period has been set.",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (count != 2) {
	ckfree((char *)argv);
	Tcl_AppendResult(interp, "Invalid number of items in encoding key '",
	      key, "'.  Should have found 2.", (char *)NULL);
	return TCL_ERROR;
    }

    if (strlen(argv[0]) != 27 || strlen(argv[1]) != 27) {
	Tcl_SetResult(interp, "Invalid length of key elements.", TCL_STATIC);
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    /*
     * The plaintext and ciphertext alphabets use the same set of
     * characters.  Set the current item's ciphertext in order to
     * validate the plaintext string.
     */

    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, pt) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    /*
     * Validate and store the key in the current item.  The key functions used
     * by the encoder assume the current item has the encoding key.
     */

    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[0], argv[1])
	    != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    ct = EncodeDigrafidString(itemPtr, itemPtr->ciphertext);
    if (ct == NULL) {
	Tcl_SetResult(interp, "Inconsistency check failed for encoding key.  Are there blanks in the key?", TCL_STATIC);
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    /*
     * Now make the cipher item consistent by setting the item's ciphertext
     * to the newly calcualted ciphertext and applying the key.
     */
    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, ct) != TCL_OK) {
	ckfree(ct);
	ckfree((char *)argv);
	return TCL_ERROR;
    }
    ckfree(ct);

    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[0], argv[1]) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    Tcl_SetResult(interp, itemPtr->ciphertext, TCL_VOLATILE);
    ckfree((char *)argv);
    return TCL_OK;
}
