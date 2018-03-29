/*
 * caesar.c --
 *
 *	This file implements the Caesar cipher type.
 *
 * Copyright (c) 2003-2008 Michael Thomas <wart@kobold.org>
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
#include <ctype.h>
#include <cipher.h>

#include <cipherDebug.h>

int CaesarCmd		_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));

/*
 * Prototypes for procedures only referenced in this file.
 */

static int  CreateCaesar	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
static char *GetCaesar		_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetCaesar		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestoreCaesar	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolveCaesar		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
static int CaesarUndo		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int CaesarSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int CaesarLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int EncodeCaesar		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));

/* Helper function? */
static void ShiftString		(char *s, int shift);

/*
 * This structure contains the data associated with a single Caesar cipher.
 */

typedef struct CaesarItem {
    CipherItem header;

    int shift;
} CaesarItem;

/*
 * This structure joins the data for an Caesar cipher with common routines
 * used to manipulate it.
 */

CipherType CaesarType = {
    "caesar",
    "abcdefghijklmnopqrstuvwxyz -',.;:?()/\"!{}",
    sizeof(CaesarItem),
    CreateCaesar,	/* create proc */
    DeleteCipher,	/* delete proc */
    CaesarCmd,		/* cipher command proc */
    GetCaesar,		/* get plaintext proc */
    SetCaesar,		/* show ciphertext proc */
    SolveCaesar,	/* solve cipher proc */
    RestoreCaesar,	/* restore proc */
    CaesarLocateTip,	/* locate proc */
    CaesarSubstitute,	/* sub proc */
    CaesarUndo,		/* undo proc */
    EncodeCaesar,	/* encode proc*/
    (CipherType *)NULL	/* next cipher type */
};

/*
 * CreateCaesar --
 *
 *	Create a new Caesar cipher item.
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
CreateCaesar(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    CaesarItem *caesarPtr = (CaesarItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    caesarPtr->header.period = 0;
    itemPtr->stepCommand = (char *)NULL;
    itemPtr->bestFitCommand = (char *)NULL;
    itemPtr->stepInterval = 0;
    caesarPtr->shift = 0;

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, CaesarCmd, itemPtr,
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
CaesarCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    CaesarItem *caesarPtr = (CaesarItem *)clientData;
    CipherItem	*itemPtr = (CipherItem *)clientData;
    char	temp_str[256];
    const char	*cmd;
    char	*tPtr=(char *)NULL;
    int		i;

    cmd = *argv;

    argv++, argc--;

    if (argc == 0) {
	Tcl_AppendResult(interp, "Usage:  ", cmd, " ?option?", (char *)NULL);
	return TCL_ERROR;
    }

    if (**argv == 'c' && (strncmp(*argv, "cget", 2) == 0)) {
	if (argc != 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " cget option",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	if (strncmp(argv[1], "-length", 6) == 0) {
	    sprintf(temp_str, "%d", caesarPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", caesarPtr->header.period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!caesarPtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_STATIC);
	    } else {
		Tcl_SetResult(interp, caesarPtr->header.ciphertext,
			TCL_VOLATILE);
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
	    sprintf(temp_str, "%d", caesarPtr->shift);
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
		if ((itemPtr->typePtr->setctProc)(interp, itemPtr, argv[1])
			!= TCL_OK) {
		    return TCL_ERROR;
		}
	    } else if (strncmp(*argv, "-language", 8) == 0) {
		itemPtr->language = cipherSelectLanguage(argv[1]);
		Tcl_SetResult(interp, cipherGetLanguage(itemPtr->language),
			TCL_VOLATILE);
	    } else if (strncmp(*argv, "-shift", 5) == 0) {
		if (sscanf(argv[1], "%d", &i) != 1) {
		    Tcl_SetResult(interp,
			    "Invalid shift value.  Must be from 0 to 26",
			    TCL_VOLATILE);
		    return TCL_ERROR;
		}
		if (i < 0 || i > 26) {
		    Tcl_SetResult(interp,
			    "Invalid shift value.  Must be from 0 to 26",
			    TCL_VOLATILE);
		    return TCL_ERROR;
		}

		caesarPtr->shift = i;
		Tcl_SetObjResult(interp, Tcl_NewStringObj(argv[1], -1));
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
    } else if (**argv == 'r' && (strncmp(*argv, "restore", 1) == 0)) {
	if (argc != 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " restore shift",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	return (itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1],
		(char *)NULL);
    } else if (**argv == 's' && (strncmp(*argv, "substitute", 2) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " substitute ct pt",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	if (strlen(argv[1]) != 1 && strlen(argv[2]) != 1) {
	    Tcl_SetResult(interp,
		    "ciphertext and plaintext must both be one character long",
		    TCL_STATIC);
	    return TCL_ERROR;
	}
	if ((itemPtr->typePtr->subProc)(interp, itemPtr, argv[1], argv[2], 0)
		== BAD_SUB) {
	    return TCL_ERROR;
	} else {
	    return TCL_OK;
	}
    } else if (**argv == 's' && (strncmp(*argv, "solve", 2) == 0)) {
	Tcl_SetResult(interp, "Solve procedure is not defined for caesar ciphers.", TCL_STATIC);
	return TCL_ERROR;
    } else if (**argv == 'u' && (strncmp(*argv, "undo", 1) == 0)) {
	if (argc != 1) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " undo", (char *)NULL);
	    return TCL_ERROR;
	}
	if ((itemPtr->typePtr->undoProc)(interp, itemPtr, (char *)NULL, 0) == TCL_OK) {
	    Tcl_SetResult(interp, "", TCL_VOLATILE);
	    return TCL_OK;
	} else {
	    return TCL_ERROR;
	}
    } else if (**argv == 'l' && (strncmp(*argv, "locate", 1) == 0)) {
	Tcl_SetResult(interp, "Locate procedure is not defined for caesar ciphers.", TCL_STATIC);
	return TCL_ERROR;
    } else if (**argv == 'e' && (strncmp(*argv, "encode", 1) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " encode pt shift",
		(char *)NULL);
	    return TCL_ERROR;
	}
	return (itemPtr->typePtr->encodeProc)(interp, itemPtr, argv[1], argv[2]);
    } else {
	Tcl_AppendResult(interp, "Unknown option ", *argv, (char *)NULL);
	Tcl_AppendResult(interp, "\nMust be one of:  ", cmd,
			" cget ?option?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" configure ?option value?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" restore shift", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" substitute ct pt", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" undo", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" encode pt shift", (char *)NULL);
	return TCL_ERROR;
    }
}

static int
SetCaesar(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
{
    char	*c,
		*e;
    int		valid = TCL_OK,
    		length=0;
    char	badchar[2];

    c = ctext;

    /*
     * First find out if every character is valid
     */
    while(*c && valid == TCL_OK) {
	e = itemPtr->typePtr->valid_chars;
	if (*c == '\n' || *c == '\r') {
	    *c = ' ';
	}
        *c = tolower(*c);

	while(*e && (*e != *c)) {
	    e++;
	}
	if (! *e) {
	    valid = TCL_ERROR;
	    badchar[0] = *c;
	}

   	length++;
	c++;
    }

    if (valid==TCL_OK) {
	itemPtr->length = length;
	if (itemPtr->ciphertext) {
	    ckfree(itemPtr->ciphertext);
	}

	itemPtr->ciphertext = (char *)ckalloc(sizeof(char)*length + 2);
	if (itemPtr->ciphertext == NULL) {
	    Tcl_SetResult(interp, "Error mallocing memory for new cipher",
		    TCL_VOLATILE);
	    return TCL_ERROR;
	}
	itemPtr->length = length;

	c = ctext;
	e = itemPtr->ciphertext;

	while((*e++ = *c++));
	Tcl_SetResult(interp, itemPtr->ciphertext, TCL_STATIC);
    } else {
	badchar[1] = '\0';
	Tcl_AppendResult(interp, "Bad character in ciphertext:  ", badchar,
	       	(char *)NULL);
    }

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    return valid;
}

static int
CaesarUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int dummy)
{
    CaesarItem *caesarPtr = (CaesarItem *)itemPtr;

    caesarPtr->shift = 0;

    return TCL_OK;
}

static int
CaesarSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, const char *pt, int dummy)
{
    CaesarItem *caesarPtr = (CaesarItem *)itemPtr;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp,
		"Can't do anything until the ciphertext has been set",
		TCL_VOLATILE);
	return BAD_SUB;
    }

    if (*pt < 'a' || *pt > 'z' || *ct < 'a' || *ct > 'z') {
	Tcl_SetResult(interp, "Plaintext and ciphertext values must be alphabetic characters from a to z", TCL_STATIC);
	return BAD_SUB;
    }

    caesarPtr->shift = (*pt - *ct + 26)%26;

    Tcl_SetResult(interp, "", TCL_STATIC);

    return NEW_SUB;
}

/*
Shifts all of the lowercase characters in a string by a given amount.
It is called by both the encoding and decoding functions.
*/
static void
ShiftString(char *s, int shift)
{
    char c;
    /* Handle negative numbers correctly. */
    if (shift < 0) {
	shift = -shift;
	shift %= 26;
	shift = 26 - shift;
    }
    /* Modify the string. */
    while(s && *s) {
	if ('a' <= *s && *s <= 'z') {
	    c = (*s - 'a') + shift;
	    *s = (c % 26) + 'a';
	}
	s++;
    }
}

static char *
GetCaesar(Tcl_Interp *interp, CipherItem *itemPtr)
{
    CaesarItem *caesarPtr = (CaesarItem *)itemPtr;
    char	*pt=(char *)ckalloc(sizeof(char)*strlen(itemPtr->ciphertext)+1);

    /* Set the newly created plaintext to be a clone of the ciphertext. */
    strcpy(pt, itemPtr->ciphertext);

    /* Shift the plaintext forward by the amount specified in the item information. */
    ShiftString(pt, caesarPtr->shift);

    return pt;
}

/*
Here 'key' is the string to be interpreted as the shift.
It's important that the shift here is interpreted to be in the opposite
direction from that of the decoding function.
*/
static int
EncodeCaesar(Tcl_Interp *interp, CipherItem *itemPtr, const char *pt, const char *key) {

    CaesarItem *caesarPtr = (CaesarItem *)itemPtr;

    /* Make sure the plaintext is reasonable. */
    if (!pt) {
	Tcl_SetResult(interp, "Plaintext for encoding is not reasonable.", TCL_STATIC);
	return TCL_ERROR;
    }

    /*
     * This call has the side effect of setting the key for the
     * current cipher item  It will convert the key string into
     * an integer and store the result in the cipher item.
     */
    if (RestoreCaesar(interp, itemPtr, key, (char *) NULL) == TCL_ERROR) {
	return TCL_ERROR;
    }

    /*
     * Modify the plaintext in-place.  This is much faster than
     * setting the ciphertext to the plaintext, doing a reverse shift,
     * resetting the ciphertext, then restoring the key.
     */
    ShiftString(pt, -caesarPtr->shift);

    /*
     * The plaintext pointer now contains the new ciphertext.
     * Store it in the cipher item.
     */
    (itemPtr->typePtr->setctProc)(interp, itemPtr, pt);

    Tcl_SetResult(interp, itemPtr->ciphertext, TCL_VOLATILE);

    return TCL_OK;
}

static int
RestoreCaesar(Tcl_Interp *interp, CipherItem *itemPtr, const char *part1, const char *part2)
{
    CaesarItem *caesarPtr = (CaesarItem *)itemPtr;
    int shift = 0;

    if (sscanf(part1, "%d", &shift) != 1) {
	Tcl_SetResult(interp, "caesar key must be from 0 to 26", TCL_STATIC);
	return TCL_ERROR;
    }

    if (shift < 0 || shift > 26) {
	Tcl_SetResult(interp, "caesar key must be from 0 to 26", TCL_STATIC);
	return TCL_ERROR;
    }

    caesarPtr->shift = shift;
    return TCL_OK;
}

static int
SolveCaesar(Tcl_Interp *interp, CipherItem *itemPtr, char *junk) {
    Tcl_SetResult(interp, "No solve function defined for caesar ciphers",
	    TCL_STATIC);
    return TCL_ERROR;
}

static int
CaesarLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, const char *tip, const char *start)
{
    Tcl_SetResult(interp, "No locate tip function defined for caesar ciphers",
	    TCL_STATIC);
    return TCL_ERROR;
}
