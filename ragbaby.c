/*
 * ragbaby.c --
 *
 *	This file implements the ragbaby cipher type.
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
#include <keygen.h>

#include <cipherDebug.h>

void DeleteRagbaby		_ANSI_ARGS_((ClientData));
int RagbabyCmd			_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));

#define MAXKEYLEN	24
#define EMPTY		-1

/*
 * Prototypes for procedures only referenced in this file.
 */

static int  CreateRagbaby	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
static char *GetRagbaby		_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetRagbaby		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestoreRagbaby	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolveRagbaby	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
static int RagbabyUndo		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int RagbabySubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int RagbabyLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static char *GetRagbabyOffsets	_ANSI_ARGS_((CipherItem *, char));
static int EncodeRagbaby	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));

/*
 * This structure contains the data associated with a single ragbaby cipher.
 */

typedef struct RagbabyItem {
    CipherItem header;

    int keylen;		/* The length of the key.  Most ragbaby ciphers
			   use 24-character keys.  We want to allow for
			   longer keys for some non-standard ciphers.
			 */
    char key[MAXKEYLEN];   /* The ragbaby cipher uses a single key to encrypt
			   itself.
			 */
    short keyPos[MAXKEYLEN]; /* This is a reverse index into the key.  It
				stores the positions of every letter.
			      */
    short *keyOffset;	/* Array holding the offsets of each ct letter from
			   it's pt letter.
			 */

} RagbabyItem;

/*
 * This structure joins the data for an ragbaby cipher with common routines
 * used to manipulate it.
 */

CipherType RagbabyType = {
    "ragbaby",
    "abcdefghijklmnopqrstuvwxyz -',.;:?()\"!",
    sizeof(RagbabyItem),
    CreateRagbaby,	/* create proc */
    DeleteRagbaby,	/* delete proc */
    RagbabyCmd,		/* cipher command proc */
    GetRagbaby,		/* get plaintext proc */
    SetRagbaby,		/* show ciphertext proc */
    SolveRagbaby,	/* solve cipher proc */
    RestoreRagbaby,	/* restore proc */
    RagbabyLocateTip,	/* locate proc */
    RagbabySubstitute,	/* sub proc */
    RagbabyUndo,	/* undo proc */
    EncodeRagbaby,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

/*
 * CreateRagbaby --
 *
 *	Create a new ragbaby cipher item.
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
CreateRagbaby(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    RagbabyItem *ragPtr = (RagbabyItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    ragPtr->header.period = 0;
    ragPtr->keyOffset = (short *)NULL;
    ragPtr->keylen = 24;

    for(i=0; i < MAXKEYLEN; i++) {
	ragPtr->key[i] = EMPTY;
	ragPtr->keyPos[i] = EMPTY;
    }

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, RagbabyCmd, itemPtr,
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
DeleteRagbaby(ClientData clientData)
{
    RagbabyItem *ragPtr = (RagbabyItem *)clientData;

    if (ragPtr->keyOffset != NULL) {
	ckfree((char *)(ragPtr->keyOffset));
    }

    DeleteCipher(clientData);
}

int
RagbabyCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    RagbabyItem *ragPtr = (RagbabyItem *)clientData;
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
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " cget option", (char *)NULL);
	    return TCL_ERROR;
	}
	if (strncmp(argv[1], "-length", 6) == 0) {
	    sprintf(temp_str, "%d", ragPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", ragPtr->header.period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!ragPtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_VOLATILE);
	    } else {
		Tcl_SetResult(interp, ragPtr->header.ciphertext, TCL_VOLATILE);
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
	} else if (strncmp(argv[1], "-keyoffset", 9) == 0) {
	    for(i=0; i < ragPtr->keylen; i++) {
		temp_str[i] = (ragPtr->key[i]==EMPTY)?' ':ragPtr->key[i];
	    }
	    temp_str[i] = '\0';
	    tPtr = GetRagbabyOffsets(itemPtr, ' ');
	    if (!tPtr) {
		return TCL_ERROR;
	    }

	    Tcl_SetResult(interp, tPtr, TCL_DYNAMIC);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-key", 4) == 0) {
	    for(i=0; i < ragPtr->keylen; i++) {
		temp_str[i] = (ragPtr->key[i]==EMPTY)?' ':ragPtr->key[i];
	    }
	    temp_str[i] = '\0';

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
		if ((itemPtr->typePtr->setctProc)(interp, itemPtr, argv[1]) != TCL_OK) {
		    return TCL_ERROR;
		}
	    } else if (strncmp(*argv, "-stepinterval", 12) == 0) {
		if (argc < 2) {
		    Tcl_AppendResult(interp, "Usage:  ", cmd,
			    " configure -stepinterval val", (char *)NULL);
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
    } else if (**argv == 'r' && (strncmp(*argv, "restore", 1) == 0)) {
	/*
	 * Even though we accept a third argument for restore, it's not used.
	 * This just makes the Tcl-levelsignature for restore similar to
	 * most of the other cipher types.
	 */
	if (argc != 2 && argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " restore key",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	return (itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1], (char *)NULL);
    } else if (**argv == 's' && (strncmp(*argv, "substitute", 2) == 0)) {
	int offset;
	if (argc != 4) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " substitute ct pt offset",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	if (strlen(argv[1]) != strlen(argv[2])) {
	    Tcl_SetResult(interp,
		    "ciphertext and plaintext must be the same length",
		    TCL_VOLATILE);
	    return TCL_ERROR;
	}
	if (sscanf(argv[3], "%d", &offset) != 1) {
	    Tcl_AppendResult(interp, "Invalid offset '", argv[3], 
		    "' in substitution.", (char *)NULL);
	    return TCL_ERROR;
	}
	if ((itemPtr->typePtr->subProc)(interp, itemPtr, argv[1], argv[2],
		    offset) == BAD_SUB) {
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
	if (argc != 1 && argc != 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " undo ?ct?",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	if (argc == 1) {
	    if ((itemPtr->typePtr->undoProc)(interp, itemPtr, (char *)NULL, 0) == TCL_OK) {
		Tcl_SetResult(interp, "", TCL_VOLATILE);
		return TCL_OK;
	    } else {
		return TCL_ERROR;
	    }
	} else {
	    if ((itemPtr->typePtr->undoProc)(interp, itemPtr, argv[1], 0) == TCL_OK) {
		Tcl_SetResult(interp, "", TCL_VOLATILE);
		return TCL_OK;
	    } else {
		return TCL_ERROR;
	    }
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
    } else if (**argv == 'e' && (strncmp(*argv, "encode", 1) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " encode pt key",
		(char *)NULL);
	    return TCL_ERROR;
	}
	return (itemPtr->typePtr->encodeProc)(interp, itemPtr, argv[1],
	    argv[2]);
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
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" locate pt ct", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" encode pt key", (char *)NULL);
	return TCL_ERROR;
    }
}

/*
 * Returns a newly ckalloc()ated array giving the offsets.
 * a co-op test  ->
 * 1 23 45 3456
 * The length, in shorts, of the returned array is equal to strlen(text).
 * The important classes of text characters are:
 * ['a'..'z'], '-', everything else.
 */
short *
GetOffsets(const char *text, int alphabetSize) {
    int i;
    int n = strlen(text);
    int start = 1;	/* What offset should the next word start with? */
    int current = 0;	/* What offset should the next letter in the word have? */
    int restart = 1;	/* Will the next alphabetic letter represent the start of a new word? */
    char c;
    short *offsetArray = (short *)ckalloc(sizeof(short) * n);
    int offset = 0;
    for (i=0; i<n; i++) {
	c = text[i];
	offset = 0;
	if ('a'<=c && c<='z') {
	    if (restart) {
		current = start++;
	    }
	    offset = current++;
	    restart = 0;
	} else if (c != '-') {
	    restart = 1;
	}
	offsetArray[i] = offset % alphabetSize;
    }
    return offsetArray;
}

static int
SetRagbaby(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
{
    RagbabyItem *ragPtr = (RagbabyItem *)itemPtr;
    int length=0;
    char *c = (char *)NULL;

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
    
    /*
     * Clean up old ciphertext and offset values.
     */
    if (itemPtr->ciphertext) {
	ckfree(itemPtr->ciphertext);
    }
    if (ragPtr->keyOffset) {
	ckfree((char *)(ragPtr->keyOffset));
    }

    /*
     * Set the new values.
     */
    itemPtr->ciphertext = c;
    itemPtr->length = strlen(c);
    ragPtr->keyOffset = GetOffsets(c, ragPtr->keylen);
    
    /*
     * Return the ciphertext.
     */
    Tcl_SetResult(interp, itemPtr->ciphertext, TCL_STATIC);

    return TCL_OK;
}

static int
RagbabyLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, const char *tip, const char *start)
{
    Tcl_SetResult(interp,
	    "No locate tip function defined for ragbaby ciphers.",
	    TCL_VOLATILE);
    return TCL_ERROR;
}

static int
RagbabyUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int dummy)
{
    Tcl_SetResult(interp,
	    "No undo function defined for ragbaby ciphers.",
	    TCL_VOLATILE);
    return TCL_ERROR;
}

static int
RagbabySubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, const char *pt, int dummy)
{
    Tcl_SetResult(interp, "Substitution is not yet defined for ragbaby ciphers",
	    TCL_VOLATILE);
    return BAD_SUB;
}

/*
 * Using a 24 letter alphabet,
 * abcdefghijklmnopqrstuvwxyz ->
 * abcdefghiiklmnopqrstuvwwyz
 * 'jumpy fox' -> 'iumpy fow'
 */
char
TranslateLetter(char c, int alphabetSize) {
    if (c == 'j' && alphabetSize < 26) {
	return 'i';
    } else if (c == 'x' && alphabetSize < 25) {
	return 'w';
    }
    return c;
}

/*
 * Using a 24 letter alphabet,
 * abcdefghijklmnopqrstuvwxyz ->
 * abcdefghiijklmnopqrstuvwwx
 * 'jumpy fox' -> 'itlow fnw'
 */
char
ReduceLetter(char c, int alphabetSize) {
    if (alphabetSize < 25 && c >= 'x') {
        c--;
    }
    if (alphabetSize < 26 && c >= 'j') {
        c--;
    }

    return c;
}

static char *
GetRagbaby(Tcl_Interp *interp, CipherItem *itemPtr)
{
    RagbabyItem *ragPtr = (RagbabyItem *)itemPtr;
    char	*c;
    int		i;
    char	*pt=(char *)NULL;
    int		index;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp, "Can't do anything until ciphertext has been set",
		TCL_STATIC);
	return (char *)NULL;
    }

    pt=(char *)ckalloc(sizeof(char) * itemPtr->length+1);
    c = itemPtr->ciphertext;

    /*
     * Read out the plaintext from the ragbaby array
     */

    for(i=0; i < itemPtr->length; i++) {
	int ctOffset = ragPtr->keyOffset[i];

	if (ctOffset == 0) {
	    pt[i] = c[i];
	} else {
	    int validCt = ' ';
	    int ctKeyPos = EMPTY;
	    if ('a' <= c[i] && c[i] <= 'z') {
		validCt = ReduceLetter(c[i], ragPtr->keylen);
		ctKeyPos = ragPtr->keyPos[(validCt - 'a')];
	    }
	    if (ctKeyPos != EMPTY) {
		index = ctKeyPos - ctOffset + ragPtr->keylen;
		pt[i] = ragPtr->key[index % ragPtr->keylen];
		if (pt[i] == EMPTY) {
		    pt[i] = ' ';
		}
	    } else {
		pt[i] = ' ';
	    }
	}
    }
    pt[i] = '\0';
	
    return pt;
}

/*
 * TODO:  Restore will fail if there are any empty spaces in the key
 */
static int
RestoreRagbaby(Tcl_Interp *interp, CipherItem *itemPtr, const char *savedKey, const char *dummy)
{
    RagbabyItem *ragPtr = (RagbabyItem *)itemPtr;
    int i;
    int validKey = 1;
    char invalidChar[] = "?";

    if (strlen(savedKey) != ragPtr->keylen) {
	Tcl_SetResult(interp, "Invalid length for key.", TCL_VOLATILE);
	return TCL_ERROR;
    }

    for(i=0; i < ragPtr->keylen; i++) {
	if ((savedKey[i] < 'a' || savedKey[i] > 'z') && savedKey[i] != ' ') {
	    invalidChar[0] = savedKey[i];
	    validKey = 0;
	} else if (savedKey[i] != TranslateLetter(savedKey[i], ragPtr->keylen)) {
	    invalidChar[0] = savedKey[i];
	    validKey = 0;
	}
    }

    if (! validKey) {
	Tcl_AppendResult(interp, "Invalid character in key:  ", invalidChar,
		(char *)NULL);
	return TCL_ERROR;
    }

    for(i=0; i < ragPtr->keylen; i++) {
	ragPtr->key[i] = EMPTY;
	ragPtr->keyPos[i] = EMPTY;
    }

    for(i=0; i < ragPtr->keylen; i++) {
	char keyLetter = savedKey[i];
	
	if (keyLetter != ' ') {
	    ragPtr->key[i] = keyLetter;
	    keyLetter = ReduceLetter(keyLetter, ragPtr->keylen);
	    ragPtr->keyPos[keyLetter-'a'] = i;
	}
    }

    Tcl_SetObjResult(interp, Tcl_NewStringObj(savedKey, -1));
    return TCL_OK;
}

/*
 * Not implemented.
 */
static int
SolveRagbaby(Tcl_Interp *interp, CipherItem *itemPtr, char *result)
{
    Tcl_SetResult(interp, "You cheat!", TCL_VOLATILE);
    return TCL_ERROR;
}

/*
 * This is for visualization only.
 */
static char *
GetRagbabyOffsets(CipherItem *itemPtr, char blankChar)
{
    RagbabyItem *ragPtr = (RagbabyItem *)itemPtr;
    char *offsetStr = (char *)NULL;
    int i;

    offsetStr = (char *)ckalloc(sizeof(char) * (itemPtr->length + 1));

    for (i=0; i < itemPtr->length; i++) {
	if (itemPtr->ciphertext[i] < 'a' || itemPtr->ciphertext[i] > 'z') {
	    offsetStr[i] = blankChar;
	} else {
	    offsetStr[i] = ragPtr->keyOffset[i] + 'a';
	}
    }

    offsetStr[i] = '\0';

    return offsetStr;
}

/*
 * The key is allowed to be a keyword.
 * It doesn't have to be a permutation of the whole alphabet.
 */
static int
EncodeRagbaby(Tcl_Interp *interp, CipherItem *itemPtr, const char *pt, const char *key) {
    
    RagbabyItem *ragPtr = (RagbabyItem *)itemPtr;
    int i, n, count;
    char *translatedKeyword;
    char K1[27];
    char translatedK1[27];
    char *ct;
    char reduced;
    int index;

    /*
     * Check for input errors.
     */
    if (!pt) {
	Tcl_SetResult(interp, "Bad pt pointer.", TCL_STATIC);
	return TCL_ERROR;
    }
    if (!key) {
	Tcl_SetResult(interp, "Bad key pointer.", TCL_STATIC);
	return TCL_ERROR;
    }
    if (!strlen(pt)) {
	Tcl_SetResult(interp, "Empty plaintext.", TCL_STATIC);
	return TCL_ERROR;
    }

    /*
     * In the key, possibly translate 'j' to 'i' and 'x' to 'w'.
     */
    n = strlen(key);
    translatedKeyword = (char *) ckalloc((n+1)*sizeof(char));
    for (i=0; i<n; i++) {
	translatedKeyword[i] = TranslateLetter(key[i], MAXKEYLEN);
    }
    translatedKeyword[n] = (char)0;

    /*
     * Generate the K1 key from the new keyword.
     */
    if (KeyGenerateK1(interp, translatedKeyword, K1) == TCL_ERROR) {
	ckfree(translatedKeyword);
	return TCL_ERROR;
    }
    ckfree(translatedKeyword);

    /*
     * Reduce the K1 key to MAXKEYLEN letters
     * by removing 'x' and 'j' if necessary.
     */
    count = 0;
    for (i=0; i<26; i++) {
	if (K1[i] == TranslateLetter(K1[i], MAXKEYLEN)) {
	    translatedK1[count++] = K1[i];
	}
    }
    translatedK1[count] = (char)0;

    /*
     * Set the internal ciphertext length.
     * Set the internal key length.
     */
    ragPtr->keylen = 24;
    itemPtr->length = strlen(pt);

    /*
     * Set up the internal key using restoreProc.
     */
    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, translatedK1, (char *) NULL) != TCL_OK) {
	return TCL_ERROR;
    }

    /*
     * Set up the internal offset string.
     */
    if (ragPtr->keyOffset != (short *)NULL) {
	ckfree((char *)ragPtr->keyOffset);
    }
    ragPtr->keyOffset = GetOffsets(pt, ragPtr->keylen);

    /*
     * Encode.
     */
    n = strlen(pt);
    ct = (char *) ckalloc((n+1)*sizeof(char));
    for (i=0; i<n; i++) {
	if ('a' > pt[i] || pt[i] > 'z') {
	    ct[i] = pt[i];
	    continue;
	}
	reduced = ReduceLetter(pt[i], ragPtr->keylen);
	index = ragPtr->keyPos[reduced - 'a'] + ragPtr->keyOffset[i];
	ct[i] = ragPtr->key[index % ragPtr->keylen];
    }
    ct[n] = (char)0;

    /*
     * Set the ciphertext.
     */
    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, ct) != TCL_OK) {
	ckfree(ct);
	return TCL_ERROR;
    }

    Tcl_SetResult(interp, ct, TCL_VOLATILE);

    ckfree(ct);

    return TCL_OK;
}



