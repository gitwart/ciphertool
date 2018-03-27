/*
 * gromark.c --
 *
 *	This file implements the Gromark cipher type.
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

#include <cipherDebug.h>

void DeleteGromark	_ANSI_ARGS_((ClientData));
int GromarkCmd		_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, char **));

/*
 * Prototypes for procedures only referenced in this file.
 */

static int  CreateGromark	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, char **));
static char *GetGromark		_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetGromark		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
static int  RestoreGromark	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *));
static int  SolveGromark	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
static int GromarkUndo		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, int));
static int GromarkSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *, int));
static int GromarkLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *));
static void GromarkInitOffset	_ANSI_ARGS_((CipherItem *, int));
static int GromarkChainSubstitute _ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char, int));
static int EncodeGromark	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *));
static char *GromarkTransform	_ANSI_ARGS_((CipherItem *, char *, int));

/*
 * This structure contains the data associated with a single gromark cipher.
 */

typedef struct GromarkItem {
    CipherItem header;

    char ptkey[26];	/* indexed by ciphertext letters */
    char ctkey[26];	/* indexed by plaintext  letters */
    int *offset;	/* Array of offsets for plaintext letter lookup */
    int primer;
    int primerLength;	/* Number of characters in the primer */
    char *chain;	/* Shift values for each period block */
} GromarkItem;

/*
 * This structure joins the data for an aristocrat cipher with common routines
 * used to manipulate it.
 */

CipherType GromarkType = {
    "gromark",
    ATOZ,
    sizeof(GromarkItem),
    CreateGromark,	/* create proc */
    DeleteGromark,	/* delete proc */
    GromarkCmd,		/* cipher command proc */
    GetGromark,		/* get plaintext proc */
    SetGromark,		/* show ciphertext proc */
    SolveGromark,	/* solve cipher proc */
    RestoreGromark,	/* restore proc */
    GromarkLocateTip,	/* locate proc */
    GromarkSubstitute,	/* sub proc */
    GromarkUndo,	/* undo proc */
    EncodeGromark,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

/*
 * CreateGromark --
 *
 *	Create a new aristocrat cipher item.
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
CreateGromark(Tcl_Interp *interp, CipherItem *itemPtr, int argc, char **argv)
{
    GromarkItem *gromPtr = (GromarkItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    gromPtr->header.period = 0;
    gromPtr->primer=0;
    gromPtr->offset=(int *)NULL;
    itemPtr->period=0;
    gromPtr->chain = (char *)NULL;

    for(i=0; i < 26; i++) {
	gromPtr->ptkey[i] = (char)NULL;
	gromPtr->ctkey[i] = (char)NULL;
    }

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, GromarkCmd, itemPtr,
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
DeleteGromark(ClientData clientData)
{
    GromarkItem *gromPtr = (GromarkItem *)clientData;

    if (gromPtr->offset != NULL) {
	ckfree((char *)gromPtr->offset);
    }

    if (gromPtr->chain != NULL) {
	ckfree((char *)gromPtr->chain);
    }

    DeleteCipher(clientData);
}

int
GromarkCmd(ClientData clientData, Tcl_Interp *interp, int argc, char **argv)
{
    GromarkItem *gromPtr = (GromarkItem *)clientData;
    CipherItem	*itemPtr = (CipherItem *)clientData;
    char	temp_str[256];
    char	*cmd;
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
	    sprintf(temp_str, "%d", gromPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", itemPtr->period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!gromPtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_VOLATILE);
	    } else {
		Tcl_SetResult(interp, gromPtr->header.ciphertext,
			TCL_VOLATILE);
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-plaintext", 9) == 0 ||
		   strncmp(argv[1], "-ptext", 3) == 0) {
	    tPtr = (itemPtr->typePtr->decipherProc)(interp, itemPtr);

	    /*
	     * The plaintext may be empty if no primer has been set.
	     */
	    if (!tPtr) {
		return TCL_ERROR;
	    }

	    Tcl_SetResult(interp, tPtr, TCL_DYNAMIC);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-primer", 4) == 0) {
	    sprintf(temp_str, "%d", gromPtr->primer);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-offset", 4) == 0) {
	    char *offsetString = 
		    (char *)ckalloc(sizeof(char *) * (itemPtr->length + 1));
	    for(i=0; i < itemPtr->length; i++) {
		offsetString[i] = gromPtr->offset[i] + '0';
	    }
	    offsetString[i] = (char)NULL;
	    Tcl_SetResult(interp, offsetString, TCL_VOLATILE);
	    ckfree((char *)offsetString);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-keyword", 4) == 0) {
	    for(i=0; i < 26; i++) {
		temp_str[i] = (gromPtr->ctkey[i])?gromPtr->ctkey[i]:' ';
	    }
	    temp_str[i] = (char)NULL;

	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-chain", 4) == 0) {
	    temp_str[0] = (char)NULL;

	    for (i=0; i < itemPtr->period; i++) {
		temp_str[i] = gromPtr->chain[i];
		if (temp_str[i] == (char)NULL) {
		    temp_str[i] = ' ';
		}
	    }
	    temp_str[i] = (char)NULL;

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
	    } else if (strncmp(*argv, "-primer", 7) == 0) {
		int primer;
		if (sscanf(argv[1], "%d", &primer) != 1) {
		    Tcl_SetResult(interp, "Invalid primer.", TCL_VOLATILE);
		    return TCL_ERROR;
		}
		gromPtr->primer = primer;
		GromarkInitOffset(itemPtr, primer);
		Tcl_SetResult(interp, argv[1], TCL_VOLATILE);
	    } else if (strncmp(*argv, "-chain", 5) == 0) {
		/*
		 * Check for invalid characters in the new chain before
		 * destroying the old one.
		 */
		for (i=0; argv[1][i]; i++) {
		    if (argv[1][i] < 'a' || argv[1][i] > 'z') {
			temp_str[0] = argv[1][i];
			temp_str[1] = (char)NULL;
			Tcl_AppendResult(interp,
				"Invalid character found in chain:  ",
				temp_str, (char *)NULL);
			return TCL_ERROR;
		    }
		}
		if (gromPtr->chain) {
		    ckfree(gromPtr->chain);
		}
		gromPtr->chain =
			(char *)ckalloc(sizeof(char) * (strlen(argv[1]) +1));
		itemPtr->period = strlen(argv[1]);
		strcpy(gromPtr->chain, argv[1]);
		/*
		 * We use spaces to signal unset values in the chain.
		 */
		for(i=0; i < itemPtr->period; i++) {
		    if (gromPtr->chain[i] == ' ') {
			gromPtr->chain[i] = (char)NULL;
		    }
		}
		Tcl_SetResult(interp, argv[1], TCL_VOLATILE);
	    } else if (strncmp(*argv, "-period", 7) == 0) {
		int period;
		if (gromPtr->chain) {
		    ckfree(gromPtr->chain);
		}
		if (sscanf(argv[1], "%d", &period) != 1) {
		    Tcl_SetResult(interp, "Invalid period.", TCL_VOLATILE);
		    return TCL_ERROR;
		}
		gromPtr->chain = (char *)ckalloc(sizeof(char)*period);
		for (i=0; i < period; i++) {
		    gromPtr->chain[i] = (char)NULL;
		}
		itemPtr->period = period;
		GromarkInitOffset(itemPtr, gromPtr->primer);
		Tcl_SetResult(interp, argv[1], TCL_VOLATILE);
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
	if (argc < 2 || argc > 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " restore ct ?pt?",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	if (argc == 2) {
	    return (itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1], (char *)NULL);
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
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " substitute ct pt",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	if (strlen(argv[1]) != strlen(argv[2])) {
	    Tcl_SetResult(interp,
		    "ciphertext and plaintext must be the same length",
		    TCL_VOLATILE);
	    return TCL_ERROR;
	}
	if ((itemPtr->typePtr->subProc)(interp, itemPtr, argv[1], argv[2], 0)
		== BAD_SUB) {
	    return TCL_ERROR;
	} else {
	    return TCL_OK;
	}
    } else if (**argv == 'c' && (strncmp(*argv, "chainsubstitute", 8) == 0)) {
	int position;
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd,
		    " chainsubstitute ct position", (char *)NULL);
	    return TCL_ERROR;
	}
	if (sscanf(argv[2], "%d", &position) != 1) {
	    Tcl_AppendResult(interp, "Invalid chain position ", argv[2],
		    (char *)NULL);
	    return TCL_ERROR;
	}

	return GromarkChainSubstitute(interp, itemPtr, argv[1][0], position);
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
			" solve", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" substitute ct pt", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" restore ct ?pt?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" undo ct", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" locate pt ct", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" encode pt key", (char *)NULL);
	return TCL_ERROR;
    }
}

static int
SetGromark(Tcl_Interp *interp, CipherItem *itemPtr, char *ctext)
{
    GromarkItem *gromPtr = (GromarkItem *)itemPtr;
    char *c;
    int valid=TCL_OK,
    	length=0;

    length = CountValidChars(itemPtr, ctext);
    if (!length) {
	Tcl_SetResult(interp, "No valid characters found in ciphertext",
		TCL_VOLATILE);
	return TCL_ERROR;
    }
    c = ExtractValidChars(itemPtr, ctext);
    itemPtr->length = strlen(c);

    itemPtr->length = length;
    if (itemPtr->ciphertext) {
	ckfree(itemPtr->ciphertext);
    }
    itemPtr->ciphertext = c;

    if (gromPtr->primer) {
	GromarkInitOffset(itemPtr, gromPtr->primer);
    }

    Tcl_SetResult(interp, itemPtr->ciphertext, TCL_VOLATILE);

    return valid;
}

/*(
 * TODO
 */
static int
GromarkLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, char *tip, char *start)
{
    GromarkItem *gromPtr = (GromarkItem *)itemPtr;
    int		valid_tip=0,
    		i;
    char	*tipStart,
    		*c,
		*t = tip,
		*ct;
    char	used_ct[256];
    char	used_pt[256];
    char	*temp;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp,
		"Can't do anything until the ciphertext has been set",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    temp = (char *)ckalloc(sizeof(char)*strlen(tip) + 2);

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    ct = itemPtr->ciphertext;

    /*
     * Locate the starting point
     */

    if (start) {
	tipStart = strstr((const char *)ct, (const char *)start);
    } else {
	tipStart = ct;
    }

    if (!tipStart) {
	Tcl_SetResult(interp, "Starting location not found.", TCL_VOLATILE);
	return TCL_ERROR;
    }

    /*
     * Loop through every possible starting point.
     */
    for(c=tipStart;
	c <= (ct + itemPtr->length - strlen(tip)) && valid_tip!=NEW_SUB;
	c++) {
	/*
	 * Loop through every letter of the tip
	 */
	valid_tip = NEW_SUB;
	for(i=0; i < 26; i++) {
	    used_ct[i] = gromPtr->ctkey[i];
	    used_pt[i] = gromPtr->ptkey[i];
	}
	i = 0;
	for(t=tip; *t && valid_tip != BAD_SUB; t++, i++) {
	    while(c[i] && (c[i] < 'a' || c[i] > 'z')) {
		i++;
	    }
	    
	    /*
	     * Check to see that the tip won't fall off the end of the
	     * ciphertext.
	     */
	    
	    if ( (strlen(tip) - (t - tip)) + c + i > ct + strlen(ct)) {
		valid_tip = BAD_SUB;
	    } else if ((used_pt[(int)(c[i] - 'a')] &&
		    used_pt[(int)(c[i] - 'a')] != *t) ||
		    (used_ct[(int)(*t - 'a')] &&
		    used_ct[(int)(*t - 'a')] != c[i]) ||
		    *t == c[i]) {
		valid_tip = BAD_SUB;
	    } else {
		used_pt[(int)(c[i] - 'a')] = *t;
		used_ct[(int)(*t - 'a')] = c[i];
		temp[t - tip] = c[i];
	    }
	}
    }
    temp[t - tip] = (char)NULL;

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    if (valid_tip == NEW_SUB) {
	i = 0;
	for(i=0; i < 26; i++) {
	    gromPtr->ptkey[i] = used_pt[i];
	    gromPtr->ctkey[i] = used_ct[i];
	}
	Tcl_SetResult(interp, temp, TCL_VOLATILE);
	return TCL_OK;
    }

    Tcl_SetResult(interp, "", TCL_VOLATILE);

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    return TCL_OK;
}

static int
GromarkUndo(Tcl_Interp *interp, CipherItem *itemPtr, char *ct, int dummy)
{
    GromarkItem *gromPtr = (GromarkItem *)itemPtr;
    char	t;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp,
		"Can't do anything until the ciphertext has been set",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    while (*ct) {
	if (*ct >= 'a' && *ct <= 'z') {
	    t = gromPtr->ptkey[*ct - 'a'];
	    gromPtr->ptkey[*ct - 'a'] = (char)NULL;
	    if (t) {
		gromPtr->ctkey[t - 'a'] = (char)NULL;
	    }

	}
	ct++;

	Tcl_ValidateAllMemory(__FILE__, __LINE__);
    }

    Tcl_ValidateAllMemory(__FILE__, __LINE__);

    return TCL_OK;
}

static int
GromarkSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, char *ct, char *pt, int dummy)
{
    GromarkItem *gromPtr = (GromarkItem *)itemPtr;
    char	*c,
		*p,
		*q,
		*r;
    char	key_ct[26];
    char	key_pt[26];
    char	t, u;
    int		valid_sub = NEW_SUB;
    int		olap_sub=0, i;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp,
		"Can't do anything until the ciphertext has been set",
		TCL_VOLATILE);
	return BAD_SUB;
    }

    q = (char *)ckalloc(sizeof(char *) * strlen(ct));
    r = q;
    *r = (char)NULL;


    for(i=0;i<26;i++) {
	key_pt[i] = (char)NULL;
	key_ct[i] = (char)NULL;
    }

    c = ct;
    p = pt;
    while(*c && *p && valid_sub!=BAD_SUB) {
	if((*c >= 'a') && (*c <= 'z')) {
	    if ((key_pt[*c - 'a']) && (key_pt[*c - 'a'] != *p)) {
		valid_sub = BAD_SUB;
	    } else if (*p!=' ' && key_ct[*p - 'a'] && key_ct[*p - 'a'] != *c) {
		valid_sub = BAD_SUB;
	    } else {
		key_pt[*c - 'a'] = *p;
		key_ct[*p - 'a'] = *c;
	    }
	}

	c++;
       	p++;
    }

    c = ct;
    p = pt;
    while (*c && *p && valid_sub != BAD_SUB) {
	if (*c >= 'a' && *c <= 'z') {
	    t = gromPtr->ptkey[*c - 'a'];
	    u = gromPtr->ctkey[*p - 'a'];

	    if (*p < 'a' || *p > 'z') {
		if (t && gromPtr->ctkey[t - 'a']) {
		    valid_sub = ALT_SUB;
		}
	    } else if (gromPtr->ctkey[*p - 'a'] &&
		    gromPtr->ctkey[*p - 'a']!=*c) {
		valid_sub = ALT_SUB;
	    }

	    if (gromPtr->ptkey[*c - 'a'] && gromPtr->ptkey[*c - 'a']!=*p) {
		valid_sub = ALT_SUB;
	    }


	    if (*p < 'a' || *p > 'z') {
		if (t) {
		    gromPtr->ctkey[t - 'a'] = (char)NULL;
		}
		gromPtr->ptkey[*c - 'a'] = (char)NULL;
	    } else {
		if (t) {
		    gromPtr->ctkey[t-'a'] = (char)NULL;
		}
		if (u) {
		    gromPtr->ptkey[u-'a'] = (char)NULL;
		}
		gromPtr->ctkey[*p - 'a'] = *c;
		gromPtr->ptkey[*c - 'a'] = *p;
	    }

	    if (valid_sub == ALT_SUB){
		*r++ = *c;
		olap_sub = 1;
	    }
	}
	c++, p++;
    }
    *r = (char)NULL;

    if (valid_sub == BAD_SUB) {
	Tcl_SetResult(interp, "Bad Substitution", TCL_VOLATILE);
	ckfree(q);
	return BAD_SUB;
    }

    Tcl_AppendElement(interp, ct);
    Tcl_AppendElement(interp, pt);
    if (olap_sub) {
	Tcl_AppendElement(interp, q);
	valid_sub = ALT_SUB;
    }

    if (q) {
	ckfree(q);
    }

    return valid_sub;
}

static char *
GetGromark(Tcl_Interp *interp, CipherItem *itemPtr)
{
    GromarkItem *gromPtr = (GromarkItem *)itemPtr;
    char	*c;
    char	*pt=(char *)NULL;
    int		i;

    c = itemPtr->ciphertext;

    if (! gromPtr->offset) {
	Tcl_SetResult(interp,
		"Can't get plaintext until a primer has been set",
		TCL_STATIC);
	return (char *)NULL;
    }

    return GromarkTransform(itemPtr, itemPtr->ciphertext, DECODE);
}

static char *
GromarkTransform(CipherItem *itemPtr, char *text, int mode)
{
    GromarkItem *gromPtr = (GromarkItem *)itemPtr;
    char	*c;
    char	*pt=(char *)NULL;
    int		i;

    pt=(char *)ckalloc(sizeof(char)*(itemPtr->length+1));

    for(i=0; i < itemPtr->length; i++) {
	char ctLetter = text[i];
	char ptLetter = gromPtr->ptkey[(ctLetter - 'a')];

	if (ptLetter == (char)NULL) {
	    pt[i] = ' ';
	} else {
	    if (itemPtr->period) {
		/*
		 * Adjust for the chain.
		 */
		char chainLetter = gromPtr->chain[((int)(i/gromPtr->primerLength))%itemPtr->period];
		if (chainLetter && gromPtr->ptkey[chainLetter-'a']) {
		    int chainLetterOffset = gromPtr->ptkey[chainLetter-'a']-'a';
		    if (mode == DECODE) {
			pt[i] = (ptLetter - 'a' - gromPtr->offset[i] - chainLetterOffset + 52)%26 + 'a';
		    } else {
			pt[i] = gromPtr->ctkey[(ctLetter - 'a' + gromPtr->offset[i] + chainLetterOffset)%26];
		    }
		} else {
		    pt[i] = ' ';
		}
	    } else {
		if (mode == DECODE) {
		    pt[i] = (ptLetter - 'a' - gromPtr->offset[i] + 26)%26 + 'a';
		} else {
		    pt[i] = gromPtr->ctkey[(ctLetter - 'a' + gromPtr->offset[i])%26];
		}
	    }
	}
    }
    pt[i] = (char)NULL;

    return pt;
}

static int
GromarkChainSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, char value, int position)
{
    GromarkItem *gromPtr = (GromarkItem *)itemPtr;

    if (itemPtr->period == 0) {
	Tcl_SetResult(interp, "Can't modify chain until a period has been set.",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (position < 1 || position > itemPtr->period) {
	Tcl_SetResult(interp, "Invalid chain position", TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (! IsValidChar(itemPtr, value) && value != (char)NULL) {
	Tcl_SetResult(interp, "Invalid chain character", TCL_VOLATILE);
	return TCL_ERROR;
    }

    gromPtr->chain[position-1] = value;

    return TCL_OK;
}

static int
RestoreGromark(Tcl_Interp *interp, CipherItem *itemPtr, char *part1, char *part2)
{
    char *pt = part2;
    if (pt == NULL) {
	pt = "abcdefghijklmnopqrstuvwxyz";
    }
    if (strlen(part1) != strlen(pt)) {
        char length1[16];
        char length2[16];
        sprintf(length1, " (%d)", strlen(part1));
        sprintf(length2, " (%d)", strlen(pt));
        Tcl_AppendResult(interp, "Restoration key components are not the same length: ", part1, length1, " vs. ", pt, length2, (char *)NULL);
        return TCL_ERROR;
    }

    if ((itemPtr->typePtr->subProc)(interp, itemPtr, part1, pt, 0)
	    == BAD_SUB) {
	return TCL_ERROR;
    } else {
	return TCL_OK;
    }
}

static int
SolveGromark(Tcl_Interp *interp, CipherItem *itemPtr, char *junk)
{
    Tcl_SetResult(interp, "You cheat!", TCL_VOLATILE);
    return TCL_ERROR;
}

static void
GromarkInitOffset(CipherItem *itemPtr, int primer)
{
    GromarkItem *gromPtr = (GromarkItem *)itemPtr;
    char primerString[32];
    int i;

    if (itemPtr->length) {
	if (gromPtr->offset) {
	    ckfree((char *)gromPtr->offset);
	}
	gromPtr->offset = (int *)ckalloc(sizeof(int) * itemPtr->length);

	sprintf(primerString, "%d", primer);
	gromPtr->primerLength = strlen(primerString);

	for (i=0; i < gromPtr->primerLength; i++) {
	    gromPtr->offset[i] = primerString[i] - '0';
	}
	for (i=gromPtr->primerLength; i < itemPtr->length; i++) {
	    gromPtr->offset[i] = (gromPtr->offset[i-gromPtr->primerLength] + gromPtr->offset[i-(gromPtr->primerLength-1)]) % 10;
	}
    }
}

static int
EncodeGromark(Tcl_Interp *interp, CipherItem *itemPtr, char *pt, char *key) {
    GromarkItem *gromPtr = (GromarkItem *)itemPtr;
    char *ct = (char *)NULL;
    int count;
    char **argv;

    if (Tcl_SplitList(interp, key, &count, &argv) != TCL_OK) {
	return TCL_ERROR;
    }

    if (! gromPtr->primer) {
	Tcl_SetResult(interp,
		"Can't encode plaintext until a primer has been set.",
		TCL_STATIC);
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    if (count != 1) {
	ckfree((char *)argv);
	Tcl_AppendResult(interp, "Invalid number of items in encoding key '",
	      key, "'.  Should have found 1.", (char *)NULL);
	return TCL_ERROR;
    }

    if (strlen(argv[0]) != 26) {
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
    ct = GromarkTransform(itemPtr, itemPtr->ciphertext, ENCODE);
    if (ct == (char *)NULL) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, ct) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }
    ckfree(ct);
    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[0], (char *)NULL) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    Tcl_SetResult(interp, itemPtr->ciphertext, TCL_VOLATILE);
    ckfree((char *)argv);

    return TCL_OK;
}
