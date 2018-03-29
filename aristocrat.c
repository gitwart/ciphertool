/*
 * aristocrat.c --
 *
 *	This file implements the Aristocrat cipher type.
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
#include <ctype.h>
#include <cipher.h>

/* The following includes are for the autosolve routines.
 */
#include <score.h>
#include <keygen.h>

#include <cipherDebug.h>

void DeleteAristocrat		_ANSI_ARGS_((ClientData));
int AristocratCmd		_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));

/*
 * Prototypes for procedures only referenced in this file.
 */

static int  CreateAristocrat	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
static char *GetAristocrat	_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetAristocrat	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestoreAristocrat	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolveSwapAristocrat	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
static int AristocratUndo	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int AristocratSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int AristocratLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *));
static int AristocratRecKeygen	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
	    			int, int));
static int AristocratApplyBlankKeyword _ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				int));
static int AristocratRecSwap	_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int EncodeAristocrat	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));

/*
 * This structure contains the data associated with a single aristocrat cipher.
 */

typedef struct AristocratItem {
    CipherItem header;

    char ptkey[26];	/* indexed by ciphertext letters */
    char ctkey[26];	/* indexed by plaintext  letters */

    char *keyWord;	/* For solving */
    char *tempKeyWord;	/* For solving */

    double maxValue;	/* For solving */
    char maxKey[26];		/* Indexed by ciphertext letters */

    int solKeywordLength;	/* Length of keyword when solving */
    int solKeyType;		/* One of '1', '2', or '3'.  Stands for
				 * K1, K2, or K3 */

    int isStrict;	/* Indicates if a replacement substitution should
			   trigger an error.  ie:  sub aba qrs  */
} AristocratItem;

/*
 * This structure joins the data for an aristocrat cipher with common routines
 * used to manipulate it.
 */

CipherType AristocratType = {
    "aristocrat",
    "abcdefghijklmnopqrstuvwxyz -=',.;:?()/\"!*",
    sizeof(AristocratItem),
    CreateAristocrat,	/* create proc */
    DeleteAristocrat,	/* delete proc */
    AristocratCmd,	/* cipher command proc */
    GetAristocrat,	/* get plaintext proc */
    SetAristocrat,	/* show ciphertext proc */
    SolveSwapAristocrat,	/* solve cipher proc */
    RestoreAristocrat,	/* restore proc */
    AristocratLocateTip,/* locate proc */
    AristocratSubstitute,/* sub proc */
    AristocratUndo,	/* undo proc */
    EncodeAristocrat, /* encode proc*/
    (CipherType *)NULL	/* next cipher type */
};

/*
 * CreateAristocrat --
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
CreateAristocrat(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    AristocratItem *aristPtr = (AristocratItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    aristPtr->header.period = 0;
    aristPtr->keyWord = (char *)NULL;
    aristPtr->tempKeyWord = (char *)NULL;
    aristPtr->solKeyType = 2;
    aristPtr->solKeywordLength = 0;
    aristPtr->isStrict = 0;

    for(i=0; i < 26; i++) {
	aristPtr->ptkey[i] = '\0';
	aristPtr->ctkey[i] = '\0';
    }

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, AristocratCmd, itemPtr,
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
DeleteAristocrat(ClientData clientData)
{
    AristocratItem *aristPtr = (AristocratItem *)clientData;

    if (aristPtr->keyWord != NULL) {
	ckfree(aristPtr->keyWord);
    }

    if (aristPtr->tempKeyWord != NULL) {
	ckfree(aristPtr->tempKeyWord);
    }

    DeleteCipher(clientData);
}

int
AristocratCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    AristocratItem *aristPtr = (AristocratItem *)clientData;
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
	    sprintf(temp_str, "%d", aristPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", aristPtr->header.period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!aristPtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_STATIC);
	    } else {
		Tcl_SetResult(interp, aristPtr->header.ciphertext,
			TCL_VOLATILE);
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-plaintext", 9) == 0 ||
		   strncmp(argv[1], "-ptext", 3) == 0) {

#ifdef USE_DMALLOC
	    if (dmalloc_verify(NULL) == DMALLOC_VERIFY_ERROR) {
		abort();
	    }
	    Tcl_ValidateAllMemory(__FILE__, __LINE__);
#endif
	    tPtr = (itemPtr->typePtr->decipherProc)(interp, itemPtr);

	    /*
	     * The only way that tPtr will be non-null is if the allocation
	     * of memory to store the result failed.
	     */

	    if (!tPtr) {
		fprintf(stderr,
		    "Could not allocate memory to store result.  %s: line %d\n",
		    __FILE__, __LINE__);
		abort();
	    }

	    Tcl_SetResult(interp, tPtr, TCL_DYNAMIC);

#ifdef USE_DMALLOC
	    if (dmalloc_verify(NULL) == DMALLOC_VERIFY_ERROR) {
		abort();
	    }
	    Tcl_ValidateAllMemory(__FILE__, __LINE__);
#endif

	    return TCL_OK;
	} else if (strncmp(argv[1], "-key", 4) == 0) {
	    for(i=0; i < 26; i++) {
		temp_str[i] = (aristPtr->ptkey[i])?aristPtr->ptkey[i]:' ';
	    }
	    temp_str[i] = '\0';

	    Tcl_AppendElement(interp, "abcdefghijklmnopqrstuvwxyz");
	    Tcl_AppendElement(interp, temp_str);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-K1key", 4) == 0) {
	    for(i=0; i < 26; i++) {
		temp_str[i] = (aristPtr->ptkey[i])?aristPtr->ptkey[i]:' ';
	    }
	    temp_str[i] = '\0';

	    Tcl_AppendElement(interp, "abcdefghijklmnopqrstuvwxyz");
	    Tcl_AppendElement(interp, temp_str);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-K2key", 4) == 0) {
	    for(i=0; i < 26; i++) {
		temp_str[i] = (aristPtr->ctkey[i])?aristPtr->ctkey[i]:' ';
	    }
	    temp_str[i] = '\0';

	    Tcl_AppendElement(interp, "abcdefghijklmnopqrstuvwxyz");
	    Tcl_AppendElement(interp, temp_str);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-strict", 7) == 0) {
	    sprintf(temp_str, "%d", aristPtr->isStrict);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-solkeytype", 8) == 0) {
	    sprintf(temp_str, "%d", aristPtr->solKeyType);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-solkeywordlength", 8) == 0) {
	    sprintf(temp_str, "%d", aristPtr->solKeywordLength);
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
	    } else if (strncmp(*argv, "-solkeytype", 8) == 0) {
		if (sscanf(argv[1], "%d", &i) != 1) {
		    Tcl_SetResult(interp,
			    "Invalid key type.  Must be one of '1', '2', or '3'.",
			    TCL_STATIC);
		    return TCL_ERROR;
		}
		if (i != 1 && i != 2 && i != 3) {
		    Tcl_SetResult(interp,
			    "Invalid key type.  Must be one of '1', '2', or '3'.",
			    TCL_STATIC);
		    return TCL_ERROR;
		}

		aristPtr->solKeyType = i;
		Tcl_SetResult(interp, argv[1], TCL_VOLATILE);
	    } else if (strncmp(*argv, "-solkeywordlength", 8) == 0) {
		if (sscanf(argv[1], "%d", &i) != 1) {
		    Tcl_SetResult(interp,
			    "Invalid keyword length.  Must be between 1 and 26",
			    TCL_STATIC);
		    return TCL_ERROR;
		}
		if (i < 1 || i > 26) {
		    Tcl_SetResult(interp,
			    "Invalid keyword length.  Must be between 1 and 26",
			    TCL_STATIC);
		    return TCL_ERROR;
		}

		aristPtr->solKeywordLength = i;
		Tcl_SetResult(interp, argv[1], TCL_VOLATILE);
	    } else if (strncmp(*argv, "-stepinterval", 12) == 0) {
		if (argc < 2) {
		    Tcl_AppendResult(interp, "Usage:  ", cmd, " configure -stepinterval val", (char *)NULL);
		    return TCL_ERROR;
		}

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
	    } else if (strncmp(*argv, "-strict", 7) == 0) {
		return Tcl_GetBoolean(interp, argv[1], &(aristPtr->isStrict));
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
    } else if (**argv == 'r' && (strncmp(*argv, "restore", 1) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " restore ct pt",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	return (itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1], argv[2]);
    } else if (**argv == 's' && (strncmp(*argv, "substitute", 2) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " substitute ct pt",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	if (strlen(argv[1]) != strlen(argv[2])) {
	    Tcl_SetResult(interp,
		    "ciphertext and plaintext must be the same length",
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
	if ((itemPtr->typePtr->solveProc)(interp, itemPtr, temp_str) != TCL_OK)
	    return TCL_ERROR;

	Tcl_SetResult(interp, temp_str, TCL_VOLATILE);

	return TCL_OK;
    } else if (**argv == 'u' && (strncmp(*argv, "undo", 1) == 0)) {
	const char *ct = NULL;
	if (argc != 1 && argc != 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " undo ?ct?",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	if (argc == 2) {
	    ct = argv[1];
	}

	if ((itemPtr->typePtr->undoProc)(interp, itemPtr, ct, 0) == TCL_OK) {
	    Tcl_SetResult(interp, "", TCL_STATIC);
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
			" restore ct pt", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" substitute ct pt", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" undo ?ct?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" locate pt ct", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" encode pt key", (char *)NULL);
	return TCL_ERROR;
    }
}

static int
SetAristocrat(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
{
    char	*c;
    char	*e;
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
        const char *iter;
	itemPtr->length = length;
	if (itemPtr->ciphertext) {
	    ckfree(itemPtr->ciphertext);
	}

	itemPtr->ciphertext = (char *)ckalloc(sizeof(char)*length + 2);
	if (itemPtr->ciphertext == NULL) {
	    Tcl_SetResult(interp, "Error mallocing memory for new cipher",
		    TCL_STATIC);
	    return TCL_ERROR;
	}
	itemPtr->length = length;

	iter = ctext;
	e = itemPtr->ciphertext;

	while((*e++ = *iter++));
	Tcl_SetResult(interp, itemPtr->ciphertext, TCL_STATIC);
    } else {
	badchar[1] = '\0';
	Tcl_AppendResult(interp, "Bad character in ciphertext:  ", badchar,
	       	(char *)NULL);
    }

    return valid;
}

static int
AristocratLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, char *tip, char *start)
{
    AristocratItem *aristPtr = (AristocratItem *)itemPtr;
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
		TCL_STATIC);
	return TCL_ERROR;
    }

    ct = itemPtr->ciphertext;

    /*
     * Locate the starting point
     */

    if (start) {
	if (sscanf(start, "%d", &i) == 1) {
	    tipStart = ct + i;
	} else {
	    tipStart = strstr((const char *)ct, (const char *)start);
	}
    } else {
	tipStart = ct;
    }

    if (!tipStart) {
	Tcl_SetResult(interp, "Starting location not found.", TCL_STATIC);
	return TCL_ERROR;
    }

    temp = (char *)ckalloc(sizeof(char)*strlen(tip) + 2);

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
	    used_ct[i] = aristPtr->ctkey[i];
	    used_pt[i] = aristPtr->ptkey[i];
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
    temp[t - tip] = '\0';

    if (valid_tip == NEW_SUB) {
	i = 0;
	for(i=0; i < 26; i++) {
	    aristPtr->ptkey[i] = used_pt[i];
	    aristPtr->ctkey[i] = used_ct[i];
	}
	Tcl_SetResult(interp, temp, TCL_DYNAMIC);
	return TCL_OK;
    }

    Tcl_SetResult(interp, "", TCL_STATIC);

    ckfree((char *)temp);

    return TCL_OK;
}

static int
AristocratUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int dummy)
{
    AristocratItem *aristPtr = (AristocratItem *)itemPtr;
    char	t;
    int		i;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp,
		"Can't do anything until the ciphertext has been set",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (ct == NULL) {
	for (i=0; i < 26; i++) {
	    aristPtr->ptkey[i] = '\0';
	    aristPtr->ctkey[i] = '\0';
	}
    } else {
	while (*ct) {
	    if (*ct >= 'a' && *ct <= 'z') {
		t = aristPtr->ptkey[*ct - 'a'];
		aristPtr->ptkey[*ct - 'a'] = '\0';
		if (t) {
		    aristPtr->ctkey[t - 'a'] = '\0';
		}

	    }
	    ct++;
	}
    }

    return TCL_OK;
}

static int
AristocratSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, const char *pt, int dummy)
{
    AristocratItem *aristPtr = (AristocratItem *)itemPtr;
    char	*c,
		*p,
		replacedCtSet[27],
		*r;
    char	key_ct[26];
    char	key_pt[26];
    char	ptOrig, ctOrig;
    char	ptKeyOrig[26];
    char	ctKeyOrig[26];
    int		valid_sub = NEW_SUB;
    int		single_sub_type = NEW_SUB;
    int		olap_sub=0, i;
    int		ptIndex = 0;
    int		ctIndex = 0;
    int		ctIsReplaced[26];

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp,
		"Can't do anything until the ciphertext has been set",
		TCL_STATIC);
	return BAD_SUB;
    }

    for(i=0;i<26;i++) {
	key_pt[i] = '\0';
	key_ct[i] = '\0';
	ctKeyOrig[i] = aristPtr->ctkey[i];
	ptKeyOrig[i] = aristPtr->ptkey[i];
	replacedCtSet[i] = '\0';
	ctIsReplaced[i] = 0;
    }

    c = ct;
    p = pt;
    /*
     * Check that the substitution is internally consistent
     */
    while(*c && *p && valid_sub!=BAD_SUB) {
	ptIndex = *c - 'a';
	ctIndex = *p - 'a';
	if((ptIndex >= 0) && (ptIndex < 26)) {
	    if ((key_pt[ptIndex]) && (key_pt[ptIndex] != *p)) {
		valid_sub = BAD_SUB;
	    } else if (*p!=' ' && key_ct[ctIndex] && key_ct[ctIndex] != *c) {
		valid_sub = BAD_SUB;
	    } else if (aristPtr->isStrict \
			&& aristPtr->ptkey[*c-'a'] \
			&& aristPtr->ptkey[*c-'a'] != *p) {
		valid_sub = BAD_SUB;
	    } else if (aristPtr->isStrict \
			&& *p >= 'a' && *p <= 'z'
			&& aristPtr->ctkey[*p-'a'] \
			&& aristPtr->ctkey[*p-'a'] != *c) {
		valid_sub = BAD_SUB;
	    } else {
		key_pt[ptIndex] = *p;
		key_ct[ctIndex] = *c;
	    }
	}

	c++;
       	p++;
    }

    /*
     * Shortcut the operation if we already know this is a bad
     * substitution.
     */
    if (valid_sub == BAD_SUB) {
	Tcl_SetResult(interp, "Bad Substitution", TCL_STATIC);
	return BAD_SUB;
    }

    c = ct;
    p = pt;
    /*
     * Check if the substitution has any side effects in the current
     * cipher key, and update the key.
     */
    while (*c && *p && valid_sub != BAD_SUB) {
	single_sub_type = NEW_SUB;
	if (*c >= 'a' && *c <= 'z') {
	    ptOrig = aristPtr->ptkey[*c - 'a'];
	    ctOrig = aristPtr->ctkey[*p - 'a'];

	    /* Are we moving a pt letter from one ct to another.
	     * ie:  abc->e__ -> abc->_e_
	     */
	    if (*p < 'a' || *p > 'z') {
		if (ptOrig && aristPtr->ctkey[ptOrig - 'a']) {
		    single_sub_type = ALT_SUB;
		    ctIsReplaced[aristPtr->ctkey[ptOrig - 'a'] - 'a'] = 1;
		}
	    /* Are we replacing an existing ct->pt mapping?
	     * ie:  abc->cd_ -> abc_>cef  (e moves) */
	    } else if (ctOrig && ctOrig!=*c) {
		single_sub_type = ALT_SUB;
		ctIsReplaced[ctOrig - 'a'] = 1;
	    }

	    /* Are we changing the pt letter prepresnted by this
	     * ct letter? */
	    if (ptOrig && ptOrig!=*p) {
		single_sub_type = ALT_SUB;
		ctIsReplaced[*c - 'a'] = 1;
	    }

	    if (*p < 'a' || *p > 'z') {
		if (ptOrig) {
		    aristPtr->ctkey[ptOrig - 'a'] = '\0';
		}
		aristPtr->ptkey[*c - 'a'] = '\0';
	    } else {
		if (ptOrig) {
		    aristPtr->ctkey[ptOrig-'a'] = '\0';
		}
		if (ctOrig) {
		    aristPtr->ptkey[ctOrig-'a'] = '\0';
		}
		aristPtr->ctkey[*p - 'a'] = *c;
		aristPtr->ptkey[*c - 'a'] = *p;
	    }

	    if (single_sub_type == ALT_SUB){
		olap_sub = 1;
		valid_sub = ALT_SUB;
		if (aristPtr->isStrict) {
		    valid_sub = BAD_SUB;
		}
	    }
	}
	c++, p++;
    }

    r = replacedCtSet;
    for (i=0; i < 26; i++) {
	if (ctIsReplaced[i]) {
	    *r++ = i + 'a';
	}
    }
    *r = '\0';

    if (valid_sub == BAD_SUB) {
	/*
	 * Restore the original key.
	 */
	for (i=0; i < 26; i++) {
	    aristPtr->ctkey[i] = ctKeyOrig[i];
	    aristPtr->ptkey[i] = ptKeyOrig[i];
	}
	Tcl_SetResult(interp, "Bad Substitution", TCL_STATIC);
	return BAD_SUB;
    }

    Tcl_AppendElement(interp, ct);
    Tcl_AppendElement(interp, pt);
    if (olap_sub) {
	Tcl_AppendElement(interp, replacedCtSet);
	valid_sub = ALT_SUB;
    }

    return valid_sub;
}

static char *
GetAristocrat(Tcl_Interp *interp, CipherItem *itemPtr)
{
    AristocratItem *aristPtr = (AristocratItem *)itemPtr;
    char	*c;
    char	*pt=(char *)ckalloc(sizeof(char)*(strlen(itemPtr->ciphertext)+1));
    int		index=0;

    c = itemPtr->ciphertext;

    while(*c) {
	if (*c < 'a' || *c > 'z') {
	    pt[index] = *c;
	} else {
	    if (aristPtr->ptkey[*c - 'a']) {
		pt[index] = aristPtr->ptkey[*c - 'a'];
	    } else {
		pt[index] = ' ';
	    }
	}

	c++, index++;
    }

    pt[index] = '\0';

    return pt;
}

static int
RestoreAristocrat(Tcl_Interp *interp, CipherItem *itemPtr, const char *part1, const char *part2)
{
    if ((itemPtr->typePtr->subProc)(interp, itemPtr, part1, part2, 0)
	    == BAD_SUB) {
	return TCL_ERROR;
    } else {
	return TCL_OK;
    }
}

static int
SolveSwapAristocrat(Tcl_Interp *interp, CipherItem *itemPtr, char *junk)
{
    AristocratItem *aristPtr = (AristocratItem *)itemPtr;
    int i;
    int result;
    int initKey=0;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp,
		"Can't do anything until the ciphertext has been set",
		TCL_STATIC);
	return TCL_ERROR;
    }
    if (aristPtr->solKeywordLength == 0) {
	Tcl_SetResult(interp,
		"Can't do anything until the keyword length has been set",
		TCL_STATIC);
	return TCL_ERROR;
    }

    aristPtr->maxValue = 0.0;
    itemPtr->curIteration = 0;
    for (i=0; i < 26; i++) {
	aristPtr->maxKey[i] = '\0';
    }

    /*
     * Initialize the key if it hasn't been already.
     */

    for(i=0; i < 26; i++) {
	if (aristPtr->ptkey[i] == '\0') {
	    initKey = 1;
	}
    }

    if (initKey) {
	for(i=0; i < 26; i++) {
	    aristPtr->ptkey[i] = i+'a';
	    aristPtr->ctkey[i] = i+'a';
	}
    }

    result = AristocratRecSwap(interp, itemPtr);

    if (result == TCL_OK) {
	for(i=0; i < 26; i++) {
	    aristPtr->ptkey[i] = aristPtr->maxKey[i];
	    aristPtr->ctkey[aristPtr->ptkey[i] - 'a'] = i + 'a';
	}

	Tcl_SetResult(interp, "", TCL_STATIC);
    }

    ckfree(aristPtr->keyWord);
    aristPtr->keyWord = (char *)NULL;

    return result;
}

static int
AristocratRecSwap(Tcl_Interp *interp, CipherItem *itemPtr)
{
    AristocratItem *aristPtr = (AristocratItem *)itemPtr;
    int i;
    int pos1, pos2;
    int maximaFound=0;
    char *pt;
    double maxValue = 0.0;

    pt = GetAristocrat(interp, itemPtr);
    if (DefaultScoreValue(interp, (const char *)pt, &aristPtr->maxValue)
            != TCL_OK) {
	return TCL_ERROR;
    }
    for(i=0; i < 26; i++) {
	aristPtr->maxKey[i] = aristPtr->ptkey[i];
    }
    ckfree(pt);

    while (! maximaFound) {
	maximaFound = 1;

	for(pos1=0; pos1 < 25; pos1++) {
	    for(pos2=pos1+1; pos2 < 26; pos2++) {
		char temp;
		double value;
		Tcl_DString dsPtr;

		/*
		 * Swap key positions i/j.  Undo the swap if the digram
		 * value isn't better than the current.
		 */

		temp = aristPtr->ptkey[pos1];
		aristPtr->ptkey[pos1] = aristPtr->ptkey[pos2];
		aristPtr->ptkey[pos2] = temp;

		aristPtr->ctkey[aristPtr->ptkey[pos1]-'a'] = pos1+'a';
		aristPtr->ctkey[aristPtr->ptkey[pos2]-'a'] = pos2+'a';

		pt = GetAristocrat(interp, itemPtr);
		if (DefaultScoreValue(interp, (const char *)pt, &value)
                        != TCL_OK) {
		    return TCL_ERROR;
		}

		if (itemPtr->stepInterval && itemPtr->curIteration % itemPtr->stepInterval == 0 && itemPtr->stepCommand && pt) {
		    char temp_str[128];

		    Tcl_DStringInit(&dsPtr);

		    Tcl_DStringAppendElement(&dsPtr, itemPtr->stepCommand);

		    sprintf(temp_str, "%ld", itemPtr->curIteration);
		    Tcl_DStringAppendElement(&dsPtr, temp_str);

		    for(i=0; i < 26; i++) {
			temp_str[i] = aristPtr->ptkey[i];
			if (temp_str[i] == '\0') {
			    temp_str[i] = ' ';
			}
		    }
		    temp_str[i] = '\0';
		    Tcl_DStringAppendElement(&dsPtr, temp_str);

		    Tcl_DStringAppendElement(&dsPtr, pt);

		    if (Tcl_Eval(interp, Tcl_DStringValue(&dsPtr)) != TCL_OK) {
			Tcl_DStringFree(&dsPtr);
			return TCL_ERROR;
		    }
		    Tcl_DStringFree(&dsPtr);
		}

		if (value > maxValue) {
		    char temp_str[128];
		    Tcl_DStringInit(&dsPtr);

		    maximaFound = 0;

		    if (itemPtr->bestFitCommand) {
			Tcl_DStringAppendElement(&dsPtr, itemPtr->bestFitCommand);
		    }

		    sprintf(temp_str, "%ld", itemPtr->curIteration);
		    Tcl_DStringAppendElement(&dsPtr, temp_str);

		    /*
		     * Store the local maximum
		     */
		    maxValue = value;
		    for(i=0; i < 26; i++) {
			aristPtr->maxKey[i] = aristPtr->ptkey[i];
		    }

		    for(i=0; i < 26; i++) {
			temp_str[i] = aristPtr->ptkey[i];
			if (temp_str[i] == '\0') {
			    temp_str[i] = ' ';
			}
		    }
		    temp_str[26] = '\0';
		    Tcl_DStringAppendElement(&dsPtr, temp_str);

		    sprintf(temp_str, "%g", value);
		    Tcl_DStringAppendElement(&dsPtr, temp_str);

		    Tcl_DStringAppendElement(&dsPtr, pt);

		    if (itemPtr->bestFitCommand) {
			if (Tcl_Eval(interp, Tcl_DStringValue(&dsPtr)) != TCL_OK) {
			    Tcl_DStringFree(&dsPtr);
			    return TCL_ERROR;
			}
		    }

		    Tcl_DStringFree(&dsPtr);
		} else {
		    /*
		     * This swap produced bad results.  Undo it.
		     */
		    temp = aristPtr->ptkey[pos1];
		    aristPtr->ptkey[pos1] = aristPtr->ptkey[pos2];
		    aristPtr->ptkey[pos2] = temp;

		    aristPtr->ctkey[aristPtr->ptkey[pos1]-'a'] = pos1+'a';
		    aristPtr->ctkey[aristPtr->ptkey[pos2]-'a'] = pos2+'a';
		}

		itemPtr->curIteration++;

		ckfree(pt);
	    }
	}
    }

    return TCL_OK;
}

static int
AristocratRecKeygen(Tcl_Interp *interp, CipherItem *itemPtr, int period, int depth)
{
    AristocratItem *aristPtr = (AristocratItem *)itemPtr;
    int result;

    if (depth >= period) {
	/*
	 * Find every permutation of the letters in the keyword and see how
	 * well they fit
	 */

	/*
	result = _internalDoPermCmd((ClientData)itemPtr, interp, period,
		AristocratCheckSolutionValue);
	*/

	result = AristocratApplyBlankKeyword(interp, itemPtr, period);

	if (result != TCL_OK) {
	    return result;
	}
    } else {
	for(; aristPtr->keyWord[depth] <= 'z'; aristPtr->keyWord[depth]++) {
	    /*
	     * Set the starting position for the next key position
	     */

	    if (depth < period - 1) {
		aristPtr->keyWord[depth+1] = aristPtr->keyWord[depth] + 1;
	    }

	    result = AristocratRecKeygen(interp, itemPtr, period, depth+1);

	    /*
	     * Break out of the loop if an error occurred
	     */

	    if (result != TCL_OK) {
		return result;
	    }
	}
    }

    return TCL_OK;
}

static int
AristocratApplyBlankKeyword(Tcl_Interp *interp, CipherItem *itemPtr, int period)
{
    AristocratItem *aristPtr = (AristocratItem *)itemPtr;
    char keyedAlphabet[27];
    char fixedKey[27];
    int i,
    	j;
    double value;
    char *pt;
    Tcl_DString dsPtr;

    KeyGenerateK1(interp, aristPtr->keyWord, fixedKey);
    /*
     * Blank out the keyword
     */
    /*
    for(i=0; i < period; i++) {
	fixedKey[i] = '\0';
    }
    */

    /*
     * Check the best fit for all 26 possible keys
     */

    for(i=0; i < 26; i++) {
	/*
	 * Apply the key according to the set key type (K1, K2, K3)
	 */

	if (aristPtr->solKeyType == 1) {
	    for(j=0; j < 26; j++) {
		keyedAlphabet[(i+j)%26] = fixedKey[j];
		aristPtr->ptkey[(i+j)%26] = fixedKey[j];
		if (fixedKey[j]) {
		    aristPtr->ctkey[fixedKey[j]-'a'] = (i+j)%26 + 'a';
		} else {
		    aristPtr->ctkey[fixedKey[j]-'a'] = '\0';
		}
	    }
	} else if (aristPtr->solKeyType == 2) {
	    for(j=0; j < 26; j++) {
		aristPtr->ptkey[j] = '\0';
	    }
	    for(j=0; j < 26; j++) {
		keyedAlphabet[(i+j)%26] = fixedKey[j];
		aristPtr->ctkey[(i+j)%26] = fixedKey[j];
		if (fixedKey[j]) {
		    aristPtr->ptkey[fixedKey[j]-'a'] = (i+j)%26 + 'a';
		} else {
		    aristPtr->ptkey[fixedKey[j]-'a'] = '\0';
		}
	    }
	} else if (aristPtr->solKeyType == 3) {
	    /*
	     * TODO:  Test this.  I think it's wrong.
	     */
	    for(j=0; j < 26; j++) {
		aristPtr->ptkey[j] = '\0';
		aristPtr->ctkey[j] = '\0';
	    }
	    for(j=0; j < 26; j++) {
		keyedAlphabet[(i+j)%26] = fixedKey[j];

		if (fixedKey[j]) {
		    aristPtr->ptkey[fixedKey[j]-'a'] = (i+j)%26 + 'a';
		    aristPtr->ctkey[(i+j)%26] = fixedKey[j];
		}
	    }
	}
	keyedAlphabet[26] = '\0';

	pt = GetAristocrat(interp, itemPtr);
	if (DefaultScoreValue(interp, (const char *)pt, &value) != TCL_OK) {
	    return TCL_ERROR;
	}

	if (itemPtr->stepInterval && itemPtr->curIteration % itemPtr->stepInterval == 0 && itemPtr->stepCommand && pt) {
	    char temp_str[128];

	    Tcl_DStringInit(&dsPtr);

	    Tcl_DStringAppendElement(&dsPtr, itemPtr->stepCommand);

	    sprintf(temp_str, "%ld", itemPtr->curIteration);
	    Tcl_DStringAppendElement(&dsPtr, temp_str);

	    Tcl_DStringStartSublist(&dsPtr);
	    for(i=0; i < 26; i++) {
		temp_str[i] = keyedAlphabet[i];
		if (temp_str[i] == '\0') {
		    temp_str[i] = ' ';
		}
	    }
	    temp_str[i] = '\0';
	    Tcl_DStringAppendElement(&dsPtr, temp_str);
	    Tcl_DStringAppendElement(&dsPtr, aristPtr->keyWord);
	    Tcl_DStringEndSublist(&dsPtr);

	    Tcl_DStringAppendElement(&dsPtr, pt);

	    if (Tcl_Eval(interp, Tcl_DStringValue(&dsPtr)) != TCL_OK) {
		Tcl_DStringFree(&dsPtr);
		if (pt) {
		    ckfree(pt);
		}
		return TCL_ERROR;
	    }
	    Tcl_DStringFree(&dsPtr);
	}

	if (value > aristPtr->maxValue) {
	    char temp_str[128];
	    Tcl_DStringInit(&dsPtr);

	    if (itemPtr->bestFitCommand) {
		Tcl_DStringAppendElement(&dsPtr, itemPtr->bestFitCommand);
	    }

	    sprintf(temp_str, "%ld", itemPtr->curIteration);
	    Tcl_DStringAppendElement(&dsPtr, temp_str);

	    aristPtr->maxValue = value;

	    Tcl_DStringStartSublist(&dsPtr);
	    for(i=0; i < 26; i++) {
		temp_str[i] = keyedAlphabet[i];
		if (temp_str[i] == '\0') {
		    temp_str[i] = ' ';
		}
	    }
	    temp_str[26] = '\0';
	    Tcl_DStringAppendElement(&dsPtr, temp_str);
	    Tcl_DStringAppendElement(&dsPtr, aristPtr->keyWord);
	    Tcl_DStringEndSublist(&dsPtr);

	    sprintf(temp_str, "%g", value);
	    Tcl_DStringAppendElement(&dsPtr, temp_str);

	    Tcl_DStringAppendElement(&dsPtr, pt);

	    if (itemPtr->bestFitCommand) {
		if (Tcl_Eval(interp, Tcl_DStringValue(&dsPtr)) != TCL_OK) {
		    if (pt) {
			ckfree(pt);
		    }
		    Tcl_DStringFree(&dsPtr);
		    return TCL_ERROR;
		}
	    }

	    Tcl_DStringFree(&dsPtr);
	}
	itemPtr->curIteration++;

	/*
	fprintf(stdout, "key: %s (%d) (%d)\npt: %s\n", aristPtr->keyWord,
		value, itemPtr->curIteration, pt);
	*/
	ckfree(pt);
    }

    return TCL_OK;
}

static int
EncodeAristocrat(Tcl_Interp *interp, CipherItem *itemPtr, const char *pt, const char *key) {
    char *ct = (char *)NULL;
    int count;
    char **argv;

    if (Tcl_SplitList(interp, key, &count, &argv) != TCL_OK) {
	return TCL_ERROR;
    }

    if (count != 2) {
	ckfree((char *)argv);
	Tcl_AppendResult(interp, "Invalid number of items in encoding key '",
	      key, "'.  Should have found 2.", (char *)NULL);
	return TCL_ERROR;
    }

    if (strlen(argv[0]) != 26 || strlen(argv[1]) != 26) {
	Tcl_SetResult(interp, "Invalid length of key elements.", TCL_STATIC);
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, pt) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }
    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1], argv[0]) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }
    ct = (itemPtr->typePtr->decipherProc)(interp, itemPtr);
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

    Tcl_SetResult(interp, ct, TCL_DYNAMIC);
    ckfree((char *)argv);

    return TCL_OK;
}
