/*
 * quagmire.c --
 *
 *	This file implements the Quagmire I-IV cipher types.
 *
 * Copyright (c) 2008 Michael Thomas <wart@kobold.org>
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

void DeleteQuagmire		_ANSI_ARGS_((ClientData));
int QuagmireCmd		        _ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));

/*
 * Prototypes for procedures only referenced in this file.
 */

static int  CreateQuagmire	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
static char *GetQuagmire	_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetQuagmire	        _ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestoreQuagmire	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static void QuagmireSetPeriod   _ANSI_ARGS_((CipherItem *, int));
static int QuagmireUndo	        _ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int QuagmireSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int QuagmireLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int EncodeQuagmire	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int SolveQuagmire	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));

/*
 * This structure contains the data associated with a single quagmire cipher.
 */

typedef struct QuagmireItem {
    CipherItem header;

    char **ptkey;	/* indexed by ciphertext letters */
    char **ctkey;	/* indexed by plaintext  letters */

    double maxValue;	/* For solving */
    char **maxKey;	/* Indexed by ciphertext letters */

    int isStrict;	/* Indicates if a replacement substitution should
			   trigger an error.  ie:  sub aba qrs  */
} QuagmireItem;

/*
 * This structure joins the data for an quagmire cipher with common routines
 * used to manipulate it.
 */

CipherType Quagmire1Type = {
    "quagmire1",
    ATOZ,
    sizeof(QuagmireItem),
    CreateQuagmire,	/* create proc */
    DeleteQuagmire,	/* delete proc */
    QuagmireCmd,	/* cipher command proc */
    GetQuagmire,	/* get plaintext proc */
    SetQuagmire,	/* show ciphertext proc */
    SolveQuagmire,	/* solve cipher proc */
    RestoreQuagmire,	/* restore proc */
    QuagmireLocateTip,/* locate proc */
    QuagmireSubstitute,/* sub proc */
    QuagmireUndo,	/* undo proc */
    EncodeQuagmire, /* encode proc*/
    (CipherType *)NULL	/* next cipher type */
};
CipherType Quagmire2Type = {
    "quagmire2",
    ATOZ,
    sizeof(QuagmireItem),
    CreateQuagmire,	/* create proc */
    DeleteQuagmire,	/* delete proc */
    QuagmireCmd,	/* cipher command proc */
    GetQuagmire,	/* get plaintext proc */
    SetQuagmire,	/* show ciphertext proc */
    SolveQuagmire,	/* solve cipher proc */
    RestoreQuagmire,	/* restore proc */
    QuagmireLocateTip,/* locate proc */
    QuagmireSubstitute,/* sub proc */
    QuagmireUndo,	/* undo proc */
    EncodeQuagmire, /* encode proc*/
    (CipherType *)NULL	/* next cipher type */
};
CipherType Quagmire3Type = {
    "quagmire3",
    ATOZ,
    sizeof(QuagmireItem),
    CreateQuagmire,	/* create proc */
    DeleteQuagmire,	/* delete proc */
    QuagmireCmd,	/* cipher command proc */
    GetQuagmire,	/* get plaintext proc */
    SetQuagmire,	/* show ciphertext proc */
    SolveQuagmire,	/* solve cipher proc */
    RestoreQuagmire,	/* restore proc */
    QuagmireLocateTip,/* locate proc */
    QuagmireSubstitute,/* sub proc */
    QuagmireUndo,	/* undo proc */
    EncodeQuagmire, /* encode proc*/
    (CipherType *)NULL	/* next cipher type */
};
CipherType Quagmire4Type = {
    "quagmire4",
    ATOZ,
    sizeof(QuagmireItem),
    CreateQuagmire,	/* create proc */
    DeleteQuagmire,	/* delete proc */
    QuagmireCmd,	/* cipher command proc */
    GetQuagmire,	/* get plaintext proc */
    SetQuagmire,	/* show ciphertext proc */
    SolveQuagmire,	/* solve cipher proc */
    RestoreQuagmire,	/* restore proc */
    QuagmireLocateTip,/* locate proc */
    QuagmireSubstitute,/* sub proc */
    QuagmireUndo,	/* undo proc */
    EncodeQuagmire, /* encode proc*/
    (CipherType *)NULL	/* next cipher type */
};
/*
 * TODO:  Add types for quagmire II -> IV
 */

/*
 * CreateQuagmire --
 *
 *	Create a new quagmire cipher item.
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
CreateQuagmire(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    QuagmireItem *quagPtr = (QuagmireItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    quagPtr->header.period = 0;

    quagPtr->ptkey = (char **)NULL;
    quagPtr->ctkey = (char **)NULL;

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, QuagmireCmd, itemPtr,
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
DeleteQuagmire(ClientData clientData)
{
    QuagmireSetPeriod(clientData, 0);

    DeleteCipher(clientData);
}

void
QuagmireSetPeriod(CipherItem *itemPtr, int period)
{
    QuagmireItem *quagPtr = (QuagmireItem *)itemPtr;
    int i;

    if (period < 0) {
        return;
    }

    if (itemPtr->period > 0) {
        for (i=0; i < itemPtr->period; i++) {
            ckfree((char *) quagPtr->ptkey[i]);
            ckfree((char *) quagPtr->ctkey[i]);
        }
        ckfree((char *) quagPtr->ptkey);
        ckfree((char *) quagPtr->ctkey);
    }

    if (period > 0) {
        int j;

        quagPtr->ptkey = (char **)ckalloc(sizeof(char *) * period);
        quagPtr->ctkey = (char **)ckalloc(sizeof(char *) * period);
        for (i=0; i < period; i++) {
            quagPtr->ptkey[i]  = (char *)ckalloc(sizeof(char) * 26);
            quagPtr->ctkey[i]  = (char *)ckalloc(sizeof(char) * 26);
            for (j=0; j < 26; j++) {
                quagPtr->ptkey[i][j] = '\0';
                quagPtr->ctkey[i][j] = '\0';
            }
        }
        itemPtr->period = period;
    }

}

int
QuagmireCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    QuagmireItem *quagPtr = (QuagmireItem *)clientData;
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
	    sprintf(temp_str, "%d", quagPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", quagPtr->header.period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!quagPtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_STATIC);
	    } else {
		Tcl_SetResult(interp, quagPtr->header.ciphertext,
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
            int keyRow;
            /*
             * TODO:  How to display when period == 0?
             * TODO:  Display K1 or K2 as a-z depending on cipher type
             */
            if (itemPtr->typePtr->type[8] == '1') {
                Tcl_AppendElement(interp, "abcdefghijklmnopqrstuvwxyz");

                for (keyRow=0; keyRow < itemPtr->period; keyRow++) {
                    for(i=0; i < 26; i++) {
                        temp_str[i] = (quagPtr->ctkey[keyRow][i])?quagPtr->ctkey[keyRow][i]:' ';
                    }
                    temp_str[i] = '\0';
                    Tcl_AppendElement(interp, temp_str);
                }
            } else if (itemPtr->typePtr->type[8] == '2') {
                Tcl_AppendElement(interp, "abcdefghijklmnopqrstuvwxyz");

                for (keyRow=0; keyRow < itemPtr->period; keyRow++) {
                    for(i=0; i < 26; i++) {
                        temp_str[i] = (quagPtr->ctkey[keyRow][i])?quagPtr->ctkey[keyRow][i]:' ';
                    }
                    temp_str[i] = '\0';
                    Tcl_AppendElement(interp, temp_str);
                }
            } else {
                Tcl_AppendElement(interp, "abcdefghijklmnopqrstuvwxyz");

                for (keyRow=0; keyRow < itemPtr->period; keyRow++) {
                    for(i=0; i < 26; i++) {
                        temp_str[i] = (quagPtr->ctkey[keyRow][i])?quagPtr->ctkey[keyRow][i]:' ';
                    }
                    temp_str[i] = '\0';
                    Tcl_AppendElement(interp, temp_str);
                }
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
	    } else if (strncmp(*argv, "-period", 7) == 0) {

		if (sscanf(argv[1], "%d", &i) != 1) {
		    Tcl_AppendResult(interp, "Bad period.  Integer expected:  ",
			    argv[1], (char *)NULL);
		    return TCL_ERROR;
		}
                if (i < 0) {
		    Tcl_AppendResult(interp,
                            "period must be greater than 0.  Found ",
			    argv[1], (char *)NULL);
		    return TCL_ERROR;
                }
		QuagmireSetPeriod(itemPtr, i);
                Tcl_SetObjResult(interp, Tcl_NewStringObj(argv[1], -1));
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
        int keyRow = 0;

	if (argc != 4) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " substitute ct pt keyRow",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	if (strlen(argv[1]) != strlen(argv[2])) {
	    Tcl_SetResult(interp,
		    "ciphertext and plaintext must be the same length",
		    TCL_STATIC);
	    return TCL_ERROR;
	}

        if (sscanf(argv[3], "%d", &keyRow) != 1) {
            Tcl_AppendResult(interp, "Invalid key row for undo: ", argv[3], (char *)NULL);
            return TCL_ERROR;
        }

	return (itemPtr->typePtr->subProc)(interp, itemPtr, argv[1], argv[2], keyRow);
    } else if (**argv == 's' && (strncmp(*argv, "solve", 2) == 0)) {
	if ((itemPtr->typePtr->solveProc)(interp, itemPtr, temp_str) != TCL_OK)
	    return TCL_ERROR;

	Tcl_SetResult(interp, temp_str, TCL_VOLATILE);

	return TCL_OK;
    } else if (**argv == 'u' && (strncmp(*argv, "undo", 1) == 0)) {
	const char *ct = NULL;
        int keyRow = 0;

	if (argc != 1 && argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " undo ?ct keyRow?",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	if (argc == 3) {
	    ct = argv[1];
            if (sscanf(argv[2], "%d", &keyRow) != 1) {
                Tcl_AppendResult(interp, "Invalid key row for undo: ", argv[2], (char *)NULL);
                return TCL_ERROR;
            }
        }
        return (itemPtr->typePtr->undoProc)(interp, itemPtr, ct, keyRow);
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
			" restore ct pt", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" substitute ct pt", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" undo ?ct?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" encode pt key", (char *)NULL);
	return TCL_ERROR;
    }
}

static int
SetQuagmire(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
{
    char	*c;
    int		valid = TCL_OK,
    		length=0;

    /*
     * First find out if every character is valid
     */

    length = CountValidChars(itemPtr, ctext);
    if (!length) {
	Tcl_SetResult(interp, "No valid characters found in ciphertext",
		TCL_STATIC);
	return TCL_ERROR;
    }
    c = ExtractValidChars(itemPtr, ctext);
    itemPtr->length = strlen(c);

    itemPtr->length = length;
    if (itemPtr->ciphertext) {
	ckfree(itemPtr->ciphertext);
    }
    itemPtr->ciphertext = c;

    return valid;
}

static int
QuagmireLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, const char *tip, const char *start)
{
    Tcl_AppendResult(interp,
	    "No locate tip function defined for ",
	    itemPtr->typePtr->type,
	    " ciphers",
	    (char *)NULL);
    return TCL_ERROR;
}

static int
QuagmireUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int keyRow)
{
    QuagmireItem *quagPtr = (QuagmireItem *)itemPtr;
    char	t;
    int		i, j;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp,
		"Can't do anything until the ciphertext has been set",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (itemPtr->period == 0) {
	Tcl_SetResult(interp,
		"Can't undo quagmire cipher until period has been set",
		TCL_STATIC);
	return TCL_ERROR;
    }

    /*
     * Convert the row value given by the user to an index into the key
     * arrays.
     */
    keyRow--;

    if (keyRow >= itemPtr->period) {
	Tcl_SetResult(interp,
		"key row for quagmire undo must be less than the cipher period",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (ct == NULL) {
	for (i=0; i < 26; i++) {
            for (j=0; j < itemPtr->period; j++) {
                quagPtr->ptkey[j][i] = '\0';
                quagPtr->ctkey[j][i] = '\0';
            }
        }
    } else {
	while (*ct) {
	    if (*ct >= 'a' && *ct <= 'z') {
                if (keyRow >= 0) {
                    t = quagPtr->ptkey[keyRow][*ct - 'a'];
                    quagPtr->ptkey[keyRow][*ct - 'a'] = '\0';
                    if (t) {
                        quagPtr->ctkey[keyRow][t - 'a'] = '\0';
                    }
                } else {
                    for (j=0; j < itemPtr->period; j++) {
                        t = quagPtr->ptkey[j][*ct - 'a'];
                        quagPtr->ptkey[j][*ct - 'a'] = '\0';
                        if (t) {
                            quagPtr->ctkey[j][t - 'a'] = '\0';
                        }
                    }
                }
            }
	    ct++;
	}
    }

    return TCL_OK;
}

static int
QuagmireSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, const char *pt, int keyRow)
{
    QuagmireItem *quagPtr = (QuagmireItem *)itemPtr;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp,
		"Can't do anything until the ciphertext has been set",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (itemPtr->period <= 0) {
        Tcl_SetResult(interp,
                "Period must be set before performing substitutions",
                TCL_STATIC);
        return TCL_ERROR;
    }

    /*
     * Convert the row value given by the user to an index into the key
     * arrays.
     */
    keyRow--;

    if (keyRow < 0 || keyRow >= itemPtr->period) {
	Tcl_SetResult(interp,
		"key row for quagmire substitute must be between 0 and the cipher period",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (strlen(ct) != strlen(pt)) {
        Tcl_SetResult(interp,
                "Length of ciphertext and plaintext for quagmire substitute must be equal",
                TCL_STATIC);
        return TCL_ERROR;
    }

    while (*ct && *pt) {
        if (*ct >= 'a' && *ct <= 'z' && *pt >= 'a' && *pt <= 'z') {
            quagPtr->ctkey[keyRow][*pt - 'a'] = *ct;
            quagPtr->ptkey[keyRow][*ct - 'a'] = *pt;
        }
        ct++, pt++;
    }

    Tcl_AppendElement(interp, ct);
    Tcl_AppendElement(interp, pt);

    return TCL_OK;
}

static char *
GetQuagmire(Tcl_Interp *interp, CipherItem *itemPtr)
{
    QuagmireItem *quagPtr = (QuagmireItem *)itemPtr;
    char	c;
    char	*pt=(char *)NULL;
    int		index=0;
    int         keyRow=0;

    if (itemPtr->period == 0) {
	Tcl_SetResult(interp,
		"Can't decode quagmire cipher until period has been set",
		TCL_STATIC);
	return (char *)NULL;
    }

    pt=(char *)ckalloc(sizeof(char)*(strlen(itemPtr->ciphertext)+1));

    for (index=0; index < itemPtr->length; index++) {
        keyRow = index%itemPtr->period;
        c = itemPtr->ciphertext[index];

        if (quagPtr->ptkey[keyRow][c - 'a']) {
            pt[index] = quagPtr->ptkey[keyRow][c - 'a'];
        } else {
            pt[index] = ' ';
        }
    }

    pt[index] = '\0';

    return pt;
}

static int
QuagmireApplyKeywords(Tcl_Interp *interp, CipherItem *itemPtr, char *vertical, char *k1, char *k2)
{
    QuagmireItem *quagPtr = (QuagmireItem *)itemPtr;
    char k1FullKey[27];
    char k2FullKey[27];
    int i;
    int keyRow;
    int ptIndex;
    int ctIndex;
    int vertKeyCol=0;
    int k1Length = 0;
    int k2Length = 0;

    if (strlen(vertical) != itemPtr->period) {
        Tcl_SetResult(interp,
                "Length of vertical key does not match cipher period.",
                TCL_STATIC);
        return TCL_ERROR;
    }

    if (k1) {
        k1Length = strlen(k1);
    }
    if (k2) {
        k2Length = strlen(k2);
    }

    for (i=0; i < itemPtr->period; i++) {
        if (! IsValidChar(itemPtr, vertical[i])) {
            Tcl_AppendResult(interp, "Invalid character found in vertical keyword: ", vertical, (char *)NULL);
            return TCL_ERROR;
        }
    }

    switch (itemPtr->typePtr->type[8]) {
        case '1':

            if (! k1) {
                Tcl_SetResult(interp,
                        "Missing k1 keyword for quagmire 1",
                        TCL_STATIC);
                return TCL_ERROR;
            }
            if (KeyGenerateK1(interp, k1, k1FullKey) != TCL_OK) {
                return TCL_ERROR;
            }
            /*
             * Find the index of the first key letter that is not part
             * of the keyword.  This is the plaintext letter under which
             * the vertical keyword will appear.
             */
            for (i = 0; i < 26; i++) {
                int j;
                for (j=0; j < k1Length && k1[j] != k1FullKey[i]; j++);
                if (j == k1Length) {
                    vertKeyCol = i;
                    break;
                }
            }

            for (keyRow=0; keyRow < itemPtr->period; keyRow++) {
                int ctKeyOffset = vertical[keyRow] - 'a';
                for (i=0; i < 26; i++) {
                    ptIndex = i;
                    ctIndex = k1FullKey[(vertKeyCol - ctKeyOffset + i + 26)%26] - 'a';
                    /*
                    fprintf(stderr, "ptkey[%d][%d] = %c; ctkey[%d][%d] = %c\n",
                            keyRow, ptIndex, ctIndex+'a',
                            keyRow, ctIndex, ptIndex+'a');
                    */
                    quagPtr->ptkey[keyRow][ptIndex] = ctIndex + 'a';
                    quagPtr->ctkey[keyRow][ctIndex] = ptIndex + 'a';
                }
            }
            break;
        case '2':
            if (! k1) {
                Tcl_SetResult(interp,
                        "Missing k2 keyword for quagmire 2",
                        TCL_STATIC);
                return TCL_ERROR;
            }
            if (KeyGenerateK1(interp, k1, k1FullKey) != TCL_OK) {
                return TCL_ERROR;
            }

            for (keyRow=0; keyRow < itemPtr->period; keyRow++) {
                for (i = 0; i < 26 && k1FullKey[i ] != vertical[keyRow]; i++);
                vertKeyCol = i;

                for (i=0; i < 26; i++) {
                    ptIndex = k1FullKey[(i + vertKeyCol)%26] - 'a';
                    ctIndex = i;

                    /*
                    fprintf(stderr, "ptkey[%d][%d] = %c; ctkey[%d][%d] = %c\n",
                            keyRow, ptIndex, ctIndex+'a',
                            keyRow, ctIndex, ptIndex+'a');
                    */

                    quagPtr->ptkey[keyRow][ptIndex] = ctIndex + 'a';
                    quagPtr->ctkey[keyRow][ctIndex] = ptIndex + 'a';
                }
            }

            break;
        case '3':
            if (! k1) {
                Tcl_SetResult(interp,
                        "Missing k1 keyword for quagmire 3",
                        TCL_STATIC);
                return TCL_ERROR;
            }
            if (KeyGenerateK1(interp, k1, k1FullKey) != TCL_OK) {
                return TCL_ERROR;
            }
            /*
             * Find the index of the first key letter that is not part
             * of the keyword.  This is the plaintext letter under which
             * the vertical keyword will appear.
             */
            for (i = 0; i < 26; i++) {
                int j;
                for (j=0; j < k1Length && k1[j] != k1FullKey[i]; j++);
                if (j == k1Length) {
                    vertKeyCol = i;
                    break;
                }
            }

            for (keyRow=0; keyRow < itemPtr->period; keyRow++) {
                for (i = 0; i < 26 && k1FullKey[i] != vertical[keyRow]; i++);
                vertKeyCol = i;

                for (i=0; i < 26; i++) {
                    ptIndex = k1FullKey[i] - 'a';
                    ctIndex = k1FullKey[(i - vertKeyCol + 26)%26] - 'a';
                    /*
                    fprintf(stderr, "ptkey[%d][%d] = %c; ctkey[%d][%d] = %c\n",
                            keyRow, ptIndex, ctIndex+'a',
                            keyRow, ctIndex, ptIndex+'a');
                    */
                    quagPtr->ptkey[keyRow][ptIndex] = ctIndex + 'a';
                    quagPtr->ctkey[keyRow][ctIndex] = ptIndex + 'a';
                }
            }
            break;
        case '4':
            if (! k1 || ! k2) {
                Tcl_SetResult(interp,
                        "Both k1 and k2 keywords must be given for quagmire 4",
                        TCL_STATIC);
                return TCL_ERROR;
            } else {
                Tcl_SetResult(interp, "k4 keywords not yet supported", TCL_STATIC);
                return TCL_ERROR;
            }
            if (KeyGenerateK1(interp, k1, k1FullKey) != TCL_OK) {
                return TCL_ERROR;
            }
            if (KeyGenerateK1(interp, k2, k2FullKey) != TCL_OK) {
                return TCL_ERROR;
            }
            break;
        default:
            Tcl_SetResult(interp, "Internal error:  QuagmireApplyKeywords run on a non-quagmire cipher.",
                    TCL_STATIC);
            return TCL_ERROR;
            break;
    }

    return TCL_OK;
}

static int
RestoreQuagmire(Tcl_Interp *interp, CipherItem *itemPtr, const char *part1, const char *part2)
{
    QuagmireItem *quagPtr = (QuagmireItem *)itemPtr;
    int count;
    char *vertical = part1;
    const char **argv;

    if (Tcl_SplitList(interp, part2, &count, &argv) != TCL_OK) {
        return TCL_ERROR;
    }

    if (count == 0) {
        Tcl_SetResult(interp, "Can't restore quagmire with an empty keyword.",
                TCL_STATIC);
        Tcl_Free((char *) argv);
        return TCL_ERROR;
    } else if (count == 1 && (itemPtr->typePtr->type[8] == '1' ||itemPtr->typePtr->type[8] == '2' || itemPtr->typePtr->type[8] == '3')) {
        int result = QuagmireApplyKeywords(interp, itemPtr, vertical, argv[0], (char *)NULL);
        Tcl_Free((char *) argv);
        return result;
    } else if (count == 2 && itemPtr->typePtr->type[8] == '4') {
        int result = QuagmireApplyKeywords(interp, itemPtr, vertical, argv[0], argv[1]);
        Tcl_Free((char *) argv);
        return result;
    } else if (count == itemPtr->period) {
        int keyRow;
        if (strlen(part1) != 26) {
            Tcl_AppendResult(interp,
                    "Length of each key element in full key restore must be 26: ",
                        part1,
                    (char *)NULL);
            Tcl_Free((char *) argv);
            return TCL_ERROR;
        }

        for (keyRow=0; keyRow < itemPtr->period; keyRow++) {
            if (strlen(argv[keyRow]) != 26) {
                Tcl_AppendResult(interp,
                        "Length of each key element in full key restore must be 26: ",
                        argv[keyRow],
                        (char *)NULL);
                Tcl_Free((char *) argv);
                return TCL_ERROR;
            }
        }

        for (keyRow=0; keyRow < itemPtr->period; keyRow++) {
            int i;
            int ptIndex;
            int ctIndex;

            for (i=0; i < 26; i++) {
                if (part1[i] < 'a' || part1[i] > 'z' || argv[keyRow][i] < 'a' || argv[keyRow][i] > 'z') {
                    Tcl_AppendResult(interp, "Invalid character found in restoration key: ",
                            argv[keyRow],
                            (char *)NULL);
                    Tcl_Free((char *) argv);
                    return TCL_ERROR;
                }
                ctIndex = argv[keyRow][i] - 'a';
                ptIndex = part1[i] - 'a';

                quagPtr->ptkey[keyRow][ctIndex] = part1[i];
                quagPtr->ctkey[keyRow][ptIndex] = argv[keyRow][i];
            }
        }
        Tcl_Free((char *) argv);
        return TCL_OK;
    }

    Tcl_SetResult(interp,
            "Number of key blocks does not match the cipher period.",
            TCL_STATIC);
    Tcl_Free((char *) argv);
    return TCL_ERROR;
}

static int
EncodeQuagmire(Tcl_Interp *interp, CipherItem *itemPtr, const char *pt, const char *key) {
    char *ct = (char *)NULL;
    int count;
    const char **argv;

    /*
     * TODO:  Implement this for quag ciphers
     */
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

static int
SolveQuagmire(Tcl_Interp *interp, CipherItem *itemPtr, char *result)
{
    Tcl_SetResult(interp, "You cheat!", TCL_STATIC);
    return TCL_ERROR;
}
