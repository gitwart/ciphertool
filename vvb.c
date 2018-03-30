/*
 * vvb.c --
 *
 *	This file implements the vigenere, variant, beaufort, gronsfeld,
 *	and porta cipher types.
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
#include <digram.h>
#include <vigTypes.h>

#include <cipherDebug.h>

#define VIG_TYPE 0
#define VAR_TYPE 1
#define BEA_TYPE 2
#define GRN_TYPE 3
#define PRT_TYPE 4

#define SOLVE_FAST	0
#define SOLVE_THOROUGH	1

static int  CreateVigenere	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
void DeleteVigenere		_ANSI_ARGS_((ClientData));
static char *GetVigenere	_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetVigenere		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestoreVigenere	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolveVigenere	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
static int  QuickSolveVigenere	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
int VigenereCmd			_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));
static int VigenereUndo		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int VigenereSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int VigenereLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int VigenereSetPeriod	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				int));
static void VigenereInitKey	_ANSI_ARGS_((CipherItem *, int));
static int RecSolveVigenere	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				int, char *));
static int RecQuickSolveVigenere _ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				int, char *));
static int FindBestTipLocation	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
	    			const char *));
static char PortaCtPtToKey	_ANSI_ARGS_((char, char));
static char PortaCtKeyToPt	_ANSI_ARGS_((char, char));
static char *GetKeyedVigenere	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int VigenereFitColumn	_ANSI_ARGS_((Tcl_Interp *, CipherItem *, int));
static int EncodeVigenere	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));

static char _portaCtPt[26][26] = {
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000acegikmoqsuwy" },
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000yacegikmoqsuw" },
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000wyacegikmoqsu" },
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000uwyacegikmoqs" },
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000suwyacegikmoq" },
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000qsuwyacegikmo" },
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000oqsuwyacegikm" },
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000moqsuwyacegik" },
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000kmoqsuwyacegi" },
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000ikmoqsuwyaceg" },
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000gikmoqsuwyace" },
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000egikmoqsuwyac" },
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000cegikmoqsuwya" },
    { "aywusqomkigec\000\000\000\000\000\000\000\000\000\000\000\000\000" },
    { "caywusqomkige\000\000\000\000\000\000\000\000\000\000\000\000\000" },
    { "ecaywusqomkig\000\000\000\000\000\000\000\000\000\000\000\000\000" },
    { "gecaywusqomki\000\000\000\000\000\000\000\000\000\000\000\000\000" },
    { "igecaywusqomk\000\000\000\000\000\000\000\000\000\000\000\000\000" },
    { "kigecaywusqom\000\000\000\000\000\000\000\000\000\000\000\000\000" },
    { "mkigecaywusqo\000\000\000\000\000\000\000\000\000\000\000\000\000" },
    { "omkigecaywusq\000\000\000\000\000\000\000\000\000\000\000\000\000" },
    { "qomkigecaywus\000\000\000\000\000\000\000\000\000\000\000\000\000" },
    { "sqomkigecaywu\000\000\000\000\000\000\000\000\000\000\000\000\000" },
    { "usqomkigecayw\000\000\000\000\000\000\000\000\000\000\000\000\000" },
    { "wusqomkigecay\000\000\000\000\000\000\000\000\000\000\000\000\000" },
    { "ywusqomkigeca\000\000\000\000\000\000\000\000\000\000\000\000\000" }};

static char _portaCtKey[26][26] = {
    { "nnooppqqrrssttuuvvwwxxyyzz" },
    { "ooppqqrrssttuuvvwwxxyyzznn" },
    { "ppqqrrssttuuvvwwxxyyzznnoo" },
    { "qqrrssttuuvvwwxxyyzznnoopp" },
    { "rrssttuuvvwwxxyyzznnooppqq" },
    { "ssttuuvvwwxxyyzznnooppqqrr" },
    { "ttuuvvwwxxyyzznnooppqqrrss" },
    { "uuvvwwxxyyzznnooppqqrrsstt" },
    { "vvwwxxyyzznnooppqqrrssttuu" },
    { "wwxxyyzznnooppqqrrssttuuvv" },
    { "xxyyzznnooppqqrrssttuuvvww" },
    { "yyzznnooppqqrrssttuuvvwwxx" },
    { "zznnooppqqrrssttuuvvwwxxyy" },
    { "aammllkkjjiihhggffeeddccbb" },
    { "bbaammllkkjjiihhggffeeddcc" },
    { "ccbbaammllkkjjiihhggffeedd" },
    { "ddccbbaammllkkjjiihhggffee" },
    { "eeddccbbaammllkkjjiihhggff" },
    { "ffeeddccbbaammllkkjjiihhgg" },
    { "ggffeeddccbbaammllkkjjiihh" },
    { "hhggffeeddccbbaammllkkjjii" },
    { "iihhggffeeddccbbaammllkkjj" },
    { "jjiihhggffeeddccbbaammllkk" },
    { "kkjjiihhggffeeddccbbaammll" },
    { "llkkjjiihhggffeeddccbbaamm" },
    { "mmllkkjjiihhggffeeddccbbaa" }};

typedef struct VigenereItem {
    CipherItem header;

    int type;		/* one of:  VIG_TYPE, VAR_TYPE, BEA_TYPE, GRN_TYPE,
			 * PRT_TYPE
			 */
    char *vigkey;	/* index by period.  key value is the pt equivalent
			 * of ciphertext 'a'
			 * This also doubles as the gronsfeld key */
    char *beakey;	/* index by period.  key value is the pt equivalent
			 * of ciphertext 'a' */
    char *varkey;	/* index by period.  key value is the pt equivalent
			 * of ciphertext 'a' */
    char *prtkey;	/* index by period.  key value is the pt equivalent
			 * of ciphertext 'a' */
    double maxSolVal;	/* Best solution value */
    char *maxkey;	/* Best solution key */

    int solveMethod;	/* Algorithm to use while solving
			 * SOLVE_FAST or SOLVE_THOROUGH */
} VigenereItem;

CipherType VigenereType = { "vigenere",
    ATOZ,
    sizeof(VigenereItem),
    CreateVigenere,	/* create proc */
    DeleteVigenere,	/* delete proc */
    VigenereCmd,	/* cipher command proc */
    GetVigenere,	/* get plaintext proc */
    SetVigenere,	/* show ciphertext proc */
    SolveVigenere,	/* solve cipher proc */
    RestoreVigenere,	/* restore proc */
    VigenereLocateTip,	/* locate proc */
    VigenereSubstitute,	/* sub proc */
    VigenereUndo,	/* undo proc */
    EncodeVigenere,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

CipherType GronsfeldType = {
    "gronsfeld",
    ATOZ,
    sizeof(VigenereItem),
    CreateVigenere,	/* create proc */
    DeleteVigenere,	/* delete proc */
    VigenereCmd,	/* cipher command proc */
    GetVigenere,	/* get plaintext proc */
    SetVigenere,	/* show ciphertext proc */
    SolveVigenere,	/* solve cipher proc */
    RestoreVigenere,	/* restore proc */
    VigenereLocateTip,	/* locate proc */
    VigenereSubstitute,	/* sub proc */
    VigenereUndo,	/* undo proc */
    EncodeVigenere,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

CipherType VariantType = {
    "variant",
    ATOZ,
    sizeof(VigenereItem),
    CreateVigenere,	/* create proc */
    DeleteVigenere,	/* delete proc */
    VigenereCmd,	/* cipher command proc */
    GetVigenere,	/* get plaintext proc */
    SetVigenere,	/* show ciphertext proc */
    SolveVigenere,	/* solve cipher proc */
    RestoreVigenere,	/* restore proc */
    VigenereLocateTip,	/* locate proc */
    VigenereSubstitute,	/* sub proc */
    VigenereUndo,	/* undo proc */
    EncodeVigenere,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

CipherType BeaufortType = {
    "beaufort",
    ATOZ,
    sizeof(VigenereItem),
    CreateVigenere,	/* create proc */
    DeleteVigenere,	/* delete proc */
    VigenereCmd,	/* cipher command proc */
    GetVigenere,	/* get plaintext proc */
    SetVigenere,	/* show ciphertext proc */
    SolveVigenere,	/* solve cipher proc */
    RestoreVigenere,	/* restore proc */
    VigenereLocateTip,	/* locate proc */
    VigenereSubstitute,	/* sub proc */
    VigenereUndo,	/* undo proc */
    EncodeVigenere,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

CipherType PortaType = {
    "porta",
    ATOZ,
    sizeof(VigenereItem),
    CreateVigenere,	/* create proc */
    DeleteVigenere,	/* delete proc */
    VigenereCmd,	/* cipher command proc */
    GetVigenere,	/* get plaintext proc */
    SetVigenere,	/* show ciphertext proc */
    SolveVigenere,	/* solve cipher proc */
    RestoreVigenere,	/* restore proc */
    VigenereLocateTip,	/* locate proc */
    VigenereSubstitute,	/* sub proc */
    VigenereUndo,	/* undo proc */
    EncodeVigenere,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

static int
CreateVigenere(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    VigenereItem *vigPtr = (VigenereItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    vigPtr->header.period = 0;
    vigPtr->vigkey = (char *)NULL;
    vigPtr->varkey = (char *)NULL;
    vigPtr->beakey = (char *)NULL;
    vigPtr->prtkey = (char *)NULL;
    vigPtr->maxkey = (char *)NULL;
    vigPtr->solveMethod = SOLVE_FAST;

    if (strcmp(itemPtr->typePtr->type, "vigenere") == 0) {
	vigPtr->type = VIG_TYPE;
    }
    else if (strcmp(itemPtr->typePtr->type, "variant") == 0) {
	vigPtr->type = VAR_TYPE;
    }
    else if (strcmp(itemPtr->typePtr->type, "beaufort") == 0) {
	vigPtr->type = BEA_TYPE;
    }
    else if (strcmp(itemPtr->typePtr->type, "gronsfeld") == 0) {
	vigPtr->type = GRN_TYPE;
    }
    else if (strcmp(itemPtr->typePtr->type, "porta") == 0) {
	vigPtr->type = PRT_TYPE;
    }

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, VigenereCmd, itemPtr,
	    itemPtr->typePtr->deleteProc);
    if (argc) {
	if (Tcl_Eval(interp, Tcl_DStringValue(&dsPtr)) != TCL_OK) {
	    Tcl_DeleteCommand(interp, temp_ptr);
	    Tcl_DStringFree(&dsPtr);
	    return TCL_ERROR;
	}
    }
    VigenereInitKey(itemPtr, 0);
    Tcl_SetResult(interp, temp_ptr, TCL_VOLATILE);
    Tcl_DStringFree(&dsPtr);
    return TCL_OK;
}

void
DeleteVigenere(ClientData clientData)
{
    VigenereItem *vigPtr = (VigenereItem *)clientData;

    if (vigPtr->vigkey) {
	ckfree(vigPtr->vigkey);
    }
    if (vigPtr->varkey) {
	ckfree(vigPtr->varkey);
    }
    if (vigPtr->beakey) {
	ckfree(vigPtr->beakey);
    }
    if (vigPtr->prtkey) {
	ckfree(vigPtr->prtkey);
    }
    if (vigPtr->maxkey) {
	ckfree(vigPtr->maxkey);
    }

    DeleteCipher(clientData);
}

int
VigenereCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    VigenereItem *vigPtr = (VigenereItem *)clientData;
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
	    sprintf(temp_str, "%d", vigPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", vigPtr->header.period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!vigPtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_STATIC);
	    } else {
		Tcl_SetResult(interp, vigPtr->header.ciphertext, TCL_VOLATILE);
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-solvemethod", 10) == 0) {
	    switch (vigPtr->solveMethod) {
		case SOLVE_FAST:
		    Tcl_SetResult(interp, "fast", TCL_STATIC);
		    break;
		case SOLVE_THOROUGH:
		    Tcl_SetResult(interp, "thorough", TCL_STATIC);
		    break;
		default:
		    fprintf(stderr, "Unknown solve method (%d) encountered.  %s line %d\n",
			    vigPtr->solveMethod,
			    __FILE__, __LINE__);
		    abort();
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-plaintext", 9) == 0 ||
		   strncmp(argv[1], "-ptext", 3) == 0) {
	    tPtr = (itemPtr->typePtr->decipherProc)(interp, itemPtr);

	    /*
	     * The only way that tPtr will be non-null is if the allocation
	     * of memory to store the result failed or a period is not set.
	     */

	    if (!tPtr) {
		return TCL_ERROR;
	    }

	    Tcl_SetResult(interp, tPtr, TCL_DYNAMIC);

	    return TCL_OK;
	} else if (strncmp(argv[1], "-keyword", 8) == 0) {
	    switch(vigPtr->type) {
		case VIG_TYPE:
		    for(i=0; i < itemPtr->period; i++) {
			if (vigPtr->vigkey[i]) {
			    temp_str[i] = vigPtr->vigkey[i];
			} else {
			    temp_str[i] = ' ';
			}
		    }
		    temp_str[itemPtr->period] = '\0';
		    break;
		case GRN_TYPE:
		    for(i=0; i < itemPtr->period; i++) {
			if (vigPtr->vigkey[i]) {
			    temp_str[i] = vigPtr->vigkey[i] - 'a' + '0';
			} else {
			    temp_str[i] = ' ';
			}
		    }
		    temp_str[itemPtr->period] = '\0';
		    break;
		case VAR_TYPE:
		    for(i=0; i < itemPtr->period; i++) {
			if (vigPtr->varkey[i]) {
			    temp_str[i] = vigPtr->varkey[i];
			} else {
			    temp_str[i] = ' ';
			}
		    }
		    temp_str[itemPtr->period] = '\0';
		    break;
		case BEA_TYPE:
		    for(i=0; i < itemPtr->period; i++) {
			if (vigPtr->beakey[i]) {
			    temp_str[i] = vigPtr->beakey[i];
			} else {
			    temp_str[i] = ' ';
			}
		    }
		    temp_str[itemPtr->period] = '\0';
		    break;
		case PRT_TYPE:
		    for(i=0; i < itemPtr->period; i++) {
			if (vigPtr->prtkey[i]) {
			    temp_str[i] = vigPtr->prtkey[i];
			} else {
			    temp_str[i] = ' ';
			}
		    }
		    temp_str[itemPtr->period] = '\0';
		    Tcl_AppendElement(interp, temp_str);

		    for(i=0; i < itemPtr->period; i++) {
			if (vigPtr->prtkey[i]) {
			    temp_str[i] = vigPtr->prtkey[i]+1;
			} else {
			    temp_str[i] = ' ';
			}
		    }
		    temp_str[itemPtr->period] = '\0';
		    break;
	    }

	    Tcl_AppendElement(interp, temp_str);

	    return TCL_OK;
	} else if (strncmp(argv[1], "-key", 4) == 0) {
	    char temp_ct[256];
	    /*
	    * Definition of vigenere:  k = ct - pt
	    * Definition of variant:   k = pt - ct
	    * Definition of beaufort:  k = ct + pt
	    */

	    switch(vigPtr->type) {
		case GRN_TYPE:
		case VIG_TYPE:
		    for(i=0; i < itemPtr->period; i++) {
			if (vigPtr->vigkey[i]) {
			    temp_str[i] = 'a';
			    temp_ct[i] = vigPtr->vigkey[i];
			} else {
			    temp_ct[i] = ' ';
			    temp_str[i] = 'a';
			}
		    }
		    break;
		case VAR_TYPE:
		    for(i=0; i < itemPtr->period; i++) {
			if (vigPtr->varkey[i]) {
			    temp_ct[i] = 'a';
			    temp_str[i] = vigPtr->varkey[i];
			} else {
			    temp_ct[i] = 'a';
			    temp_str[i] = ' ';
			}
		    }
		    break;
		case BEA_TYPE:
		    for(i=0; i < itemPtr->period; i++) {
			if (vigPtr->beakey[i]) {
			    temp_ct[i] = 'a';
			    temp_str[i] = vigPtr->beakey[i];
			} else {
			    temp_ct[i] = 'a';
			    temp_str[i] = ' ';
			}
		    }
		    break;
		case PRT_TYPE:
		    for(i=0; i < itemPtr->period; i++) {
			if (vigPtr->prtkey[i]) {
			    temp_ct[i] = vigPtr->prtkey[i];
			    temp_str[i] = PortaCtKeyToPt(temp_ct[i], temp_ct[i]);
			} else {
			    temp_ct[i] = ' ';
			    temp_str[i] = 'a';
			}
		    }
		    break;
	    }
	    temp_str[itemPtr->period] = '\0';
	    temp_ct[itemPtr->period] = '\0';

	    Tcl_AppendElement(interp, temp_ct);
	    Tcl_AppendElement(interp, temp_str);

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
	    } else if (strncmp(*argv, "-solvemethod", 7) == 0) {
		if (strcmp(argv[1], "fast") == 0) {
		    vigPtr->solveMethod = SOLVE_FAST;
		} else if (strcmp(argv[1], "thorough") == 0) {
		    vigPtr->solveMethod = SOLVE_THOROUGH;
		} else {
		    Tcl_SetResult(interp,
			    "Invalid solve algorithm.  Must be one of 'fast' or 'thorough'",
			    TCL_STATIC);
		    return TCL_ERROR;
		}
		return TCL_OK;
	    } else if (strncmp(*argv, "-period", 7) == 0) {

		if (sscanf(argv[1], "%d", &i) != 1) {
		    Tcl_AppendResult(interp, "Bad period.  Integer expected:  ",
			    argv[1], (char *)NULL);
		    return TCL_ERROR;
		}
		if (VigenereSetPeriod(interp, itemPtr, i) != TCL_OK) {
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
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " restore ct pt", (char *)NULL);
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
	int valid;
	if (argc != 4) {
	    Tcl_AppendResult(interp,
		    "Usage:  ", cmd,
		    " substitute ct pt offset",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	if (strlen(argv[1]) != strlen(argv[2])) {
	    Tcl_SetResult(interp,
		    "ciphertext and plaintext must be the same length",
		    TCL_STATIC);
	    return TCL_ERROR;
	}
	if (sscanf(argv[3], "%d", &i) != 1) {
	    Tcl_AppendResult(interp, "Bad column number:  ", 
		    argv[3], (char *)NULL);
	    return TCL_ERROR;
	}
	
	/*
	 * Users start with column 1, C starts with column 0
	 */

	i = i - 1;

	valid = (itemPtr->typePtr->subProc)(interp, itemPtr, argv[1], argv[2],
		i);
	if (valid == BAD_SUB) {
	    return TCL_ERROR;
	} else {
	    return TCL_OK;
	}
    } else if (**argv == 'f' && (strncmp(*argv, "fit", 2) == 0)) {
	if (argc != 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " fit col", (char *)NULL);
	    return TCL_ERROR;
	}
	if (sscanf(argv[1], "%d", &i) != 1) {
	    Tcl_AppendResult(interp, "Bad column value:  ", 
		    argv[1], (char *)NULL);
	    return TCL_ERROR;
	}
	return VigenereFitColumn(interp, itemPtr, i);
    } else if (**argv == 's' && (strncmp(*argv, "solve", 2) == 0)) {
	int result;

	switch (vigPtr->solveMethod) {
	    case SOLVE_FAST:
		result = QuickSolveVigenere(interp, itemPtr, temp_str);
		break;
	    case SOLVE_THOROUGH:
		result = SolveVigenere(interp, itemPtr, temp_str);
		break;
	    default:
		fprintf(stderr, "Unknown solve method (%d) encountered.  %s line %d\n",
			vigPtr->solveMethod,
			__FILE__, __LINE__);
		abort();
	}
	if (result != TCL_OK) {
	    return TCL_ERROR;
	} else {
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	}
    } else if (**argv == 'u' && (strncmp(*argv, "undo", 1) == 0)) {
	if (argc != 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " undo col", (char *)NULL);
	    return TCL_ERROR;
	}
	if (sscanf(argv[1], "%d", &i) != 1) {
	    Tcl_AppendResult(interp, "Bad column number:  ", 
		    argv[1], (char *)NULL);
	    return TCL_ERROR;
	}
	(itemPtr->typePtr->undoProc)(interp, itemPtr, argv[1], i);
	Tcl_SetResult(interp, "", TCL_STATIC);
	return TCL_OK;
    } else if (**argv == 'l' && (strncmp(*argv, "locatebest", 9) == 0)) {
	if (argc != 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " locatebest tip", (char *)NULL);
	    return TCL_ERROR;
	}
	return FindBestTipLocation(interp, itemPtr, argv[1]);
    } else if (**argv == 'l' && (strncmp(*argv, "locate", 1) == 0)) {
	if (argc < 2 || argc > 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " locate pt ct", (char *)NULL);
	    return TCL_ERROR;
	}
	if (argc == 2) {
	    return (itemPtr->typePtr->locateProc)(interp, itemPtr, argv[1], (char *)NULL);
	} else { 
	    return (itemPtr->typePtr->locateProc)(interp, itemPtr, argv[1], argv[2]);
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
			" substitute ct pt col", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" locate ct pt", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" locatebest tip", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" undo ct", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" encode pt key", (char *)NULL);
	return TCL_ERROR;
    }
}

static int
SetVigenere(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
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

static char
PortaCtPtToKey(char ct, char pt)
{
    /*
     * A little extra care must be taken for the porta cipher
     */

    if (ct < 'a' || ct > 'z' || pt < 'a' || pt > 'z')
	return '\0';

    return _portaCtPt[ct-'a'][pt-'a'];
}

static char
PortaCtKeyToPt(char ct, char key)
{
    if (!key)
	return '\0';

    if (ct < 'a' || ct > 'z' || key < 'a' || key > 'z')
	return '\0';

    return _portaCtKey[ct-'a'][key-'a'];
}

static int
VigenereLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, const char *tip, const char *start)
{
    int		i;
    char	*s,
    		*c,
		*ct;
    char	*vigkey;
    char	*varkey;
    char	*beakey;
    char	*prtkey;
    int		valid_sub=NEW_SUB;
    int		tipLen = strlen(tip);

    vigkey = (char *)ckalloc(sizeof(char) * itemPtr->period);
    varkey = (char *)ckalloc(sizeof(char) * itemPtr->period);
    beakey = (char *)ckalloc(sizeof(char) * itemPtr->period);
    prtkey = (char *)ckalloc(sizeof(char) * itemPtr->period);
    for(i=0; i < itemPtr->period; i++) {
	vigkey[i] = varkey[i] = beakey[i] = prtkey[i] = '\0';
    }

    ct = itemPtr->ciphertext;

    /*
     * Locate the starting point
     */

    if (start) {
	s = strstr((const char *)ct, (const char *)start);
    } else {
	s = ct;
    }

    if (!s) {
	Tcl_SetResult(interp, "Starting location not found.", TCL_STATIC);
	return BAD_SUB;
    }

    /*
     * Loop through every possible starting point.
     */
    valid_sub = BAD_SUB;
    for(c=s; c < (ct + itemPtr->length - tipLen) && valid_sub!=NEW_SUB; c++) {
	/*
	 * Loop through every letter of the tip
	 */
	if ((itemPtr->typePtr->subProc)(interp, itemPtr, c, tip, (c - itemPtr->ciphertext)%itemPtr->period) != NEW_SUB) {
	    valid_sub = BAD_SUB;
	} else {
	    valid_sub = NEW_SUB;
	}
    }

    ckfree(vigkey);
    ckfree(varkey);
    ckfree(beakey);
    ckfree(prtkey);

    Tcl_SetObjResult(interp, Tcl_NewStringObj(tip, -1));
    return TCL_OK;
}

static int
FindBestTipLocation(Tcl_Interp *interp, CipherItem *itemPtr, const char *tip)
{
    VigenereItem *vigPtr = (VigenereItem *)itemPtr;
    int		i;
    char	*s,
    		*c,
		*ct;
    char	*vigkey;
    char	*varkey;
    char	*beakey;
    char	*prtkey;
    double	curkey, maxkey = 0.0;
    int		tipLen = strlen(tip);

    vigkey = (char *)ckalloc(sizeof(char) * itemPtr->period);
    varkey = (char *)ckalloc(sizeof(char) * itemPtr->period);
    beakey = (char *)ckalloc(sizeof(char) * itemPtr->period);
    prtkey = (char *)ckalloc(sizeof(char) * itemPtr->period);
    for(i=0; i < itemPtr->period; i++) {
	vigkey[i] = '\0';
	varkey[i] = '\0';
	beakey[i] = '\0';
	prtkey[i] = '\0';
    }

    ct = itemPtr->ciphertext;
    s = ct;

    /*
     * Loop through every possible starting point.
     */
    for(c=s; c < (ct + itemPtr->length - tipLen); c++) {
	/*
	 * Erase the current key for the next attempt
	 */

	for(i=0; i < itemPtr->period; i++) {
	    vigPtr->vigkey[i] = '\0';
	    vigPtr->varkey[i] = '\0';
	    vigPtr->beakey[i] = '\0';
	    vigPtr->prtkey[i] = '\0';
	}

	/*
	 * Only pay attention to valid tips.
	 */
	if ((itemPtr->typePtr->subProc)(interp, itemPtr, c, tip, (c - itemPtr->ciphertext)) == NEW_SUB) {
	    char *curPt=(char *)NULL;

	    /*
	     * Store the key if it's the best one.
	     */

	    curPt = GetVigenere(interp, itemPtr);

	    if (curPt) {
		if (DefaultScoreValue(interp, curPt, &curkey) != TCL_OK) {
		    return TCL_ERROR;
		}
		if (curkey > maxkey) {
		    maxkey = curkey;
		    for(i=0; i < itemPtr->period; i++) {
			vigkey[i] = vigPtr->vigkey[i];
			varkey[i] = vigPtr->varkey[i];
			beakey[i] = vigPtr->beakey[i];
			prtkey[i] = vigPtr->prtkey[i];
		    }
		}
		ckfree(curPt);
	    }
	}
    }

    for(i=0; i < itemPtr->period; i++) {
	vigPtr->vigkey[i] = vigkey[i];
	vigPtr->varkey[i] = varkey[i];
	vigPtr->beakey[i] = beakey[i];
	vigPtr->prtkey[i] = prtkey[i];
    }

    ckfree(vigkey);
    ckfree(varkey);
    ckfree(beakey);
    ckfree(prtkey);

    return TCL_OK;
}

static int
VigenereUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int offset)
{
    VigenereItem *vigPtr = (VigenereItem *)itemPtr;
    int		i;

    if (sscanf(ct, "%d", &i) != 1) {
	Tcl_AppendResult(interp, "Bad column number:  ", ct, (char *)NULL);
	return TCL_ERROR;
    }

    if (i < 1 || i > itemPtr->period) {
	Tcl_SetResult(interp, "Bad column index", TCL_STATIC);
	return TCL_ERROR;
    }

    i--;

    vigPtr->vigkey[i] = '\0';
    vigPtr->varkey[i] = '\0';
    vigPtr->beakey[i] = '\0';
    vigPtr->prtkey[i] = '\0';

    return TCL_OK;
}

static int
VigenereSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, const char *pt, int offset)
{
    VigenereItem *vigPtr = (VigenereItem *)itemPtr;
    const char	*c,
		*p;
    char	*vigkey;
    char	*varkey;
    char	*beakey;
    char	*prtkey;
    char	*q;
    char	vigk;
    char	vark;
    char	beak;
    char	prtk;
    int		i;
    int		index;
    int		valid_sub = NEW_SUB;


    if (itemPtr->period == 0) {
	Tcl_SetResult(interp, "Period must be set before performing substitutions", TCL_STATIC);
	return BAD_SUB;
    }

    if (offset < 0 || offset >= itemPtr->period) {
	Tcl_SetResult(interp, "Invalid offset.  Must be from 1 to period",
		TCL_STATIC);
	return BAD_SUB;
    }

    offset %= itemPtr->period;

    /*
     * Determine the 3 keys based on the ciphertext and plaintext.
     */

    vigkey = (char *)ckalloc(sizeof(char) * itemPtr->period);
    varkey = (char *)ckalloc(sizeof(char) * itemPtr->period);
    beakey = (char *)ckalloc(sizeof(char) * itemPtr->period);
    prtkey = (char *)ckalloc(sizeof(char) * itemPtr->period);
    q = (char *)ckalloc(sizeof(char) * strlen(ct) +1);
    for(i=0; i < itemPtr->period; i++) {
	vigkey[i] = varkey[i] = beakey[i] = prtkey[i] = '\0';
    }

    c = ct;
    p = pt;
    index = 0;
    while(*c && *p && valid_sub != BAD_SUB) {

	i = (c - ct + offset)%itemPtr->period;
	/*
	* Definition of vigenere:  k = ct - pt
	* Definition of variant:   k = pt - ct
	* Definition of beaufort:  k = ct + pt
	*/

	vigk = VigenereGetKey(*c, *p);
	vark = VariantGetKey(*c, *p);
	beak = BeaufortGetKey(*c, *p);
	
	/*
	 * A little extra care must be taken for the porta cipher
	 */
	prtk = PortaCtPtToKey(*c, *p);
	if (vigPtr->type == PRT_TYPE && prtk == '\0') {
	    valid_sub = BAD_SUB;
	}

	/*
	 * Return an error if we have an invalid key for
	 * a gronsfeld cipher
	 */

	if (vigPtr->type == GRN_TYPE && (vigk > 'j' && vigk <= 'z')) {
	    valid_sub = BAD_SUB;
	}

	if (vigPtr->vigkey[i] && vigk != vigPtr->vigkey[i]) {
	    valid_sub = ALT_SUB;
	}
	if (vigPtr->varkey[i] && vark != vigPtr->varkey[i]) {
	    valid_sub = ALT_SUB;
	}
	if (vigPtr->beakey[i] && beak != vigPtr->beakey[i]) {
	    valid_sub = ALT_SUB;
	}
	if (vigPtr->prtkey[i] && prtk != vigPtr->prtkey[i]) {
	    valid_sub = ALT_SUB;
	}

	if (vigkey[i] && vigkey[i] != vigk) {
	    valid_sub = BAD_SUB;
	}
	if (varkey[i] && varkey[i] != vark) {
	    valid_sub = BAD_SUB;
	}
	if (beakey[i] && beakey[i] != beak) {
	    valid_sub = BAD_SUB;
	}
	if (prtkey[i] && prtkey[i] != prtk) {
	    valid_sub = BAD_SUB;
	}

	if (valid_sub == ALT_SUB) {
	    q[index++] = *c;
	}

	vigkey[i] = vigk;
	varkey[i] = vark;
	beakey[i] = beak;
	prtkey[i] = prtk;

	c++, p++;
    }
    q[index] = '\0';

    if (valid_sub == BAD_SUB) {
	Tcl_SetResult(interp, "Bad substitution", TCL_STATIC);
	ckfree(vigkey);
	ckfree(varkey);
	ckfree(beakey);
	ckfree(prtkey);
	ckfree(q);
	return BAD_SUB;
    } else {
	for(i=0; i < itemPtr->period; i++) {
	    if (vigkey[i]) {
		vigPtr->vigkey[i] = vigkey[i];
	    }
	    if (varkey[i]) {
		vigPtr->varkey[i] = varkey[i];
	    }
	    if (beakey[i]) {
		vigPtr->beakey[i] = beakey[i];
	    }
	    if (prtkey[i]) {
		vigPtr->prtkey[i] = prtkey[i];
	    }
	}
    }

    Tcl_AppendElement(interp, ct);
    Tcl_AppendElement(interp, pt);
    if (valid_sub == ALT_SUB) {
	Tcl_AppendElement(interp, q);
	valid_sub = ALT_SUB;
    }

    ckfree(vigkey);
    ckfree(varkey);
    ckfree(beakey);
    ckfree(prtkey);
    ckfree(q);

    return valid_sub;
}

static char *
GetVigenere(Tcl_Interp *interp, CipherItem *itemPtr)
{
    VigenereItem *vigPtr = (VigenereItem *)itemPtr;

    switch (vigPtr->type) {
	case GRN_TYPE:
	case VIG_TYPE:  return GetKeyedVigenere(interp, itemPtr,
				vigPtr->vigkey);
			break;
	case VAR_TYPE:  return GetKeyedVigenere(interp, itemPtr,
				vigPtr->varkey);
			break;
	case BEA_TYPE:  return GetKeyedVigenere(interp, itemPtr,
				vigPtr->beakey);
			break;
	case PRT_TYPE:  return GetKeyedVigenere(interp, itemPtr,
				vigPtr->prtkey);
			break;
    }

    return (char *)NULL;
}

static char *
GetKeyedVigenere(Tcl_Interp *interp, CipherItem *itemPtr, const char *key)
{
    VigenereItem *vigPtr = (VigenereItem *)itemPtr;
    char	*c;
    int		i;
    int		index;
    char	*result=(char *)ckalloc(sizeof(char) * strlen(itemPtr->ciphertext) + 1);

    c = itemPtr->ciphertext;

    if (itemPtr->period <= 0) {
	ckfree(result);
	Tcl_SetResult(interp, "Can't produce plaintext without a period",
		TCL_STATIC);
	return (char *)NULL;
    }

    for(i=0; c[i]; i++) {
	/*
	* Definition of vigenere:  k = ct - pt
	* Definition of variant:   k = pt - ct
	* Definition of beaufort:  k = ct + pt
	*/

	index = i % itemPtr->period;
	switch (vigPtr->type) {
	    case GRN_TYPE:
	    case VIG_TYPE:  if (key[index]) {
				result[i] = VigenereGetPt(key[index], c[i]);
			    } else {
				result[i] = ' ';
			    }
			    break;
	    case VAR_TYPE:  if (key[index]) {
				result[i] = VariantGetPt(key[index], c[i]);
			    } else {
				result[i] = ' ';
			    }
			    break;
	    case BEA_TYPE:  if (key[index]) {
				result[i] = BeaufortGetPt(key[index], c[i]);
			    } else {
				result[i] = ' ';
			    }
			    break;
	    case PRT_TYPE:  if (key[index]) {
				result[i] = PortaCtKeyToPt(c[i], key[index]);
			    } else {
				result[i] = ' ';
			    }
			    break;
	}
    }

    result[i] = '\0';

    return result;
}

static int
RestoreVigenere(Tcl_Interp *interp, CipherItem *itemPtr, const char *part1, const char *part2)
{
    if ((itemPtr->typePtr->subProc)(interp, itemPtr, part1, part2, 0) == BAD_SUB) {
	return TCL_ERROR;
    } else {
	return TCL_OK;
    }
}

static int
SolveVigenere(Tcl_Interp *interp, CipherItem *itemPtr, char *maxkey)
{
    VigenereItem *vigPtr = (VigenereItem *)itemPtr;
    char	*key=(char *)NULL;
    char	c,
    		p;
    int		tally=0;
    int		i;

    if (itemPtr->period < 1) {
	Tcl_SetResult(interp, "Can't solve this cipher until a period has been set", TCL_STATIC);
	return TCL_ERROR;
    }

    key = (char *)ckalloc(sizeof(char) * itemPtr->period);
    vigPtr->maxkey = (char *)ckalloc(sizeof(char) * itemPtr->period);

    for(i=0; i < itemPtr->period; i++) {
	key[i] = '\0';
	maxkey[i] = '\0';
	vigPtr->maxkey[i] = '\0';
    }

    vigPtr->maxSolVal = 0.0;
    itemPtr->curIteration = 0;

    tally = RecSolveVigenere(interp, itemPtr, 0, key);

    for(i=0; i < itemPtr->period; i++) {

	/*
	 * Definition of vigenere:  k = ct - pt
	 * Definition of variant:   k = pt - ct
	 * Definition of beaufort:  k = ct + pt
	 */

	maxkey[i] = vigPtr->maxkey[i];
	c = 'a';
	switch(vigPtr->type) {
	    case GRN_TYPE:
	    case VIG_TYPE:
			p = VigenereGetPt(maxkey[i], c);
			vigPtr->vigkey[i] = maxkey[i];
			vigPtr->varkey[i] = VariantGetKey(c, p);
			vigPtr->beakey[i] = BeaufortGetKey(c, p);
			vigPtr->prtkey[i] = PortaCtPtToKey(c, p);
			break;
	    case VAR_TYPE:
			p = VariantGetPt(maxkey[i], c);
			vigPtr->vigkey[i] = VigenereGetKey(c, p);
			vigPtr->varkey[i] = maxkey[i];
			vigPtr->beakey[i] = BeaufortGetKey(c, p);
			vigPtr->prtkey[i] = PortaCtPtToKey(c, p);
			break;
	    case BEA_TYPE:
			p = BeaufortGetPt(maxkey[i], c);
			vigPtr->vigkey[i] = VigenereGetKey(c, p);
			vigPtr->varkey[i] = VariantGetKey(c, p);
			vigPtr->beakey[i] = maxkey[i];
			vigPtr->prtkey[i] = PortaCtPtToKey(c, p);
			break;
	    case PRT_TYPE:
			p = (maxkey[i] - c + 26)%26 + 'a';
			vigPtr->vigkey[i] = (c - p + 26)%26 + 'a';
			vigPtr->varkey[i] = (p - c + 26)%26 + 'a';
			vigPtr->beakey[i] = (p + c - 'a' - 'a')%26 + 'a';
			vigPtr->prtkey[i] = maxkey[i];
			break;
	}
    }

    Tcl_SetResult(interp, maxkey, TCL_VOLATILE);
    if (key) {
	ckfree(key);
    }
    if (vigPtr->maxkey) {
	ckfree(vigPtr->maxkey);
	vigPtr->maxkey = (char *)NULL;
    }
    return TCL_OK;
}

static int
QuickSolveVigenere(Tcl_Interp *interp, CipherItem *itemPtr, char *maxkey)
{
    VigenereItem *vigPtr = (VigenereItem *)itemPtr;
    char        *key=(char *)NULL;
    char        c,
                p;
    int         tally=0;
    int         maxtally=0;
    int         i;

    if (itemPtr->period < 1) {
        Tcl_SetResult(interp, "Can't solve this cipher until a period has been set", TCL_STATIC);
        return TCL_ERROR;
    }

    key = (char *)ckalloc(sizeof(char) * itemPtr->period);

    for(i=0; i < itemPtr->period; i++) {
        key[i] = maxkey[i] = '\0';
    }

    for(key[0] = 'a', tally=0; key[0] <= 'z'; key[0]++) {
        for(i=1; i < itemPtr->period; i++) {
            key[i] = '\0';
	}

        tally = RecQuickSolveVigenere(interp, itemPtr, 1, key);

        if (tally > maxtally) {
            maxtally = tally;
            for(i=0; i < itemPtr->period; i++) {
                maxkey[i] = key[i];
	    }
            maxkey[i] = '\0';
        }
    }

    for(i=0; i < itemPtr->period; i++) {

        /*
        * Definition of vigenere:  k = ct - pt
        * Definition of variant:   k = pt - ct
        * Definition of beaufort:  k = ct + pt
        */

        c = 'a';
        switch(vigPtr->type) {
            case GRN_TYPE:
            case VIG_TYPE:
			p = VigenereGetPt(maxkey[i], c);
			vigPtr->vigkey[i] = maxkey[i];
			vigPtr->varkey[i] = VariantGetKey(c, p);
			vigPtr->beakey[i] = BeaufortGetKey(c, p);
                        vigPtr->prtkey[i] = PortaCtPtToKey(c, p);
                        break;
            case VAR_TYPE:
			p = VariantGetPt(maxkey[i], c);
			vigPtr->vigkey[i] = VigenereGetKey(c, p);
			vigPtr->varkey[i] = maxkey[i];
			vigPtr->beakey[i] = BeaufortGetKey(c, p);
                        vigPtr->prtkey[i] = PortaCtPtToKey(c, p);
                        break;
            case BEA_TYPE:
			p = BeaufortGetPt(maxkey[i], c);
			vigPtr->vigkey[i] = VigenereGetKey(c, p);
			vigPtr->varkey[i] = VariantGetKey(c, p);
			vigPtr->beakey[i] = maxkey[i];
                        vigPtr->prtkey[i] = PortaCtPtToKey(c, p);
                        break;
            case PRT_TYPE:
                        p = (maxkey[i] - c + 26)%26 + 'a';
                        vigPtr->vigkey[i] = (c - p + 26)%26 + 'a';
                        vigPtr->varkey[i] = (p - c + 26)%26 + 'a';
                        vigPtr->beakey[i] = (p + c - 'a' - 'a')%26 + 'a';
                        vigPtr->prtkey[i] = maxkey[i];
                        break;
        }
    }

    Tcl_SetResult(interp, maxkey, TCL_VOLATILE);
    if (key) {
        ckfree(key);
    }
    return TCL_OK;
}

static int
RecSolveVigenere(Tcl_Interp *interp, CipherItem *itemPtr, int index, char *key)
{
    VigenereItem *vigPtr = (VigenereItem *)itemPtr;
    int		i;
    double	value;
    int		lastchar = 'z';	/* needed to satisfy limited gronsfeld key */
    char	*pt;

    if (index >= itemPtr->period) {
	Tcl_DString dsPtr;
	/*
	 * We're at the end.  Tally up the count and save it.
	 */
	pt = GetKeyedVigenere(interp, itemPtr, key);
	if (DefaultScoreValue(interp, pt, &value) != TCL_OK) {
	    return TCL_ERROR;
	}
	itemPtr->curIteration++;

	if (pt && itemPtr->stepInterval && itemPtr->stepCommand && itemPtr->curIteration%itemPtr->stepInterval == 0) {
	    char temp_str[128];

	    Tcl_DStringInit(&dsPtr);

	    Tcl_DStringAppendElement(&dsPtr, itemPtr->stepCommand);

	    sprintf(temp_str, "%ld", itemPtr->curIteration);
	    Tcl_DStringAppendElement(&dsPtr, temp_str);

	    Tcl_DStringStartSublist(&dsPtr);
	    for(i=0; i < itemPtr->period; i++) {
		sprintf(temp_str, "%c", key[i]);
		Tcl_DStringAppendElement(&dsPtr, temp_str);
	    }
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

	if (value > vigPtr->maxSolVal) {
	    char temp_str[128];

	    Tcl_DStringInit(&dsPtr);

	    if (itemPtr->bestFitCommand) {
		Tcl_DStringAppendElement(&dsPtr, itemPtr->bestFitCommand);
	    }

	    sprintf(temp_str, "%ld", itemPtr->curIteration);
	    Tcl_DStringAppendElement(&dsPtr, temp_str);

	    vigPtr->maxSolVal = value;
	    for(i=0; i < itemPtr->period; i++) {
		vigPtr->maxkey[i] = key[i];
	    }

	    Tcl_DStringStartSublist(&dsPtr);
	    for(i=0; i < itemPtr->period; i++) {
		sprintf(temp_str, "%c", key[i]);
		Tcl_DStringAppendElement(&dsPtr, temp_str);
	    }
	    Tcl_DStringEndSublist(&dsPtr);

	    sprintf(temp_str, "%g", value);
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

	if (pt) {
	    ckfree(pt);
	}

	return TCL_OK;
    } else {
	if (vigPtr->type == GRN_TYPE) {
	    lastchar = 'j';
	}

	for(key[index] = 'a'; key[index] <= lastchar; key[index]++) {
	    value = RecSolveVigenere(interp, itemPtr, index+1, key);
	}
    }

    return TCL_OK;
}

static int
RecQuickSolveVigenere(Tcl_Interp *interp, CipherItem *itemPtr, int index, char *key)
{
    VigenereItem *vigPtr = (VigenereItem *)itemPtr;
    int		i;
    int		value;
    int		maxvalue=0;
    int		maxchar='a';
    int		lastchar = 'z';	/* needed to satisfy limited gronsfeld key */
    char	c1;
    char	c2;

    if (index >= itemPtr->period) {
	/*
	 * We're at the end.  Tally up the count and save it.
	 */

	return 0;
    } else {
	/*
	 * Find the best match for this letter.
	 */

	/*
	printf("Testing key position %d\n", index);
	*/
	if (vigPtr->type == GRN_TYPE) {
	    lastchar = 'j';
	}

	for(key[index] = 'a'; key[index] <= lastchar; key[index]++) {
	    /*
	     * How well does this key value match?
	     */
	    for(i=index-1, value=0;
		i < itemPtr->length;
		i+=itemPtr->period)
	    {
		c1 = itemPtr->ciphertext[i];
		c2 = itemPtr->ciphertext[i+1];

		/*
		* Definition of vigenere:  k = ct - pt
		* Definition of variant:   k = pt - ct
		* Definition of beaufort:  k = ct + pt
		*/

		/*
		printf("%c,%c->", c1, c2);
		*/
		switch(vigPtr->type) {
		    case GRN_TYPE:
		    case VIG_TYPE: c1 = VigenereGetPt(key[index-1], c1);
				   c2 = VigenereGetPt(key[index], c2);
				   break;
		    case VAR_TYPE: c1 = VariantGetPt(key[index-1], c1);
				   c2 = VariantGetPt(key[index], c2);
				   break;
		    case BEA_TYPE: c1 = BeaufortGetPt(key[index-1], c1);
				   c2 = BeaufortGetPt(key[index], c2);
				   break;
		    case PRT_TYPE: c1 = PortaCtKeyToPt(c1, key[index-1]);
				   c2 = PortaCtKeyToPt(c2, key[index]);
				   break;
		}
		value += get_digram_value(c1, c2, itemPtr->language);
	    }

	    if (value > maxvalue) {
		maxvalue = value;
		maxchar = key[index];
	    }
	}
	fflush(stdout);

	key[index] = maxchar;
	return (maxvalue + RecQuickSolveVigenere(interp, itemPtr, index+1, key));
    }
}

static int
VigenereSetPeriod(Tcl_Interp *interp, CipherItem *itemPtr, int period)
{
    char result[16];

    sprintf(result, "%d", period);

    if (period < 1) {
	Tcl_AppendResult(interp, "Bad period for cipher:  ", result, (char *)NULL);
	return TCL_ERROR;
    }

    if (itemPtr->period == period) {
	Tcl_SetResult(interp, result, TCL_VOLATILE);
	return TCL_OK;
    }

    VigenereInitKey(itemPtr, period);

    itemPtr->period = period;

    return TCL_OK;
}

static void
VigenereInitKey(CipherItem *itemPtr, int period)
{
    VigenereItem *vigPtr = (VigenereItem *)itemPtr;
    int		i;

    if (period > 0 && period != itemPtr->period) {
	if (vigPtr->vigkey) {
	    ckfree(vigPtr->vigkey);
	}
	if (vigPtr->varkey) {
	    ckfree(vigPtr->varkey);
	}
	if (vigPtr->beakey) {
	    ckfree(vigPtr->beakey);
	}
	if (vigPtr->prtkey) {
	    ckfree(vigPtr->prtkey);
	}
	vigPtr->vigkey = (char *)NULL;
	vigPtr->beakey = (char *)NULL;
	vigPtr->varkey = (char *)NULL;
	vigPtr->prtkey = (char *)NULL;

	if (period) {
	    vigPtr->vigkey = (char *)ckalloc(sizeof(char) * period);
	    vigPtr->varkey = (char *)ckalloc(sizeof(char) * period);
	    vigPtr->beakey = (char *)ckalloc(sizeof(char) * period);
	    vigPtr->prtkey = (char *)ckalloc(sizeof(char) * period);

	    for(i=0; i < period; i++) {
		vigPtr->vigkey[i] = '\0';
		vigPtr->varkey[i] = '\0';
		vigPtr->beakey[i] = '\0';
		vigPtr->prtkey[i] = '\0';
	    }
	}
    }
}

static int
VigenereFitColumn(Tcl_Interp *interp, CipherItem *itemPtr, int col)
{
    VigenereItem *vigPtr = (VigenereItem *)itemPtr;
    int		hist[26];
    int		fitValue,
		maxValue,
		i;
    char	lastChar = 'z';
    char	ct,
    		pt,
		keyVal;
    char	result[2];

    if (itemPtr->period < 1) {
	Tcl_SetResult(interp, "Can't fit columns until a period has been set",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (itemPtr->length <= 0) {
	Tcl_SetResult(interp, "Can't fit columns until ciphertext has been set",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (col < 1 || col > itemPtr->period) {
	Tcl_SetResult(interp, "Bad column index", TCL_STATIC);
	return TCL_ERROR;
    }
    col--;

    if (vigPtr->type == GRN_TYPE) {
	lastChar = 'j';
    }

    maxValue=0;
    for (keyVal = 'a'; keyVal <= lastChar; keyVal++) {
	for (i=0; i < 26; i++) {
	    hist[i] = 0;
	}

	for (i=col; i < itemPtr->length; i+= itemPtr->period) {
	    /*
	    * Definition of vigenere:  k = ct - pt
	    * Definition of variant:   k = pt - ct
	    * Definition of beaufort:  k = ct + pt
	    */

	    ct = itemPtr->ciphertext[i];

	    switch (vigPtr->type) {
		case GRN_TYPE:
		case VIG_TYPE:  pt = VigenereGetPt(keyVal, ct);
				break;
		case VAR_TYPE:  pt = VariantGetPt(keyVal, ct);
				break;
		case BEA_TYPE:  pt = BeaufortGetPt(keyVal, ct);
				break;
		case PRT_TYPE:  pt = PortaCtKeyToPt(ct, keyVal);
				break;
		default:
		    Tcl_SetResult(interp,
                        "Unknown vigenere-like cipher type identifier found!",
                        TCL_STATIC);
		    return TCL_ERROR;
	    }

	    hist[pt-'a']++;
	}
	fitValue = alphHistFit(hist);

	if (fitValue > maxValue) {
	    maxValue = fitValue;
	    result[0] = keyVal;
	}
    }

    vigPtr->vigkey[col] = result[0];

    result[1] = '\0';

    Tcl_SetResult(interp, result, TCL_VOLATILE);
    return TCL_OK;
}

static int
EncodeVigenere(Tcl_Interp *interp, CipherItem *itemPtr, const char *pt, const char *key) {
    VigenereItem *vigPtr = (VigenereItem *)itemPtr;
    char *ct = (char *)NULL;
    int count;
    const char **argv;

    if (Tcl_SplitList(interp, key, &count, &argv) != TCL_OK) {
	return TCL_ERROR;
    }

    if (count != 2) {
	Tcl_AppendResult(interp, "Invalid number of items in encoding key '",
	      key, "'.  Should have found 2.", (char *)NULL);
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    if (strlen(argv[0]) != strlen(argv[1])) {
	Tcl_SetResult(interp, "Length of key elements must match.",
		TCL_STATIC);
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    if (strlen(argv[0]) == 0 || strlen(argv[1]) == 0) {
	Tcl_SetResult(interp, "Length of key elements can not be zero.",
		TCL_STATIC);
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    if (VigenereSetPeriod(interp, itemPtr, strlen(argv[1])) != TCL_OK) {
	ckfree((char *)argv);
        return TCL_ERROR;
    }
    /*
     * Reset the result set by VigenereSetPeriod above
     */
    Tcl_ResetResult(interp);

    /*
    if (strlen(argv[0]) != itemPtr->period || strlen(argv[1]) != itemPtr->period) {
	Tcl_SetResult(interp, "Length of key elements does not match the period.", TCL_STATIC);
	ckfree((char *)argv);
	return TCL_ERROR;
    }
    */

    /*
     * Special case the gronsfeld substitution as it has a more restricted
     * key than the vigenere.
     */
    if (vigPtr->type == GRN_TYPE) {
	int i;
	char keyLetter;

	ct = (char *)ckalloc(sizeof(char) * (strlen(pt) + 1));
	for(i=0; i < strlen(pt); i++) {
	    if (pt[i] < 'a' || pt[i] > 'z') {
		ckfree(ct);
		Tcl_AppendResult(interp,
			"Invalid character found in plaintext at position '",
			pt+i, "'", (char *)NULL);
		ckfree((char *)argv);
		return TCL_ERROR;
	    }

	    if (argv[0][i%itemPtr->period] < 'a'
		    || argv[0][i%itemPtr->period] > 'z') {
		ckfree(ct);
		Tcl_AppendResult(interp, "Invalid character in key '",
			argv[0], "'", (char *)NULL);
		ckfree((char *)argv);
		return TCL_ERROR;
	    }

	    if (argv[1][i%itemPtr->period] < 'a'
		    || argv[1][i%itemPtr->period] > 'z') {
		ckfree(ct);
		Tcl_AppendResult(interp, "Invalid character in key '",
			argv[1], "'", (char *)NULL);
		ckfree((char *)argv);
		return TCL_ERROR;
	    }

	    keyLetter = VigenereGetKey(argv[0][i%itemPtr->period],
		    argv[1][i%itemPtr->period]);

	    if (keyLetter > 'j' && keyLetter <= 'z') {
		ckfree(ct);
		Tcl_SetResult(interp, "Invalid gronsfeld substitution.",
			TCL_STATIC);
		ckfree((char *)argv);
		return TCL_ERROR;
	    }

	    ct[i] = VigenereGetCt(keyLetter, pt[i]);
	}
	ct[i] = '\0';
    } else {
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

#undef SOLVE_FAST
#undef SOLVE_THOROUGH

#undef VIG_TYPE
#undef VAR_TYPE
#undef BEA_TYPE
#undef GRN_TYPE
