/*
 * homophonic.c --
 *
 *	This file implements the homophonic cipher type.
 *
 * Copyright (c) 1995-2008 Michael Thomas <wart@kobold.org>
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
#include "score.h"
#include "cipher.h"
#include "digram.h"

#include <cipherDebug.h>

#define SOLVE_FAST	0
#define SOLVE_THOROUGH	1

static int  CreateHomophonic	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, char **));
void DeleteHomophonic		_ANSI_ARGS_((ClientData));
static char *GetHomophonic	_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetHomophonic	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
static int  RestoreHomophonic	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *));
static int  SolveHomophonic	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
int HomophonicCmd		_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, char **));
static int HomophonicUndo	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, int));
static int HomophonicSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *, int));
static int HomophonicLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *));
static char HomophonicCtToPt	_ANSI_ARGS_((int ct, char key));
static char HomophonicPtToKey	_ANSI_ARGS_((char pt, int ct));
static char *HomophonicGetFullKey _ANSI_ARGS_((CipherItem *itemPtr));
static int EncodeHomophonic	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *));


typedef struct HomophonicItem {
    CipherItem header;

    char *prv_ciphertext;
    int *int_ct;
    int int_ct_length;
    char key[4];
    int	histogram[100];
    int solveMethod;	/* Algorithm to use while solving
			 * SOLVE_FAST or SOLVE_THOROUGH */
} HomophonicItem;

CipherType HomophonicType = {
    "homophonic",
    ZEROTONINE,
    sizeof(HomophonicItem),
    CreateHomophonic,	/* create proc */
    DeleteHomophonic,	/* delete proc */
    HomophonicCmd,	/* cipher command proc */
    GetHomophonic,	/* get ciphertext proc */
    SetHomophonic,	/* set ciphertext proc */
    SolveHomophonic,	/* solve cipher proc */
    RestoreHomophonic,	/* restore proc */
    HomophonicLocateTip,/* locate proc */
    HomophonicSubstitute,/* sub proc */
    HomophonicUndo,	/* undo proc */
    EncodeHomophonic,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

static int
CreateHomophonic(Tcl_Interp *interp, CipherItem *itemPtr, int argc, char **argv)
{
    HomophonicItem *homoPtr = (HomophonicItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    homoPtr->header.period = 0;
    homoPtr->key[0] = (char)NULL;
    homoPtr->key[1] = (char)NULL;
    homoPtr->key[2] = (char)NULL;
    homoPtr->key[3] = (char)NULL;
    homoPtr->int_ct = (int *)NULL;
    homoPtr->int_ct_length = 0;
    homoPtr->prv_ciphertext = (char *)NULL;
    homoPtr->solveMethod = SOLVE_THOROUGH;

    for(i=0; i < 100; i++) {
	homoPtr->histogram[i] = 0;
    }

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, HomophonicCmd, itemPtr,
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
DeleteHomophonic(ClientData clientData)
{
    HomophonicItem *homoPtr = (HomophonicItem *)clientData;

    if (homoPtr->prv_ciphertext != NULL) {
	ckfree((char *)(homoPtr->prv_ciphertext));
    }

    if (homoPtr->int_ct != NULL) {
	ckfree((char *)(homoPtr->int_ct));
    }

    DeleteCipher(clientData);
}

int
HomophonicCmd(ClientData clientData, Tcl_Interp *interp, int argc, char **argv)
{
    HomophonicItem *homoPtr = (HomophonicItem *)clientData;
    CipherItem	*itemPtr = (CipherItem *)clientData;
    char	temp_str[1024];
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
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " cget option", (char *)NULL);
	    return TCL_ERROR;
	} else if (strncmp(argv[1], "-length", 6) == 0) {
	    sprintf(temp_str, "%d", homoPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", homoPtr->header.period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-intlength", 6) == 0) {
	    sprintf(temp_str, "%d", homoPtr->int_ct_length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!homoPtr->prv_ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_VOLATILE);
	    } else {
		Tcl_SetResult(interp, homoPtr->prv_ciphertext, TCL_VOLATILE);
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-histogram", 5) == 0) {
	    Tcl_Obj *resultObj = Tcl_NewListObj(0, NULL);
	    Tcl_Obj *elemObj = (Tcl_Obj *)NULL;
	    Tcl_Obj *histObj[2];

	    for (i=0; i < 100; i++) {
		sprintf(temp_str, "%02d", (i+1)%100);
		histObj[0] = Tcl_NewStringObj(temp_str, -1);
		histObj[1] = Tcl_NewIntObj(homoPtr->histogram[i]);
		elemObj = Tcl_NewListObj(2, histObj);
		if (Tcl_ListObjAppendList(interp, resultObj, elemObj) != TCL_OK) {
		    return TCL_ERROR;
		}
	    }

	    Tcl_SetObjResult(interp, resultObj);

	    return TCL_OK;
	} else if (strncmp(argv[1], "-plaintext", 9) == 0 ||
		   strncmp(argv[1], "-ptext", 3) == 0) {
	    tPtr = ((itemPtr->typePtr->decipherProc)(interp, itemPtr));

	    if (!tPtr) {
		return TCL_ERROR;
	    }

	    Tcl_SetResult(interp, tPtr, TCL_DYNAMIC);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-fullkey", 5) == 0) {
	    tPtr = HomophonicGetFullKey(itemPtr);
	    Tcl_SetResult(interp, tPtr, TCL_VOLATILE);
	    ckfree(tPtr);

	    return TCL_OK;
	} else if (strncmp(argv[1], "-keyword", 8) == 0) {
	    for(i=0; i < 4; i++) {
		temp_str[i] = (homoPtr->key[i]?homoPtr->key[i]:' ');
	    }
	    temp_str[i] = (char)NULL;

	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-key", 4) == 0) {
	    for(i=0; i < 4; i++) {
		temp_str[i] = (homoPtr->key[i]?homoPtr->key[i]:' ');
	    }
	    temp_str[i] = (char)NULL;

	    Tcl_AppendElement(interp, "01 26 51 76");
	    Tcl_AppendElement(interp, temp_str);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-solvemethod", 10) == 0) {
	    switch (homoPtr->solveMethod) {
		case SOLVE_FAST:
		    Tcl_SetResult(interp, "fast", TCL_STATIC);
		    break;
		case SOLVE_THOROUGH:
		    Tcl_SetResult(interp, "thorough", TCL_STATIC);
		    break;
		default:
		    fprintf(stderr, "Unknown solve method (%d) encountered.  %s line %d\n",
			    homoPtr->solveMethod,
			    __FILE__, __LINE__);
		    abort();
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
	    } else if (strncmp(*argv, "-language", 8) == 0) {
		itemPtr->language = cipherSelectLanguage(argv[1]);
		Tcl_SetResult(interp, cipherGetLanguage(itemPtr->language),
			TCL_VOLATILE);
	    } else if (strncmp(*argv, "-solvemethod", 7) == 0) {
		if (strcmp(argv[1], "fast") == 0) {
		    homoPtr->solveMethod = SOLVE_FAST;
		} else if (strcmp(argv[1], "thorough") == 0) {
		    homoPtr->solveMethod = SOLVE_THOROUGH;
		} else {
		    Tcl_SetResult(interp,
			    "Invalid solve algorithm.  Must be one of 'fast' or 'thorough'",
			    TCL_STATIC);
		    return TCL_ERROR;
		}
		return TCL_OK;
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
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " restore ct pt",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	return (itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1], argv[2]);
    } else if (**argv == 's' && (strncmp(*argv, "substitute", 2) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " substitute ct pt", (char *)NULL);
	    return TCL_ERROR;
	}
	if ((itemPtr->typePtr->subProc)(interp, itemPtr, argv[1], argv[2], 0) == BAD_SUB) {
	    return TCL_ERROR;
	} else {
	    return TCL_OK;
	}
    } else if (**argv == 's' && (strncmp(*argv, "solve", 2) == 0)) {
	if ( (itemPtr->typePtr->solveProc)(interp, itemPtr, temp_str) != TCL_OK) {
	    return TCL_ERROR;
	}

	Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	return TCL_OK;
    } else if (**argv == 'u' && (strncmp(*argv, "undo", 1) == 0)) {
	if (argc != 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " undo ct", (char *)NULL);
	    return TCL_ERROR;
	}
	(itemPtr->typePtr->undoProc)(interp, itemPtr, argv[1], 0);
	Tcl_SetResult(interp, "", TCL_VOLATILE);
	return TCL_OK;
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
    } else if (**argv == 'e' && (strncmp(*argv, "encode", 1) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " encode pt key", (char *)NULL);
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
			" solve", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" substitute ct pt", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" locate pt", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" undo ct", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" encode pt key", (char *)NULL);
	return TCL_ERROR;
    }
}

static int
SetHomophonic(Tcl_Interp *interp, CipherItem *itemPtr, char *ctext)
{
    HomophonicItem *homoPtr = (HomophonicItem *)itemPtr;
    char	*c=(char *)NULL;
    int		valid = TCL_OK,
    		length=0;
    int		count=0;
    int		i,
    		val;

    c = ctext;

    /*
     * Count the number of valid characters
     */

    length = CountValidChars(itemPtr, ctext);
    if (!length) {
	Tcl_SetResult(interp, "No valid characters found in ciphertext", TCL_VOLATILE);
	return TCL_ERROR;
    }
    if (length%2) {
	Tcl_SetResult(interp, "Odd number of valid characters found in ciphertext.", TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (itemPtr->ciphertext) {
	ckfree(itemPtr->ciphertext);
    }

    if (homoPtr->prv_ciphertext) {
	ckfree(homoPtr->prv_ciphertext);
    }

    if (homoPtr->int_ct) {
	ckfree((char *)(homoPtr->int_ct));
    }

    homoPtr->prv_ciphertext = ExtractValidChars(itemPtr, ctext);
    homoPtr->int_ct = TextToInt(interp, itemPtr, ctext, &count, "%2d", 2);
    homoPtr->int_ct_length = count;

    /*
     * Generate the histogram
     */

    for(i=0; i < 100; i++) {
	homoPtr->histogram[i] = 0;
    }

    for(i=0; i < homoPtr->int_ct_length; i++) {
	val = homoPtr->int_ct[i];

	if (val==0) val=100;
	if (val > 100) {
	    fprintf(stderr, "Ciphertext corruption error.  %s: line %d\n",
		    __FILE__, __LINE__);
	    abort();
	}

	homoPtr->histogram[val-1]++;
    }

    itemPtr->length = strlen(ctext);

    c = (char *)ckalloc(sizeof(char) * itemPtr->length + 1);
    strcpy(c, ctext);

    itemPtr->ciphertext = c;

    return valid;
}

static int
HomophonicLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, char *tip, char *start)
{
    HomophonicItem *homoPtr = (HomophonicItem *)itemPtr;
    int		valid_tip=0,
    		i;
    char	*s,
    		*c,
		*t = tip,
		*ct;
    char	used_ct[256];
    char	used_pt[256];
    char	*temp;

    Tcl_SetResult(interp, "locate procedure not yet available for homophonic ciphers", TCL_VOLATILE);
    return TCL_ERROR;

    temp = (char *)ckalloc(sizeof(char)*strlen(tip) + 2);

    ct = itemPtr->ciphertext;

    /*
     * Locate the starting point
     */

    if (start)
	s = strstr((const char *)ct, (const char *)start);
    else
	s = ct;

    if (!s) {
	Tcl_SetResult(interp, "Starting location not found.", TCL_VOLATILE);
	return TCL_ERROR;
    }

    /*
     * Loop through every possible starting point.
     */
    for(c=s; c < (ct + itemPtr->length - strlen(tip)) && valid_tip!=NEW_SUB; c++) {
	/*
	 * Loop through every letter of the tip
	 */
	valid_tip = NEW_SUB;
	for(i=0; i < 4; i++) {
	    used_ct[i] = homoPtr->key[i];
	}
	i = 0;
	for(t=tip; *t && valid_tip != BAD_SUB; t++, i++) {
	    while(c[i] && (c[i] < 'a' || c[i] > 'z')) i++;

	    if ((used_pt[(int)(c[i] - 'a')] && used_pt[(int)(c[i] - 'a')] != *t) ||
	        (used_ct[(int)(*t - 'a')] && used_ct[(int)(*t - 'a')] != c[i]))
		valid_tip = BAD_SUB;
	    else {
		used_pt[(int)(c[i] - 'a')] = *t;
		used_ct[(int)(*t - 'a')] = c[i];
		temp[t - tip] = c[i];
	    }
	}
    }
    temp[t - tip] = (char)NULL;

    if (valid_tip == NEW_SUB) {
	i = 0;
	for(i=0; i < 4; i++) {
	    homoPtr->key[i] = used_ct[i];
	}
	Tcl_SetResult(interp, temp, TCL_VOLATILE);
	return TCL_OK;
    }

    Tcl_SetResult(interp, "", TCL_VOLATILE);
    return TCL_OK;
}

static int
HomophonicUndo(Tcl_Interp *interp, CipherItem *itemPtr, char *ct, int dummy)
{
    HomophonicItem *homoPtr = (HomophonicItem *)itemPtr;
    int		*ctIntarr=(int *)NULL;
    int		col,
    		i;
    int		count;

    ctIntarr = TextToInt(interp, itemPtr, ct, &count, "%2d", 2);
    if (!ctIntarr) {
	return TCL_ERROR;
    }

    for(i=0; i < count; i++) {
	col = (ctIntarr[i]-1)/25;
	homoPtr->key[col] = (char)NULL;
    }
    ckfree((char *)ctIntarr);

    return TCL_OK;
}

static int
HomophonicSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, char *ct, char *pt, int dummy)
{
    HomophonicItem *homoPtr = (HomophonicItem *)itemPtr;
    char	*p,
		q[13],
		r[13];
    char	e,
    		f;
    char	key[4];
    char	keyChar;
    int		valid_sub = NEW_SUB;
    int		olap_sub=0, i;
    int		count=0;
    int		qcount=0,
    		rcount=0;
    int		*ctIntarr=(int *)NULL;
    int		*c;
    int		col=0;
    int		col_used[4];


    for(i=0;i<4;i++) {
	key[i] = (char)NULL;
	col_used[i] = 0;
    }

    /*
     * Convert the ciphertext into an integer array
     */

    ctIntarr = TextToInt(interp, itemPtr, ct, &count, "%2d", 2);
    if (!ctIntarr) {
	return BAD_SUB;
    }

    /*
     * Store the substitution in the temporary key.  Look for bad
     * substitutions.
     */ 
    
    c = ctIntarr, p = pt;
    for(i=0, p=pt; i < count && *p && valid_sub != BAD_SUB; i++, p++) {
	col = (c[i] - 1)/25;

	if (col > 3) {
	    fprintf(stderr, "Ciphertext corruption error\n");
	    abort();
	}

	keyChar = HomophonicPtToKey(*p, c[i]);

	if (key[col] && key[col] != keyChar) {
	    valid_sub = BAD_SUB;
	} else {
	    key[col] = keyChar;
	}
    }

    if (valid_sub == BAD_SUB) {
	ckfree((char *)ctIntarr);
	Tcl_SetResult(interp, "Bad Substitution", TCL_STATIC);
	return BAD_SUB;
    }

    /*
     * Look for "alternate" substitutions
     */

    c = ctIntarr, p = pt;
    for(i=0, p=pt; i < count && *p && valid_sub != BAD_SUB; i++, p++) {
	col = (c[i] - 1)/25;
	e = key[col], f = homoPtr->key[col];

	if (col > 3) {
	    fprintf(stderr, "Ciphertext corruption error\n");
	    abort();
	}

	if (f && e != f) {
	    valid_sub = ALT_SUB;
	    sprintf(q+qcount*3, "%2d ", c[i]);
	    qcount++;
	}

	if (e) {
	    sprintf(r+rcount*3, "%2d ", (int) (e-'a'));
	    rcount++;
	}

	col_used[col] = 1;
    }

    ckfree((char *)ctIntarr);

    if (valid_sub == BAD_SUB) {
	Tcl_SetResult(interp, "Bad Substitution", TCL_STATIC);
	return BAD_SUB;
    }

    /*
     * Store the ciphertext and the plaintext in the interpreter result
     */

    for(i=0; i < 4; i++) {
	if (col_used[i]) {
	    homoPtr->key[i] = key[i];
	}
    }

    Tcl_ResetResult(interp);
    Tcl_AppendElement(interp, ct);
    Tcl_AppendElement(interp, pt);
    if (olap_sub) {
	Tcl_AppendElement(interp, q);
	valid_sub = ALT_SUB;
    }

    return valid_sub;
}

static char *
GetHomophonic(Tcl_Interp *interp, CipherItem *itemPtr)
{
    HomophonicItem *homoPtr = (HomophonicItem *)itemPtr;
    int		*c;
    int		i,
    		col;
    char	*pt=(char *)ckalloc(sizeof(char) * homoPtr->int_ct_length + 1);

    c = homoPtr->int_ct;

    for(i=0; i < homoPtr->int_ct_length; i++) {
	col = (c[i] - 1) / 25;

	if (col > 3) {
	    fprintf(stderr, "Ciphertext corruption error\n");
	    abort();
	}

	if (homoPtr->key[col])
	    pt[i] = HomophonicCtToPt(c[i], homoPtr->key[col]);
	else
	    pt[i] = ' ';
    }

    pt[i] = (char)NULL;

    return pt;
}

static char
HomophonicCtToPt(int ct, char key)
{
    char pt;

    if (key < 'a' || key > 'z')
	return ' ';

    if (key > 'i')
	key--;
    key -= 'a';

    ct = (ct - 1)%25;

    pt = (key + ct) % 25;
    if (pt > 'i' - 'a')
	pt++;

    return pt+'a';
}

static char
HomophonicPtToKey(char pt, int ct)
{
    char key;

    if (pt < 'a' || pt > 'z') {
	return (char)NULL;
    }

    pt -= 'a';
    ct = (ct - 1)%25;

    if (pt > 'i'-'a')
	pt--;

    key = (pt - ct + 25)%25;

    if (key > 'i' - 'a')
	key++;

    return key + 'a';
}

static int
RestoreHomophonic(Tcl_Interp *interp, CipherItem *itemPtr, char *part1, char *part2)
{
    int result;

    result = (itemPtr->typePtr->subProc)(interp, itemPtr, part1, part2, 0);
    
    if (result == BAD_SUB) {
	return TCL_ERROR;
    } else {
	return TCL_OK;
    }
}

/*
 * Solve a homophonic cipher by independantly matching each
 * column to a histogram of the alphabet.
 */

static int
SolveHomophonic(Tcl_Interp *interp, CipherItem *itemPtr, char *maxkey)
{
    HomophonicItem *homoPtr = (HomophonicItem *)itemPtr;
    int		i,
    		bestfit=0;
    int		offset;
    char        *pt;
    double      bestValue = 0.0;

    if (homoPtr->solveMethod == SOLVE_FAST) {
        for(i=0; i < 4; i++) {
            offset = 25*i;
            bestfit = ij_alphfit(homoPtr->histogram+offset);
            maxkey[i] = ((char)bestfit) + 'a';
            if (maxkey[i] > 'i') {
                maxkey[i]++;
            }
        }
    } else {
        for (homoPtr->key[0]='a'; homoPtr->key[0] <= 'z'; homoPtr->key[0]++) {
            for (homoPtr->key[1]='a'; homoPtr->key[1] <= 'z'; homoPtr->key[1]++) {
                for (homoPtr->key[2]='a'; homoPtr->key[2] <= 'z'; homoPtr->key[2]++) {
                    for (homoPtr->key[3]='a'; homoPtr->key[3] <= 'z'; homoPtr->key[3]++) {
                        double value;
                        pt = GetHomophonic(interp, itemPtr);
                        if (DefaultScoreValue(interp, (unsigned char *)pt, &value)
                                != TCL_OK) {
                            ckfree(pt);
                            return TCL_ERROR;
                        }
                        ckfree(pt);
                        if (value > bestValue) {
                            maxkey[0] = homoPtr->key[0];
                            maxkey[1] = homoPtr->key[1];
                            maxkey[2] = homoPtr->key[2];
                            maxkey[3] = homoPtr->key[3];
                            bestValue = value;
                        }
                    }
                }
            }
        }
    }


    maxkey[4] = (char)NULL;
    homoPtr->key[0] = maxkey[0];
    homoPtr->key[1] = maxkey[1];
    homoPtr->key[2] = maxkey[2];
    homoPtr->key[3] = maxkey[3];
    
    Tcl_SetResult(interp, maxkey, TCL_VOLATILE);
    return TCL_OK;
}

static char *
HomophonicGetFullKey (CipherItem *itemPtr)
{
    HomophonicItem *homoPtr = (HomophonicItem *)itemPtr;
    Tcl_DString	dsPtr;
    char	temp[TCL_DOUBLE_SPACE];
    char	*result=(char *)NULL;
    int		i;

    Tcl_DStringInit(&dsPtr);

    Tcl_DStringStartSublist(&dsPtr);
    for (i=1; i <= 100; i++) {
	sprintf(temp, "%d", i);
	Tcl_DStringAppendElement(&dsPtr, temp);
    }
    Tcl_DStringEndSublist(&dsPtr);

    Tcl_DStringStartSublist(&dsPtr);
    temp[1] = (char)NULL;
    for (i=1; i <= 100; i++) {
	if (homoPtr->key[(i-1)/25])
	    temp[0] = HomophonicCtToPt(i, homoPtr->key[(i-1)/25]);
	else
	    temp[0] = ' ';

	Tcl_DStringAppendElement(&dsPtr, temp);
    }
    Tcl_DStringEndSublist(&dsPtr);

    result = (char *)ckalloc(sizeof(char) * Tcl_DStringLength(&dsPtr)+1);
    strcpy(result, Tcl_DStringValue(&dsPtr));
    Tcl_DStringFree(&dsPtr);

    return result;
}


/*
 * Reduce helps deal with the reduced-letter alphabet.
 * See ragbaby cipher.c for a more general version.
 */
char
Reduce (char c) {
    if (c > 'i') {
	return c - 1;
    } else {
	return c;
    }
}


int
EncodeHomophonic (Tcl_Interp *interp, CipherItem *itemPtr, char *pt, char *key)
{
    char offset[4];
    char firstPart[] = "01265176";
    char keyComplaint[] = "The key should be four lowercase letters.";
    char *ct;
    int count;
    int i, n;

    /*
     * Verify some conditions and 'restore' the key.
     */
    if (strlen(key) != 4) {
	Tcl_SetResult(interp, keyComplaint, TCL_VOLATILE);
	return TCL_ERROR;
    }
    for (i=0; i<4; i++) {
	if (!islower(key[i])) {
	    Tcl_SetResult(interp, keyComplaint, TCL_VOLATILE);
	    return TCL_ERROR;
	}
    }
    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, firstPart, key) != TCL_OK) {
	return TCL_ERROR;
    }

    /*
     * Set up the offsets from the key.
     */
    for (i=0; i<4; i++) {
	offset[i] = 25 - (Reduce(key[i]) - 'a');
    }

    /*
     * Encipher using random homophones (well, homographs).
     */
    n = strlen(pt);
    ct = (char *)ckalloc(sizeof(char) * (2*n+1));
    count=0;
    for (i=0; i<n; i++) {
	int c;
	int keychoice;
	char letter[4]; /* Holds up to "100". */
	if (!islower(pt[i])) {
	    continue;
	}
	keychoice = rand()%4;
	c = (offset[keychoice] + Reduce(pt[i]) - 'a') % 25;
	sprintf(letter, "%03d", c + keychoice*25 + 1);	/* Print a zero-prefixed string. */
	strcpy(ct + count, letter+1);			/* Skip the first digit. */
	count += 2;
    }
    ct[count] = (char)0;

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

#undef SOLVE_FAST
#undef SOLVE_THOROUGH
