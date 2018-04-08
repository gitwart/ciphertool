/*
 * keyphrase.c --
 *
 *	This file implements the keyphrase cipher type.
 *
 * Copyright (c) 1995-2000 Michael Thomas <wart@kobold.org>
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

static int  CreateKeyphrase	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, char **));
static char *GetKeyphrase	_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetKeyphrase	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
static int  RestoreKeyphrase	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *));
static int  SolveKeyphrase	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
int KeyphraseCmd		_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, char **));
static int KeyphraseUndo	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, int));
static int KeyphraseSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *, int));
static int KeyphraseLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *));

typedef struct KeyphraseItem {
    CipherItem header;

    char ptkey[26];	/* indexed by ciphertext letters */
    char ctkey[26][10];	/* indexed by ciphertext letters */
} KeyphraseItem;

CipherType KeyphraseType = {
    "keyphrase",
    "abcdefghijklmnopqrstuvwxyz -',.;:",
    sizeof(KeyphraseItem),
    CreateKeyphrase,	/* create proc */
    DeleteCipher,	/* delete proc */
    KeyphraseCmd,	/* cipher command proc */
    GetKeyphrase,	/* get plaintext proc */
    SetKeyphrase,	/* show ciphertext proc */
    SolveKeyphrase,	/* solve cipher proc */
    RestoreKeyphrase,	/* restore proc */
    KeyphraseLocateTip,	/* locate proc */
    KeyphraseSubstitute,/* sub proc */
    KeyphraseUndo,	/* undo proc */
    NULL,		/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

static int
CreateKeyphrase(Tcl_Interp *interp, CipherItem *itemPtr, int argc, char **argv)
{
    KeyphraseItem *kpPtr = (KeyphraseItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    kpPtr->header.period = 0;

    for(i=0; i < 26; i++)
	kpPtr->ptkey[i] = kpPtr->ctkey[i] = (char)NULL;

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++)
	Tcl_DStringAppendElement(&dsPtr, argv[i]);

    Tcl_CreateCommand(interp, temp_ptr, KeyphraseCmd, itemPtr,
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

int
KeyphraseCmd(ClientData clientData, Tcl_Interp *interp, int argc, char **argv)
{
    KeyphraseItem *kpPtr = (KeyphraseItem *)clientData;
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
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " cget option", (char *)NULL);
	    return TCL_ERROR;
	}
	if (strncmp(argv[1], "-length", 6) == 0) {
	    sprintf(temp_str, "%d", kpPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", kpPtr->header.period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!kpPtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_STATIC);
	    } else {
		Tcl_SetResult(interp, kpPtr->header.ciphertext, TCL_VOLATILE);
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-plaintext", 9) == 0 ||
		   strncmp(argv[1], "-ptext", 3) == 0) {
	    tPtr = (itemPtr->typePtr->decipherProc)(interp, itemPtr);

	    if (!tPtr) {
		return TCL_ERROR;
	    }

	    Tcl_SetResult(interp, temp_str, TCL_DYNAMIC);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-key", 4) == 0) {
	    for(i=0; i < 26; i++)
		temp_str[i] = (kpPtr->ptkey[i])?kpPtr->ptkey[i]:' ';
	    temp_str[i] = (char)NULL;

	    Tcl_AppendElement(interp, "abcdefghijklmnopqrstuvwxyz");
	    Tcl_AppendElement(interp, temp_str);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-type", 5) == 0) {
	    Tcl_SetResult(interp, itemPtr->typePtr->type, TCL_STATIC);
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
	if (strlen(argv[1]) != strlen(argv[2])) {
	    Tcl_SetResult(interp, "ciphertext and plaintext must be the same length", TCL_STATIC);
	    return TCL_ERROR;
	}
	if ((itemPtr->typePtr->subProc)(interp, itemPtr, argv[1], argv[2], 0) == BAD_SUB) {
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
	(itemPtr->typePtr->undoProc)(interp, itemPtr, argv[1], 0);
	Tcl_SetResult(interp, "", TCL_STATIC);
	return TCL_OK;
    } else if (**argv == 'l' && (strncmp(*argv, "locate", 1) == 0)) {
	if (argc < 2 || argc > 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " locate pt ct", (char *)NULL);
	    return TCL_ERROR;
	}
	if (argc == 2)
	    return (itemPtr->typePtr->locateProc)(interp, itemPtr, argv[1], (char *)NULL);
	else 
	    return (itemPtr->typePtr->locateProc)(interp, itemPtr, argv[1], argv[2]);
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
	return TCL_ERROR;
    }
}

static int
SetKeyphrase(Tcl_Interp *interp, CipherItem *itemPtr, char *ctext)
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
	if (*c == '\n' || *c == '\r') *c = ' ';

	while(*e && (*e != *c)) e++;
	if (*e && *e != ' ' && *e != '\t' && *e != '\n' &&
	    *e != '\r' && *e != *c)
	    valid = TCL_ERROR, badchar[0] = *c;

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
	    Tcl_SetResult(interp, "Error mallocing memory for new cipher", TCL_STATIC);
	    return TCL_ERROR;
	}
	itemPtr->length = length;

	c = ctext;
	e = itemPtr->ciphertext;

	while((*e++ = *c++));
	Tcl_SetResult(interp, itemPtr->ciphertext, TCL_STATIC);
    } else {
	badchar[1] = (char)NULL;
	Tcl_AppendResult(interp, "Bad character in ciphertext:  ", badchar, (char *)NULL);
    }

    return valid;
}

static int
KeyphraseLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, char *tip, char *start)
{
    KeyphraseItem *kpPtr = (KeyphraseItem *)itemPtr;
    int		valid_tip=0,
    		i;
    char	*s,
    		*c,
		*t = tip,
		*ct;
    char	used_ct[256];
    char	used_pt[256];
    char	*temp;

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
	Tcl_SetResult(interp, "Starting location not found.", TCL_STATIC);
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
	for(i=0; i < 26; i++) {
	    used_ct[i] = kpPtr->ctkey[i];
	    used_pt[i] = kpPtr->ptkey[i];
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
	for(i=0; i < 26; i++) {
	    kpPtr->ptkey[i] = used_pt[i];
	    kpPtr->ctkey[i] = used_ct[i];
	}
	Tcl_SetResult(interp, temp, TCL_VOLATILE);
	return TCL_OK;
    }

    Tcl_SetResult(interp, "", TCL_STATIC);
    return TCL_OK;
}

static int
KeyphraseUndo(Tcl_Interp *interp, CipherItem *itemPtr, char *ct, int dummy)
{
    KeyphraseItem *kpPtr = (KeyphraseItem *)itemPtr;
    char	t;

    while (*ct) {
	t = kpPtr->ptkey[*ct - 'a'];
	kpPtr->ptkey[*ct - 'a'] = (char)NULL;
	kpPtr->ctkey[t - 'a'] = (char)NULL;

	ct++;
    }

    return TCL_OK;
}

static int
KeyphraseSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, char *ct, char *pt, int dummy)
{
    KeyphraseItem *kpPtr = (KeyphraseItem *)itemPtr;
    char	*c,
		*p,
		*q,
		*r;
    char	key_ct[26];
    char	key_pt[26];
    char	t;
    int		valid_sub = NEW_SUB;
    int		olap_sub=0, i;


    q = (char *)ckalloc(sizeof(char *) * strlen(ct));
    r = q;
    *r = (char)NULL;


    for(i=0;i<26;i++) {
	key_pt[i] = (char)NULL;
	key_ct[i] = (char)NULL;
    }

    c = ct, p = pt;
    while(*c && *p && valid_sub!=BAD_SUB) {
	if(*c >= 'a' && *c <= 'z') {
	    if (key_pt[*c - 'a'] && key_pt[*c - 'a'] != *p)
		valid_sub = BAD_SUB;
	    else if (*p!=' ' && key_ct[*p - 'a'] && key_ct[*p - 'a'] != *c)
		valid_sub = BAD_SUB;
	    else {
		key_pt[*c - 'a'] = *p;
		key_ct[*p - 'a'] = *c;
	    }
	}
	c++, p++;
    }

    c = ct, p = pt;
    while (*c && *p && valid_sub) {
	if (*c >= 'a' && *c <= 'z') {
	    t = kpPtr->ptkey[*c - 'a'];

	    if (*p < 'a' || *p > 'z') {
		if (kpPtr->ctkey[t - 'a'])
		    valid_sub = ALT_SUB;
	    }
	    else if (kpPtr->ctkey[*p - 'a'] && kpPtr->ctkey[*p - 'a']!=*c)
		valid_sub = ALT_SUB;

	    if (kpPtr->ptkey[*c - 'a'] && kpPtr->ptkey[*c - 'a']!=*p)
		valid_sub = ALT_SUB;


	    if (*p < 'a' || *p > 'z') {
		kpPtr->ctkey[t - 'a'] = (char)NULL;
		kpPtr->ptkey[*c - 'a'] = (char)NULL;
	    } else {
		kpPtr->ctkey[*p - 'a'] = *c;
		kpPtr->ptkey[*c - 'a'] = *p;
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
	Tcl_SetResult(interp, "Bad Substitution", TCL_STATIC);
	return TCL_ERROR;
    }

    Tcl_AppendElement(interp, ct);
    Tcl_AppendElement(interp, pt);
    if (olap_sub) {
	Tcl_AppendElement(interp, q);
	valid_sub = ALT_SUB;
    }

    return valid_sub;
}

static char *
GetKeyphrase(Tcl_Interp *interp, CipherItem *itemPtr)
{
    KeyphraseItem *kpPtr = (KeyphraseItem *)itemPtr;
    char	*c;
    char	*pt=(char *)ckalloc(sizeof(char) * strlen(itemPtr->ciphertext)+1);
    int		index=0;

    c = itemPtr->ciphertext;

    while(*c) {
	if (*c < 'a' || *c > 'z') {
	    pt[index] = *c;
	} else {
	    if (kpPtr->ptkey[*c - 'a'])
		pt[index] = kpPtr->ptkey[*c - 'a'];
	    else
		pt[index] = ' ';
	}

	c++, index++;
    }

    pt[index] = (char)NULL;

    return pt;
}

static int
RestoreKeyphrase(Tcl_Interp *interp, CipherItem *itemPtr, char *part1, char *part2)
{
    return (itemPtr->typePtr->subProc)(interp, itemPtr, part1, part2, 0);
}

static int
SolveKeyphrase(Tcl_Interp *interp, CipherItem *itemPtr, char *result)
{
    Tcl_SetResult(interp, "You cheat!", TCL_STATIC);
    return TCL_ERROR;
}
