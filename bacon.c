/*
 * bacon.c --
 *
 *	This file implements the baconian cipher type.
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
#include <dictionaryCmds.h>

#include <cipherDebug.h>

#define AFLAG       'a'
#define BFLAG       'b'

static char baconBitsToChar[24] = {
    'a', /* aaaaa, a */
    'b', /* aaaab, b */
    'c', /* aaaba, c */
    'd', /* aaabb, d */
    'e', /* aabaa, e */
    'f', /* aabab, f */
    'g', /* aabba, g */
    'h', /* aabbb, h */
    'i', /* abaaa, i */
    'k', /* abaab, k */
    'l', /* ababa, l */
    'm', /* ababb, m */
    'n', /* abbaa, n */
    'o', /* abbab, o */
    'p', /* abbba, p */
    'q', /* abbbb, q */
    'r', /* baaaa, r */
    's', /* baaab, s */
    't', /* baaba, t */
    'u', /* baabb, u */
    'w', /* babaa, w */ /* Used to be 'v' in both places here.  I think this was a bug. */
    'x', /* babab, x */
    'y', /* babba, y */
    'z'  /* babbb, z */ };

static long alphabetBitmask[26] = {
    0x0000001, /* a */
    0x0000002, /* b */
    0x0000004, /* c */
    0x0000008, /* d */
    0x0000010, /* e */
    0x0000020, /* f */
    0x0000040, /* g */
    0x0000080, /* h */
    0x0000100, /* i */
    0x0000200, /* j */
    0x0000400, /* k */
    0x0000800, /* l */
    0x0001000, /* m */
    0x0002000, /* n */
    0x0004000, /* o */
    0x0008000, /* p */
    0x0010000, /* q */
    0x0020000, /* r */
    0x0040000, /* s */
    0x0080000, /* t */
    0x0100000, /* u */
    0x0200000, /* v */
    0x0400000, /* w */
    0x0800000, /* x */
    0x1000000, /* y */
    0x2000000  /* z */
};

extern Dictionary *globalDictionary;

static char *baconAlphabet[26] = {"aaaaa", "aaaab", "aaaba", "aaabb",
				  "aabaa", "aabab", "aabba", "aabbb",
				  "abaaa", "abaaa", "abaab", "ababa",
				  "ababb", "abbaa", "abbab", "abbba",
				  "abbbb", "baaaa", "baaab", "baaba",
				  "baabb", "baabb", "babaa", "babab",
				  "babba", "babbb" };

static int CreateBaconian	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				int, const char **));
void DeleteBaconian		_ANSI_ARGS_((ClientData));
static char *GetBaconian	_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetBaconian		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestoreBaconian	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolveBaconian	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
int BaconianCmd			_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));
static int BaconianUndo		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int BaconianSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int BaconianLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *));
static int BaconianSingleSub	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int BaconianGroupSub	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static char *BaconianTranslate	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *));
static int BaconianCheckSub	_ANSI_ARGS_((CipherItem *, const char *, const char *));
static int EncodeBaconian	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));

typedef struct BaconianItem {
    CipherItem header;

    char ptkey[26];
    char **alphabet;
    char *solPt;
    char maxSolKey[26];
    double maxSolVal;

    char *bt;
    char *pt;
} BaconianItem;

CipherType BaconianType = {
    "baconian",
    ATOZ,
    sizeof(BaconianItem),
    CreateBaconian,	/* create proc */
    DeleteBaconian,	/* delete proc */
    BaconianCmd,	/* cipher command proc */
    GetBaconian,	/* get plaintext proc */
    SetBaconian,	/* show ciphertext proc */
    SolveBaconian,	/* solve cipher proc */
    RestoreBaconian,	/* restore proc */
    BaconianLocateTip,	/* locate proc */
    BaconianSubstitute,	/* sub proc */
    BaconianUndo,	/* undo proc */
    EncodeBaconian,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

static int
CreateBaconian(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    BaconianItem *baconPtr = (BaconianItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    baconPtr->header.period = 0;
    baconPtr->alphabet = baconAlphabet;
    baconPtr->solPt = (char *)NULL;
    baconPtr->pt = (char *)NULL;
    baconPtr->bt = (char *)NULL;

    for(i=0; i < 26 ; i++) {
	baconPtr->ptkey[i] = '\0';
    }

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++)
	Tcl_DStringAppendElement(&dsPtr, argv[i]);

    Tcl_CreateCommand(interp, temp_ptr, BaconianCmd, itemPtr,
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
DeleteBaconian(ClientData clientData)
{
    BaconianItem *baconPtr = (BaconianItem *)clientData;

    if (baconPtr->pt != NULL) {
	ckfree(baconPtr->pt);
    }

    if (baconPtr->bt != NULL) {
	ckfree(baconPtr->bt);
    }

    DeleteCipher(clientData);
}

int
BaconianCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    BaconianItem *baconPtr = (BaconianItem *)clientData;
    CipherItem	*itemPtr = (CipherItem *)clientData;
    char	temp_str[256];
    char	*cmd;
    char	*tPtr=(char *)NULL;
    char	*tPtr1=(char *)NULL;
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
	if (strncmp(argv[1], "-plaintext", 9) == 0 ||
		   strncmp(argv[1], "-ptext", 3) == 0) {
	    tPtr = (itemPtr->typePtr->decipherProc)(interp, itemPtr);

	    if (!tPtr) {
		fprintf(stderr,
		    "Could not allocate memory to store result.  %s: line %d\n",
		    __FILE__, __LINE__);
		abort();
	    }

	    tPtr1 = BaconianTranslate(interp, itemPtr, tPtr, baconPtr->pt);

	    if (!tPtr1) {
		fprintf(stderr,
		    "Internal baconian error.  %s: line %d\n",
		    __FILE__, __LINE__);
		abort();
	    }

	    Tcl_SetResult(interp, tPtr1, TCL_STATIC);

	    return TCL_OK;
	} else if (strncmp(argv[1], "-bacontext", 10) == 0 ||
		   strncmp(argv[1], "-bt", 3) == 0) {
	    tPtr = (itemPtr->typePtr->decipherProc)(interp, itemPtr);
	    if (!tPtr) {
		fprintf(stderr,
		    "Could not allocate memory to store result.  %s: line %d\n",
		    __FILE__, __LINE__);
		abort();
	    }

	    Tcl_SetResult(interp, tPtr, TCL_STATIC);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-length", 6) == 0) {
	    sprintf(temp_str, "%d", baconPtr->header.length);
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
	} else if (strncmp(argv[1], "-alphabet", 6) == 0) {
	    for (i=0; i < 26; i++) {
		Tcl_AppendElement(interp, baconPtr->alphabet[i]);
	    }

	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", baconPtr->header.period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!baconPtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_VOLATILE);
	    } else {
		Tcl_SetResult(interp, baconPtr->header.ciphertext, TCL_VOLATILE);
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-key", 4) == 0) {
	    for(i=0; i < 26; i++) {
		if (baconPtr->ptkey[i]) {
		    temp_str[i] = baconPtr->ptkey[i];
		} else {
		    temp_str[i] = ' ';
		}
	    }
	    temp_str[i] = '\0';
	    Tcl_AppendElement(interp, "abcdefghijklmnopqrstuvwxyz");
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
		if (CipherSetStepCmd(itemPtr, argv[1]) != TCL_OK)
		    return TCL_ERROR;
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
    } else if (**argv == 'r' && (strncmp(*argv, "restore", 1) == 0)) {
	if (argc != 2 && argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " restore ct ?pt?", (char *)NULL);
	    return TCL_ERROR;
	}
	if (argc == 2) {
	    return (itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1], (char *)NULL);
	} else {
	    return (itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1], argv[2]);
	}
    } else if (**argv == 's' && (strncmp(*argv, "substitute", 2) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " substitute ct pt", (char *)NULL);
	    return TCL_ERROR;
	}
	if((itemPtr->typePtr->subProc)(interp, itemPtr, argv[1], argv[2], 0) == BAD_SUB) {
	    return TCL_ERROR;
	} else {
	    return TCL_OK;
	}
    } else if (**argv == 'e' && (strncmp(*argv, "encode", 1) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " encode pt key",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	return (itemPtr->typePtr->encodeProc)(interp, itemPtr, argv[1], argv[2]);
    } else if (**argv == 's' && (strncmp(*argv, "solve", 2) == 0)) {
	if ((itemPtr->typePtr->solveProc)(interp, itemPtr, temp_str) != TCL_OK) {
	    return TCL_ERROR;
	} else {
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	}
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
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " locate pt ?ct?", (char *)NULL);
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
			" locate pt ?ct?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" solve", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" substitute ct pt", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" undo ct", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" restore key", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" encode pt key", (char *)NULL);
	return TCL_ERROR;
    }
}

static int
SetBaconian(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
{
    BaconianItem *baconPtr = (BaconianItem *)itemPtr;
    char	*c;
    int		valid = TCL_OK,
    		length=0;
    char errstr[1000];

    /*
     * First find out if every character is valid
     */

    length = CountValidChars(itemPtr, ctext);
    if (!length) {
	Tcl_SetResult(interp, "No valid characters found in ciphertext",
		TCL_VOLATILE);
	return TCL_ERROR;
    }
    if (length%5) {
	sprintf(errstr, "Length of bacon ct (%d) must be a multiple of 5.", length);
	Tcl_SetResult(interp, errstr, TCL_VOLATILE);
	return TCL_ERROR;
    }

    c = ExtractValidChars(itemPtr, ctext);
    itemPtr->length = strlen(c);

    itemPtr->length = length;
    if (itemPtr->ciphertext) {
	ckfree(itemPtr->ciphertext);
    }
    itemPtr->ciphertext = c;

    if (baconPtr->pt) {
	ckfree((char *)(baconPtr->pt));
    }
    if (baconPtr->bt) {
	ckfree((char *)(baconPtr->bt));
    }
    baconPtr->pt = (char *)ckalloc(sizeof(char) * length + 1);
    baconPtr->bt = (char *)ckalloc(sizeof(char) * length/5 + 1);

    return valid;
}

static int
BaconianLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, char *tip, char *start)
{
    BaconianItem *baconPtr = (BaconianItem *)itemPtr;
    int		valid_tip=0;
    char	*s,
    		*c,
		*t = tip,
		*ct;
    char	*temp;
    Tcl_DString	dsPtr;

    temp = (char *)ckalloc(sizeof(char)*strlen(tip)*5 + 2);

    ct = itemPtr->ciphertext;

    /*
     * Convert the plaintext tip to the baconian 'ab' form
     */

    Tcl_DStringInit(&dsPtr);
    t = tip;
    while (*t) {
	if (*t >= 'a' && *t <= 'z') {
	    Tcl_DStringAppend(&dsPtr, baconPtr->alphabet[*t - 'a'], 5);
	} else {
	    Tcl_AppendResult(interp, "Bad substitution substring:  ", t, (char *)NULL);
	    Tcl_DStringFree(&dsPtr);
	    ckfree(temp);
	    return TCL_ERROR;
	}
	t++;
    }

    /*
     * Locate the starting point
     */

    if (start) {
	if (*start) {
	    s = strstr((const char *)ct, (const char *)start);
	} else {
	    s = ct;
	}
    }
    else
	s = ct;

    if (!s) {
	Tcl_SetResult(interp, "Starting location not found.", TCL_VOLATILE);
	Tcl_DStringFree(&dsPtr);
	ckfree(temp);
	return TCL_ERROR;
    }

    /*
     * Loop through every possible starting point.
     */

    for(c=s; c < (ct + 1 + itemPtr->length - Tcl_DStringLength(&dsPtr)) && valid_tip!=NEW_SUB; c+=5) {
	valid_tip = BaconianCheckSub(itemPtr, c, Tcl_DStringValue(&dsPtr));

    }
    if (c != s) {
	c-=5;
    }
    strncpy(temp, c, Tcl_DStringLength(&dsPtr));
    temp[Tcl_DStringLength(&dsPtr)] = '\0';

    if (valid_tip == NEW_SUB) {
	BaconianSingleSub(interp, itemPtr, temp, Tcl_DStringValue(&dsPtr));
	Tcl_SetResult(interp, temp, TCL_VOLATILE);
	Tcl_DStringFree(&dsPtr);
	ckfree(temp);

	return TCL_OK;
    }

    Tcl_SetResult(interp, "", TCL_VOLATILE);
    Tcl_DStringFree(&dsPtr);
    ckfree(temp);
    return TCL_OK;
}

static int
BaconianUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int dummy)
{
    BaconianItem *baconPtr = (BaconianItem *)itemPtr;

    while (*ct) {
	baconPtr->ptkey[*ct - 'a'] = '\0';
	ct++;
    }

    return TCL_OK;
}

static int
BaconianSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, const char *pt, int dummy)
{
    if (strlen(ct)%5 == 0 && strlen(ct)/5 == strlen(pt)) {
	return BaconianGroupSub(interp, itemPtr, ct, pt);
    }

    if (strlen(ct) == strlen(pt)) {
	return BaconianSingleSub(interp, itemPtr, ct, pt);
    }

    Tcl_SetResult(interp, "Ciphertext and plaintext lengths don't match up", TCL_VOLATILE);
    return BAD_SUB;
}

static int
BaconianCheckSub(CipherItem *itemPtr, const char *ct, const char *pt)
{
    BaconianItem *baconPtr = (BaconianItem *)itemPtr;
    char	key_pt[26];
    int		valid_sub = NEW_SUB;
    char	*c,
    		*p;
    int		i;
    char	c1,
		c2,
    		p1,
		p2;

    for(i=0; i < 26; i++) {
	key_pt[i] = '\0';
    }

    c = ct, p = pt;

    while (*c && *p && valid_sub != BAD_SUB) {
	if(*p != AFLAG && *p != BFLAG && *p != ' ') {
	    valid_sub = BAD_SUB;
	} else if (*c < 'a' || *c > 'z') {
	    valid_sub = BAD_SUB;
	} else if (baconPtr->ptkey[*c-'a'] && baconPtr->ptkey[*c-'a'] != *p) {
	    valid_sub = ALT_SUB;
	} else if (key_pt[*c - 'a'] && key_pt[*c - 'a'] != *p) {
	    valid_sub = BAD_SUB;
	}

	key_pt[*c - 'a'] = *p;
	c++, p++;
    }

    /*
     * Make sure we aren't trying to put two b's at the start of a word
     */

    for(i=0; i < itemPtr->length && valid_sub != BAD_SUB; i+=5) {
	c1 = itemPtr->ciphertext[i];
	c2 = itemPtr->ciphertext[i+1];
	p1 = (key_pt[c1 - 'a'])?key_pt[c1 - 'a']:baconPtr->ptkey[c1 - 'a'];
	p2 = (key_pt[c2 - 'a'])?key_pt[c2 - 'a']:baconPtr->ptkey[c2 - 'a'];

	if (p1 && p2) {
	    if (p1 == BFLAG && p2 == BFLAG) {
		valid_sub = BAD_SUB;
	    }
	}
    }

    return valid_sub;
}

static int
BaconianGroupSub(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, const char *pt)
{
    BaconianItem *baconPtr = (BaconianItem *)itemPtr;
    char	*c,
		*p,
		*q,
		*r;
    int		valid_sub = NEW_SUB;
    Tcl_DString	dsPtr;

    q = (char *)ckalloc(sizeof(char) * strlen(ct));
    r = q;
    *r = '\0';

    Tcl_DStringInit(&dsPtr);
    p = pt;
    while (*p) {
	if (*p >= 'a' && *p <= 'z') {
	    Tcl_DStringAppend(&dsPtr, baconPtr->alphabet[*p - 'a'], 5);
	} else {
	    Tcl_DStringFree(&dsPtr);
	    ckfree(q);
	    Tcl_AppendResult(interp, "Bad substitution substring:  ", p, (char *)NULL);
	    return BAD_SUB;
	}
	p++;
    }

    valid_sub = BaconianCheckSub(itemPtr, ct, Tcl_DStringValue(&dsPtr));

    if (valid_sub == BAD_SUB) {
	Tcl_SetResult(interp, "Bad substitution", TCL_VOLATILE);
	Tcl_DStringFree(&dsPtr);
	ckfree(q);
	return BAD_SUB;
    }

    c = ct, p = Tcl_DStringValue(&dsPtr);
    while (*c && *p) {
	if (baconPtr->ptkey[*c - 'a'] && baconPtr->ptkey[*c - 'a'] != *p) {
	    *r++ = *c;
	}

	baconPtr->ptkey[*c - 'a'] = *p;
	c++, p++;
    }
    *r = '\0';

    Tcl_AppendElement(interp, ct);
    Tcl_AppendElement(interp, pt);
    if (valid_sub == ALT_SUB) {
	Tcl_AppendElement(interp, q);
	valid_sub = ALT_SUB;
    }

    Tcl_DStringFree(&dsPtr);
    ckfree(q);

    return valid_sub;
}

static int
BaconianSingleSub(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, const char *pt)
{
    BaconianItem *baconPtr = (BaconianItem *)itemPtr;
    char	*c,
		*p,
		*q,
		*r;
    int		valid_sub = NEW_SUB;

    if (strlen(ct) != strlen(pt)) {
	Tcl_SetResult(interp,
		"Ciphertext and plaintext are not the same length",
		TCL_VOLATILE);
	return BAD_SUB;
    }

    valid_sub = BaconianCheckSub(itemPtr, ct, pt);

    if (valid_sub == BAD_SUB) {
	Tcl_SetResult(interp, "Bad substitution", TCL_VOLATILE);
	return BAD_SUB;
    }

    q = (char *)ckalloc(sizeof(char *) * strlen(ct));
    r = q;
    *r = '\0';

    c = ct, p = pt;
    while (*c && *p) {
	if (baconPtr->ptkey[*c - 'a'] && baconPtr->ptkey[*c - 'a'] != *p) {
	    *r++ = *c;
	}

	baconPtr->ptkey[*c - 'a'] = *p;
	p++, c++;
    }
    *r = '\0';

    Tcl_AppendElement(interp, ct);
    Tcl_AppendElement(interp, pt);
    if (valid_sub == ALT_SUB) {
	Tcl_AppendElement(interp, q);
	valid_sub = ALT_SUB;
    }

    ckfree(q);

    return valid_sub;
}

static char *
GetBaconian(Tcl_Interp *interp, CipherItem *itemPtr)
{
    BaconianItem *baconPtr = (BaconianItem *)itemPtr;
    char	*c;
    char	*key = (char *)NULL;
    int		index=0;

    c = itemPtr->ciphertext;
    key = baconPtr->ptkey;

    /*
     * First get the bacon text
     */

    while(*c) {
	if (*c < 'a' || *c > 'z') {
	    baconPtr->pt[index] = *c;
	} else {
	    if (key[*c - 'a']) {
		baconPtr->pt[index] = key[*c - 'a'];
	    } else {
		baconPtr->pt[index] = ' ';
	    }
	}

	c++, index++;
    }

    baconPtr->pt[index] = '\0';

    return baconPtr->pt;
}

static char *
BaconianTranslate(Tcl_Interp *interp, CipherItem *itemPtr, char *btext, char *result)
{
    BaconianItem *baconPtr = (BaconianItem *)itemPtr;
    char	*c;
    int		index,
    		i;
    int		blength = strlen(btext);

    for(c = btext; *c; c++) {
	if (*c != AFLAG && *c != BFLAG && *c != ' ') {
	    Tcl_AppendResult(interp, "Bad Baconian subtext:  ", c, (char *)NULL);
	    return result;
	}
    }

    if (result == (char *)NULL) {
	result = (char *)ckalloc(sizeof(char) * strlen(btext) / 5 + 2);
    }

    for(c = btext, index = 0; c < btext + blength; c+=5, index++) {
	for(i=0; i < 26 && (strncmp(c, baconPtr->alphabet[i], 5) != 0); i++);

	if (i < 26) {
	    result[index] = i + 'a';
	} else {
	    result[index] = ' ';
	}
    }
    result[index] = '\0';

    return result;
}

static int
RestoreBaconian(Tcl_Interp *interp, CipherItem *itemPtr, const char *part1, const char *part2)
{
    char *alphabet = part1;
    char *btext = part2;

    if (part2 == NULL) {
	alphabet = "abcdefghijklmnopqrstuvwxyz";
	btext = part1;
    }

    if (BaconianSingleSub(interp, itemPtr, alphabet, btext) != NEW_SUB) {
	return TCL_ERROR;
    }

    return TCL_OK;
}

/*
 * Solve a baconian cipher by going through all 2^26 possible keys
 */

static int
SolveBaconian(Tcl_Interp *interp, CipherItem *itemPtr, char *result)
{
    BaconianItem *baconPtr = (BaconianItem *)itemPtr;
    Tcl_DString dsPtr;
    long tKey = 0;
    long keyMax = 1<<26;
    int i;
    long *ctMask = (long *)NULL;
    char key[26];
    double val = 0.0;
    int btLength = itemPtr->length / 5;
    char baconVal = 0;
    int blockStart = 0;

    baconPtr->solPt = (char *)ckalloc(sizeof(char) * (btLength + 1));
    ctMask = (long *)ckalloc(sizeof(long) * itemPtr->length);
    itemPtr->curIteration=0;
    baconPtr->maxSolVal=0.0;

    for (i=0; i < itemPtr->length; i++) {
	ctMask[i] = alphabetBitmask[itemPtr->ciphertext[i] - 'a'];
    }

    /*
     * Each key can be represented by a unique 26-bit value between
     * 1<<0 and 1<<26.
     */
    for (tKey = 0; tKey < keyMax; tKey++) {
	int valid = 1;
	/*
	 * Get the bacontext from the key
	 */

	for (i=0; i < btLength && valid; i++) {
	    blockStart = i*5;
	    baconVal =  ((ctMask[blockStart]   & tKey) == 0)?0:0x10;
	    baconVal |= ((ctMask[blockStart+1] & tKey) == 0)?0:0x08;
	    baconVal |= ((ctMask[blockStart+2] & tKey) == 0)?0:0x04;
	    baconVal |= ((ctMask[blockStart+3] & tKey) == 0)?0:0x02;
	    baconVal |= ((ctMask[blockStart+4] & tKey) == 0)?0:0x01;

	    if (baconVal >= 24) {
		/*
		 * TODO: continue on to the next key if this happens because it
		 * means we got double-b's at the start of this group
		 * of bacontext, which is not allowed according to ACA
		 * standards.
		 */
		valid = 0;
		baconPtr->solPt[i] = ' ';
	    } else {
		/*
		fprintf(stdout, "%c = %s\n", baconBitsToChar[baconVal],
			itemPtr->ciphertext+i);
		*/
		baconPtr->solPt[i] = baconBitsToChar[(int)baconVal];
	    }
	}

	baconPtr->solPt[i] = '\0';

	/*
	 * Check the value of this decipherment and save the key if
	 * it was good.
	 */
	if (itemPtr->stepInterval && itemPtr->stepCommand && tKey%itemPtr->stepInterval == 0) {
	    char temp_str[128];

	    Tcl_DStringInit(&dsPtr);

	    Tcl_DStringAppendElement(&dsPtr, itemPtr->stepCommand);

	    sprintf(temp_str, "%ld", tKey);
	    Tcl_DStringAppendElement(&dsPtr, temp_str);

	    Tcl_DStringStartSublist(&dsPtr);
	    /*
	     * Convert the binary key to a 26-char array.
	     */
	    for(i=0; i < 26; i++) {
		if (tKey&(alphabetBitmask[i])) {
		    key[i] = BFLAG;
		} else {
		    key[i] = AFLAG;
		}
		sprintf(temp_str, "%c", key[i]);
		Tcl_DStringAppendElement(&dsPtr, temp_str);
	    }
	    Tcl_DStringEndSublist(&dsPtr);

	    Tcl_DStringAppendElement(&dsPtr, baconPtr->solPt);

	    if (Tcl_Eval(interp, Tcl_DStringValue(&dsPtr)) != TCL_OK) {
		Tcl_ResetResult(interp);
		Tcl_AppendResult(interp, "Bad command usage:  ", Tcl_DStringValue(&dsPtr), (char *)NULL);
		Tcl_DStringFree(&dsPtr);
		return TCL_ERROR;
	    }
	    Tcl_DStringFree(&dsPtr);
	}

	/*
	 * Weed out plaintext combinations produced from invalid
	 * bacon text (translates into spaces)
	 */

	if (! valid) {
	    continue;
	}

	if (DefaultScoreValue(interp, (const char *)baconPtr->solPt, &val)
                != TCL_OK) {
	    return TCL_ERROR;
	}
	if (val > baconPtr->maxSolVal) {
	    char temp_str[128];

	    Tcl_DStringInit(&dsPtr);

	    if (itemPtr->bestFitCommand) {
		Tcl_DStringAppendElement(&dsPtr, itemPtr->bestFitCommand);
	    }

	    sprintf(temp_str, "%ld", tKey);
	    Tcl_DStringAppendElement(&dsPtr, temp_str);

	    baconPtr->maxSolVal = val;
	    /*
	     * Convert the binary key to a 26-char array.
	     */
	    for(i=0; i < 26; i++) {
		if (tKey&(alphabetBitmask[i])) {
		    key[i] = BFLAG;
		} else {
		    key[i] = AFLAG;
		}
		baconPtr->maxSolKey[i] = key[i];
	    }

	    Tcl_DStringStartSublist(&dsPtr);
	    for(i=0; i < 26; i++) {
		sprintf(temp_str, "%c", key[i]);
		Tcl_DStringAppendElement(&dsPtr, temp_str);
	    }
	    Tcl_DStringEndSublist(&dsPtr);

	    sprintf(temp_str, "%g", val);
	    Tcl_DStringAppendElement(&dsPtr, temp_str);

	    Tcl_DStringAppendElement(&dsPtr, baconPtr->solPt);

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
    }

    for(i=0; i < 26; i++) {
	baconPtr->ptkey[i] = baconPtr->maxSolKey[i];
    }

    ckfree((char *)ctMask);
    ckfree(baconPtr->solPt);
    baconPtr->solPt = (char *)NULL;

    Tcl_ResetResult(interp);
    return TCL_OK;
}

/*
 * Get the 5-letter word dictionary file if it exists.
 * Some of this code should definitely be somewhere else.
 */
FILE *
GetWordFilePtr() {

    char s[1000];
    char filename[1000];
    char *dirname = 0;
    char share[] = "/usr/local/share/dict";
    FILE *result = 0;

    /* Get the directory. */
    if (!dirname) {
	dirname = getenv("CIPHERTOOL_DICTIONARY");
    }
    if (!dirname && getenv("HOME")) {
	sprintf(s, "%s/share/dict", getenv("HOME"));
	dirname = s;
    }
    if (!dirname) {
	dirname = share;
    }

    /* Get the filename using the directory. */
    sprintf(filename, "%s/LEN05", dirname);

    /* Try to open the file. */
    result = fopen(filename, "rt");

    return result;

}

/*
 * Given the bacon key and a null-terminated 5 letter word,
 * determine the canonical ciphertext letter that can be enciphered as this 5 letter word.
 *
 * 'key' maps {0..25} ==> {'a', 'b'}.
 */
char
GetPtLetter(const char *key, const char *word) {
    int i;
    int index = 0;
    for (i=0; i<5; i++) {
	index<<=1;
	index |= key[word[i]-'a'] - 'a';
    }
    /*
     * babbb is the largest pattern.
     * 10111 binary == 23 decimal.
     * Therefore 0 <= index <= 23.
     */
    if (index > 23) {
	return 0;
    }
    return baconBitsToChar[index];
}

static int
EncodeBaconian(Tcl_Interp *interp, CipherItem *itemPtr, const char *pt, const char *key) {
    char *ct = (char *)NULL;
    int count;
    int i;
    char **argv;
    Tcl_Obj *wordlist;

    FILE *fptr;
    char c;
    int index;
    char errstr[1000];
    char *word;
    int incomplete = 0;
    int num_5_letter_words;
    Tcl_Obj *wordListByLetter[26];
    int lengthOfWordListByLetter[26];

    if (Tcl_SplitList(interp, key, &count, &argv) != TCL_OK) {
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

    /* Load all 5-letter words from the dictionary. */
    wordlist = lookupByLength(interp, globalDictionary, 5, (char *)NULL);

    /*
     * Initialize the sorted wordlist to 26 empty lists.
     */

    for (i =0 ; i < 26; i++) {
	wordListByLetter[i] = Tcl_NewListObj(0, (Tcl_Obj **)NULL);
	lengthOfWordListByLetter[i] = 0;
    }

    /*
     * Loop through all 5-letter words and determine which bacon letter
     * they represent.
     */
    Tcl_ListObjLength(interp, wordlist, &num_5_letter_words);
    for (i=0; i < num_5_letter_words; i++) {
	Tcl_Obj *wordObj;
	int index;
	Tcl_ListObjIndex(interp, wordlist, i, &wordObj);
	index = GetPtLetter(key, Tcl_GetString(wordObj)) - 'a';
	if (index >= 0) {
	    Tcl_ListObjAppendElement(interp, wordListByLetter[index], wordObj);
	    lengthOfWordListByLetter[index]++;
	}
    }

    /*
     * Make sure that all letters including 'j' and 'v' have words to represent
     * them.
     */
    lengthOfWordListByLetter['j'-'a'] = lengthOfWordListByLetter['i'-'a'];
    wordListByLetter['j'-'a'] = wordListByLetter['i'-'a'];
    lengthOfWordListByLetter['v'-'a'] = lengthOfWordListByLetter['u'-'a'];
    wordListByLetter['v'-'a'] = wordListByLetter['u'-'a'];
    for (i=0; i<26; i++) {
	if (lengthOfWordListByLetter[i] == 0) {
	    incomplete = 1;
	}
    }

    /* This should be in another file. */
    srand(time(0));

    if (!incomplete) {
	
	/* Encode. */
	ct = (char *) ckalloc(sizeof(char) * strlen(pt)*5 + 1);
	count=0;
	for (i=0; pt[i]; i++) {
	    Tcl_Obj *wordObj;
	    c = pt[i];
	    if (islower(c)) {
		Tcl_ListObjIndex(interp,
			wordListByLetter[c-'a'],
			rand() % lengthOfWordListByLetter[c-'a'],
			&wordObj);
		strcpy(ct + 5*count, Tcl_GetString(wordObj));
		count++;
	    }
	}
    }

    /* Free vars. */
    for (i=0; i<26; i++) {
	/*
	 * 'i' and 'j' share the same wordlist, as do 'u' and 'v'.
	 * Be careful not to delete these shared wordlists twice.
	 */
	if (i != 'j'-'a' && i != 'v'-'a') {
	    Tcl_DecrRefCount(wordListByLetter[i]);
	}
    }
    Tcl_DecrRefCount(wordlist);

    if (incomplete) {
	ckfree((char *)argv);
	ckfree(ct);
	Tcl_SetResult(interp, "Not all letters have corresponding words.", TCL_VOLATILE);
	return TCL_ERROR;
    }

    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, ct) != TCL_OK) {
	ckfree((char *)argv);
	ckfree(ct);
	return TCL_ERROR;
    }

    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[0], (char *)NULL) != TCL_OK) {
	ckfree((char *)argv);
	ckfree(ct);
	return TCL_ERROR;
    }

    Tcl_SetResult(interp, itemPtr->ciphertext, TCL_VOLATILE);

    ckfree((char *)argv);
    ckfree(ct);

    return TCL_OK;
}
