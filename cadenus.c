/*
 * cadenus.c --
 *
 *	This file implements the cadenus cipher type.
 *
 * Copyright (c) 1997-2004 Michael Thomas <wart@kobold.org>
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
#include <perm.h>

#include <cipherDebug.h>

static int  CreateCadenus	_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, const char **));
void DeleteCadenus		_ANSI_ARGS_((ClientData));
static char *GetCadenus		_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetCadenus		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *));
static int  RestoreCadenus	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static int  SolveCadenus	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
int CadenusCmd			_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, const char **));
static int CadenusUndo		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, int));
static int CadenusSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *, int));
static int CadenusLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *));
static int CadenusRotate	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				int, int));
static void CadenusInitKey	_ANSI_ARGS_((CipherItem *, int));
static int CadenusSwapColumns	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
	    			int, int));
static int CadenusFitColumns	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
	    			int, int));
int CadenusCheckValue		_ANSI_ARGS_((Tcl_Interp *, ClientData,
				int *, int));
static void RecSolveCadenus	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
	    			int, char *));
static int EncodeCadenus	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				const char *, const char *));
static char *CadenusTransform	_ANSI_ARGS_((CipherItem *, const char *, int));
static char *CadenusGenerateKeyOrder _ANSI_ARGS_((const char *));

#define KEY_ROTATE	-2
#define ALL_ROTATE	-1

typedef struct CadenusItem {
    CipherItem header;

    char *key;
    int *order;

    double maxVal;
    char *maxKey;
    int *maxOrder;
} CadenusItem;

CipherType CadenusType = {
    "cadenus",
    ATOZ,
    sizeof(CadenusItem),
    CreateCadenus,	/* create proc */
    DeleteCadenus,	/* delete proc */
    CadenusCmd,		/* cipher command proc */
    GetCadenus,		/* get plaintext proc */
    SetCadenus,		/* show ciphertext proc */
    SolveCadenus,	/* solve cipher proc */
    RestoreCadenus,	/* restore proc */
    CadenusLocateTip,	/* locate proc */
    CadenusSubstitute,	/* sub proc */
    CadenusUndo,	/* undo proc */
    EncodeCadenus,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

static int
CreateCadenus(Tcl_Interp *interp, CipherItem *itemPtr, int argc, const char **argv)
{
    CadenusItem *cadPtr = (CadenusItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    cadPtr->header.period = 0;
    cadPtr->key = (char *)NULL;
    cadPtr->maxKey = (char *)NULL;
    cadPtr->maxOrder = (int *)NULL;
    cadPtr->order = (int *)NULL;
    cadPtr->maxVal = 0.0;

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, CadenusCmd, itemPtr,
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
DeleteCadenus(ClientData clientData)
{
    CadenusItem *cadPtr = (CadenusItem *)clientData;

    if (cadPtr->key) {
	ckfree(cadPtr->key);
    }

    if (cadPtr->order) {
	ckfree((char *)(cadPtr->order));
    }

    DeleteCipher(clientData);
}

static int
SetCadenus(Tcl_Interp *interp, CipherItem *itemPtr, const char *ctext)
{
    char	*c;
    int		valid = TCL_OK,
    		length=0;

    c = ctext;

    length = CountValidChars(itemPtr, ctext);
    c = ExtractValidChars(itemPtr, ctext);
    if (c == NULL) {
	Tcl_SetResult(interp, "Error mallocing memory for new cipher",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    valid = TCL_OK;

    if (valid==TCL_OK) {
	itemPtr->length = length;
	if (itemPtr->ciphertext) {
	    ckfree(itemPtr->ciphertext);
	}
	itemPtr->ciphertext = c;


	/*
	 * Cadenus ciphers must have a length that is a multiple of 25
	 */

	if (itemPtr->length % 25 != 0) {
	    Tcl_SetResult(interp,
		    "Cipher format error:  Cadenus ciphers must have a length which is a multiple of 25.",
		    TCL_VOLATILE);
	    return TCL_ERROR;
	}

	itemPtr->length = length;
	itemPtr->period = length/25;

	CadenusInitKey(itemPtr, itemPtr->period);

	Tcl_SetResult(interp, itemPtr->ciphertext, TCL_STATIC);
    }

    return valid;
}

static int
CadenusUndo(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, int offset)
{
    CadenusItem *cadPtr = (CadenusItem *)itemPtr;
    int		i;

    for(i=0; i < itemPtr->period; i++) {
	cadPtr->key[i] = '\0';
	cadPtr->order[i] = i;
    }

    return TCL_OK;
}

static int
CadenusSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, const char *ct, const char *pt, int offset)
{
    Tcl_SetResult(interp, "No substitute command for cadenus ciphers.",
	    TCL_VOLATILE);
    return TCL_ERROR;
}

static char *
GetCadenus(Tcl_Interp *interp, CipherItem *itemPtr)
{
    return CadenusTransform(itemPtr, itemPtr->ciphertext, DECODE);
}

static char *
CadenusTransform(CipherItem *itemPtr, const char *text, int mode) {
    CadenusItem *cadPtr = (CadenusItem *)itemPtr;
    int		i, col, offset;
    char	*result=(char *)NULL;
    int		newCol;
    int textLength = strlen(text);
    
    result=(char *)ckalloc(sizeof(char) * (textLength + 1));

    /*
     * Cadenus columns are 25 characters long
     */

    for(col=0; col < cadPtr->header.period; col++) {
	newCol = cadPtr->order[col];
	offset = cadPtr->key[col];

	for(i=0; i < 25; i++) {
	    int newIndex = newCol + ((i + offset)%25) * itemPtr->period;

	    int oldIndex = col + i * itemPtr->period;

	    if (newIndex > itemPtr->length || oldIndex > textLength) {
		fprintf(stderr, "Fatal indexing error! %s: line %d\n",
		       	__FILE__, __LINE__);
		abort();
	    }
	    if (mode == DECODE) {
		result[oldIndex] = cadPtr->header.ciphertext[newIndex];
	    } else {
		result[newIndex] = cadPtr->header.ciphertext[oldIndex];
	    }
	}
    }

    result[itemPtr->length] = '\0';

    return result;
}

static int
RestoreCadenus(Tcl_Interp *interp, CipherItem *itemPtr, const char *key, const char *order)
{
    CadenusItem *cadPtr = (CadenusItem *)itemPtr;
    int i;

    if (strlen(order) != cadPtr->header.period || strlen(key) != cadPtr->header.period) {
	Tcl_SetResult(interp,
		"Key and order must be the same length as the cipher period",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    for(i=0; i < cadPtr->header.period; i++) {
	if (order[i]-'0' < 1 || order[i]-'0' > cadPtr->header.period) {
	    Tcl_SetResult(interp, "Invalid character in order", TCL_VOLATILE);
	    return TCL_ERROR;
	}
	if (key[i] < 'a' || key[i] > 'z') {
	    Tcl_SetResult(interp, "Invalid character in key", TCL_VOLATILE);
	    return TCL_ERROR;
	}
    }
    for(i=0; i < cadPtr->header.period; i++) {
	cadPtr->order[i] = order[i]-'1';
	cadPtr->key[i] = key[i]-'a';
	if (key[i] > 'v') {
	    cadPtr->key[i]--;
	}
    }

    return TCL_OK;
}

/*
 * Fix this
 */

static int
SolveCadenus(Tcl_Interp *interp, CipherItem *itemPtr, char *maxkey)
{
    CadenusItem *cadPtr = (CadenusItem *)itemPtr;
    int i;
    char *curKey;

    curKey = (char *)ckalloc(sizeof(char) * itemPtr->period);
    for(i=0; i < itemPtr->period; i++) {
	curKey[i] = '\0';
    }

    if (cadPtr->maxKey) {
	ckfree(cadPtr->maxKey);
    }
    if (cadPtr->maxOrder) {
	ckfree((char *)(cadPtr->maxOrder));
    }
    cadPtr->maxKey = (char *)ckalloc(sizeof(char)*itemPtr->period);
    cadPtr->maxOrder = (int *)ckalloc(sizeof(int)*itemPtr->period);
    cadPtr->maxVal = 0;

    _internalDoPermCmd((ClientData)itemPtr, interp, itemPtr->period, CadenusCheckValue);

    /*
    RecSolveCadenus(interp, itemPtr, 0, curKey);
    */

    for(i=0; i < itemPtr->period; i++) {
	cadPtr->key[i] = cadPtr->maxKey[i];
	cadPtr->order[i] = cadPtr->maxOrder[i];
    }

    ckfree(cadPtr->maxKey);
    ckfree((char *)(cadPtr->maxOrder));
    cadPtr->maxKey = (char *)NULL;
    cadPtr->maxOrder = (int *)NULL;

    Tcl_ResetResult(interp);
    return TCL_OK;
}

static void
RecSolveCadenus(Tcl_Interp *interp, CipherItem *itemPtr, int depth, char *curKey) {
    CadenusItem *cadPtr = (CadenusItem *)itemPtr;
    int i;

    if (depth == itemPtr->period) {
	/*
	 * Perform a best fit search of all permutations
	 */
	for(i=0; i < itemPtr->period; i++) {
	    cadPtr->key[i] = curKey[i];
	    fprintf(stderr, "%d ", curKey[i]);
	}
	fprintf(stderr, "\n");
	fflush(stderr);

	_internalDoPermCmd((ClientData)itemPtr, interp, itemPtr->period, CadenusCheckValue);
    } else {
	for(i=0; i < 25; i++) {
	    curKey[depth] = i;
	    RecSolveCadenus(interp, itemPtr, depth+1, curKey);
	}
    }
}

int
CadenusCheckValue(Tcl_Interp *interp, ClientData clientData, int *key, int keylen)
{
    CadenusItem *cadPtr = (CadenusItem *)clientData;
    int		i;
    double	value;
    char	*pt = (char *)NULL;
    char	*tOrder;

    tOrder = (char *)ckalloc(sizeof(char) * keylen);
    for(i=0; i < keylen; i++) {
	tOrder[i] = cadPtr->order[i];
    }

    for(i=0; i < keylen; i++) {
	cadPtr->order[i] = key[i];
    }
    
    for(i=1; i <= keylen; i++) {
	CadenusFitColumns(interp, (CipherItem *)clientData, i, i+1);
    }

    pt = GetCadenus(interp, (CipherItem *)clientData);

    if (pt) {
	if (DefaultScoreValue(interp, pt, &value) != TCL_OK) {
	    return TCL_ERROR;
	}

	if (value > cadPtr->maxVal) {
	    cadPtr->maxVal = value;
	    for(i=0; i < keylen; i++) {
		cadPtr->maxKey[i] = cadPtr->key[i];
		cadPtr->maxOrder[i] = cadPtr->order[i];
	    }
	}
	ckfree(pt);
	pt = (char *)NULL;
    }

    ckfree(tOrder);

    return TCL_OK;
}

static void
CadenusInitKey(CipherItem *itemPtr, int period)
{
    CadenusItem *cadPtr = (CadenusItem *)itemPtr;
    int		i;

    if (cadPtr->key) {
	ckfree(cadPtr->key);
    }

    if (cadPtr->order) {
	ckfree((char *)(cadPtr->order));
    }

    cadPtr->key = (char *)NULL;
    cadPtr->order = (int *)NULL;
    cadPtr->header.period = period;

    if (period) {
	cadPtr->key=ckalloc(sizeof(char)*period+1);
	cadPtr->order=(int *)ckalloc(sizeof(int)*(period+1));
	for(i=0; i < cadPtr->header.period; i++) {
	    cadPtr->key[i] = '\0';
	    cadPtr->order[i] = i;
	}
	cadPtr->key[period]='\0';
	cadPtr->order[period]=0;
    }
}

/*
 * We probably won't need this.
 */

static int
CadenusLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, char *tip, char *start)
{
    Tcl_SetResult(interp, "No locate tip function defined for cadenus ciphers.",
	    TCL_VOLATILE);
    return TCL_ERROR;
}

static int
CadenusRotate(Tcl_Interp *interp, CipherItem *itemPtr, int col, int amt)
{
    CadenusItem *cadPtr = (CadenusItem *)itemPtr;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp,
		"Can't do anything until the ciphertext has been set",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (col < 1 || col > itemPtr->period) {
	Tcl_SetResult(interp, "Bad column value.", TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (amt < -25 || amt > 25) {
	Tcl_SetResult(interp, "Bad rotation amount.", TCL_VOLATILE);
	return TCL_ERROR;
    }
    col--;
    /*
    col = cadPtr->order[col];
    */

    cadPtr->key[col] = ((char)amt + cadPtr->key[col] + 25) % 25;

    return TCL_OK;
}

static int
CadenusFitColumns(Tcl_Interp *interp, CipherItem *itemPtr, int col1, int col2)
{
    CadenusItem *cadPtr = (CadenusItem *)itemPtr;
    int i, tcol1, tcol2;
    char string1[26];
    char string2[26];

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp,
		"Can't do anything until the ciphertext has been set",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (col1 < 1 || col2 < 1 || col1 == col2 || col1 > itemPtr->period || col2 > itemPtr->period) {
	Tcl_SetResult(interp, "Bad column value", TCL_VOLATILE);
	return TCL_ERROR;
    }
    col1--, col2--;

    /*
    printf("col1, col2 = %d, %d\n", col1, col2);
    */
    tcol1 = cadPtr->order[col1];
    tcol2 = cadPtr->order[col2];
    /*
    printf("tcol1, tcol2 = %d, %d\n", tcol1, tcol2);
    printf("key = ");
    for(i=0; i < itemPtr->period; i++)
	printf("%d ", cadPtr->key[i]);
    printf("\n");
    */
    for(i=0; i < 25; i++) {
	string1[i] = itemPtr->ciphertext[tcol1+((i+cadPtr->key[col1]+25)%25)*itemPtr->period];
	string2[i] = itemPtr->ciphertext[tcol2+((i+cadPtr->key[col2]+25)%25)*itemPtr->period]; }
    string1[25] = string2[25] = '\0';
    /*
    printf("Fitting: %s\n         %s\n", string1, string2);
    */
    i = 25 - find_best_fit(string1, string2, itemPtr->language);
    /*
    printf("best fit = %d\n", i);
    */
    cadPtr->key[col2] = (i + cadPtr->key[col2] + 25 )%25;
    /*
    cadPtr->key[col] = ((char)amt + cadPtr->key[col] + 25) % 25;
    */

    sprintf(string1, "%d", i);
    Tcl_SetResult(interp, string1, TCL_VOLATILE);

    return TCL_OK;
}

static int
CadenusSwapColumns(Tcl_Interp *interp, CipherItem *itemPtr, int col1, int col2)
{
    CadenusItem *cadPtr = (CadenusItem *)itemPtr;
    char t;

    if (itemPtr->length == 0) {
	Tcl_SetResult(interp,
		"Can't do anything until the ciphertext has been set",
		TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (col1 < 1 ||
	col2 < 1 ||
	col1 > itemPtr->period ||
	col2 > itemPtr->period ||
	col1 == col2) {

	Tcl_SetResult(interp, "Bad column index", TCL_VOLATILE);
	return TCL_ERROR;
    }

    /*
    printf("Swapping columns %d and %d\n", col1, col2);
    */
    col1--, col2--;

    /*
    for(i=0; i < itemPtr->period && cadPtr->order[i] != col1; i++);
    col1 = i;
    for(i=0; i < itemPtr->period && cadPtr->order[i] != col2; i++);
    col2 = i;
    */

    if (col1 == itemPtr->period || col2 == itemPtr->period) {
	fprintf(stderr, "Columns not found!\n");
	abort();
    }

    t = cadPtr->order[col1];
    cadPtr->order[col1] = cadPtr->order[col2];
    cadPtr->order[col2] = t;

    t = cadPtr->key[col1];
    cadPtr->key[col1] = cadPtr->key[col2];
    cadPtr->key[col2] = t;

    /*
    printf("order = ");
    for(i=0; i < itemPtr->period; i++) {
	printf("%d ", cadPtr->order[i]);
    }
    printf("\n");
    printf("key   = ");
    for(i=0; i < itemPtr->period; i++) {
	printf("%d ", cadPtr->key[i]);
    }
    printf("\n\n");
    */

    return TCL_OK;
}

int
CadenusCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    CadenusItem *cadPtr = (CadenusItem *)clientData;
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
	    sprintf(temp_str, "%d", cadPtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", itemPtr->period);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!cadPtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_VOLATILE);
	    } else {
		Tcl_SetResult(interp, cadPtr->header.ciphertext, TCL_VOLATILE);
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
	} else if (strncmp(argv[1], "-keyword", 8) == 0) {
	    for(i=0; i < itemPtr->period; i++) {
		temp_str[i] = cadPtr->key[i]+'a';
		if (temp_str[i] > 'v') {
		    temp_str[i]++;
		}
	    }
	    temp_str[itemPtr->period] = '\0';

	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-key", 4) == 0) {
	    for(i=0; i < itemPtr->period; i++) {
		temp_str[i] = cadPtr->key[i]+'a';
		if (temp_str[i] > 'v') {
		    temp_str[i]++;
		}
	    }
	    temp_str[itemPtr->period] = '\0';

	    Tcl_AppendElement(interp, temp_str);

	    for(i=0; i < itemPtr->period; i++) {
		sprintf(temp_str+i, "%d", cadPtr->order[i]+1);
	    }
	    temp_str[itemPtr->period] = '\0';

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
	    if (strncmp(*argv, "-ciphertext", 10) == 0 ||
		strncmp(*argv, "-ctext", 3) == 0) {
		if ((itemPtr->typePtr->setctProc)(interp, itemPtr, argv[1]) != TCL_OK) {
		    return TCL_ERROR;
		}
	    } else if (strncmp(*argv, "-period", 7) == 0) {
		/*
		 * Ignore attempts to set the period.
		 */

		Tcl_SetResult(interp, "", TCL_VOLATILE);
		return TCL_OK;
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
    } else if (**argv == 'r' && (strncmp(*argv, "restore", 2) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " restore key order", 
		    (char *)NULL);
	    return TCL_ERROR;
	}
	if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[1], argv[2]) == TCL_ERROR) {
	    return TCL_ERROR;
	} else {
	    return TCL_OK;
	}
    } else if (**argv == 's' && (strncmp(*argv, "substitute", 2) == 0)) {
	Tcl_AppendResult(interp,
		"No substitute command defined for cadenus ciphers",
		(char *)NULL);
	return TCL_ERROR;
    } else if (**argv == 'e' && (strncmp(*argv, "encode", 1) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " encode pt key",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	return (itemPtr->typePtr->encodeProc)(interp, itemPtr, argv[1], argv[2]);
    } else if (**argv == 'r' && (strncmp(*argv, "rotate", 2) == 0)) {
	int col, amt;
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " rotate key|col|all amt",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	if (strcmp(argv[1], "all") == 0) {
	    col = ALL_ROTATE;
	} else if (strcmp(argv[1], "key") == 0) {
	    col = KEY_ROTATE;
	} else if (sscanf(argv[1], "%d", &col) != 1) {
	    Tcl_SetResult(interp, "Bad column value.", TCL_VOLATILE);
	    return TCL_ERROR;
	}

	if (sscanf(argv[2], "%d", &amt) != 1) {
	    Tcl_SetResult(interp, "Bad rotation amount.", TCL_VOLATILE);
	    return TCL_ERROR;
	}

	if (col == KEY_ROTATE) {
	    if (itemPtr->period > 1) {
		char *tKey = (char *)ckalloc(sizeof(char) * itemPtr->period);
		char *tOrder = (char *)ckalloc(sizeof(int) * itemPtr->period);
		for(i=0; i < itemPtr->period; i++) {
		    tKey[i] = cadPtr->key[i];
		    tOrder[i] = cadPtr->order[i];
		}
		for(i=0; i < itemPtr->period; i++) {
		    cadPtr->key[i] =
			    tKey[(i + amt + itemPtr->period)%itemPtr->period];
		    cadPtr->order[i] =
			    tOrder[(i + amt + itemPtr->period)%itemPtr->period];
		}

		ckfree(tKey);
		ckfree((char *)tOrder);
	    }
	} else if (col == ALL_ROTATE) {
	    for(i=1; i <= itemPtr->period; i++) {
		if (CadenusRotate(interp, itemPtr, i, amt) != TCL_OK) {
		    return TCL_ERROR;
		}
	    }
	} else {
	    if (CadenusRotate(interp, itemPtr, col, amt) != TCL_OK) {
		return TCL_ERROR;
	    }
	}

	return TCL_OK;
    } else if (**argv == 'f' && (strncmp(*argv, "fit", 3) == 0)) {
	int col1, col2;
	if (argc == 2) {
	    for(i=1; i < itemPtr->period; i++) {
		if (CadenusFitColumns(interp, itemPtr, i, i+1) != TCL_OK) {
		    return TCL_ERROR;
		}
	    }
	    return TCL_OK;
	}
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " fit ?col1 col2?",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	if (sscanf(argv[1], "%d", &col1) != 1) {
	    Tcl_SetResult(interp, "Bad column value.", TCL_VOLATILE);
	    return TCL_ERROR;
	}
	if (sscanf(argv[2], "%d", &col2) != 1) {
	    Tcl_SetResult(interp, "Bad column value.", TCL_VOLATILE);
	    return TCL_ERROR;
	}

	if (CadenusFitColumns(interp, itemPtr, col1, col2) != TCL_OK) {
	    return TCL_ERROR;
	}

	return TCL_OK;
    } else if (**argv == 's' && (strncmp(*argv, "swap", 2) == 0)) {
	int col1, col2;
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " swap col1 col2",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	if (sscanf(argv[1], "%d", &col1) != 1) {
	    Tcl_SetResult(interp, "Bad column value.", TCL_VOLATILE);
	    return TCL_ERROR;
	}
	if (sscanf(argv[2], "%d", &col2) != 1) {
	    Tcl_SetResult(interp, "Bad column value.", TCL_VOLATILE);
	    return TCL_ERROR;
	}

	if (CadenusSwapColumns(interp, itemPtr, col1, col2) != TCL_OK) {
	    return TCL_ERROR;
	}

	return TCL_OK;
    } else if (**argv == 's' && (strncmp(*argv, "solve", 2) == 0)) {
	if( (itemPtr->typePtr->solveProc)(interp, itemPtr, temp_str) != TCL_OK) {
	    /*
	     * This should not be able to happen.
	     */
	    fprintf(stderr, "Internal cipher error:  cadenus solve proc returned !TCL_OK\n");
	    abort();
	    return TCL_ERROR;
	} else {
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	}
    } else if (**argv == 'u' && (strncmp(*argv, "undo", 1) == 0)) {
	/*
	 * The final argument to CadenusUndo is ignored.  Send it a dummy
	 * value of '0'
	 */
	if ( (itemPtr->typePtr->undoProc)(interp, itemPtr, argv[1], 0) != TCL_OK) {
	    /*
	     * This should not be able to happen.
	     */
	    fprintf(stderr, "Internal cipher error:  cadenus undo proc returned !TCL_OK\n");
	    abort();
	    return TCL_ERROR;
	}
	Tcl_SetResult(interp, "", TCL_VOLATILE);
	return TCL_OK;
    } else if (**argv == 'l' && (strncmp(*argv, "locate", 1) == 0)) {
	Tcl_SetResult(interp,
		"No locate tip function defined for cadenus ciphers.",
		TCL_VOLATILE);
	return TCL_ERROR;
    } else {
	Tcl_AppendResult(interp, "Unknown option ", *argv, (char *)NULL);
	Tcl_AppendResult(interp, "\nMust be one of:  ", cmd,
			" cget ?option?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" configure ?option value?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" solve", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" rotate col amt", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" undo ct", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" encode pt key", (char *)NULL);
	return TCL_ERROR;
    }
}

static char *
CadenusGenerateKeyOrder(const char *key) {
    int keyLength = strlen(key);
    char *order = (char *)ckalloc(sizeof(char) * (keyLength+1));
    int i, j;

    for (i=0; i < keyLength; i++) {
        order[i] = '1';
    }
    for (i=0; i < keyLength; i++) {
        for (j=i+1; j < keyLength; j++) {
            if ((i != j && key[j] < key[i]) || (i > j && key[j] == key[i])) {
                order[i]++;
            } else {
                order[j]++;
            }
        }
    }
    order[keyLength] = '\0';
    
    return order;
}

static int
EncodeCadenus(Tcl_Interp *interp, CipherItem *itemPtr, const char *pt, const char *key) {
    char *ct = (char *)NULL;
    int count;
    char *order = (char *)NULL;
    int orderFromMalloc = 0;
    char **argv;

    if (Tcl_SplitList(interp, key, &count, &argv) != TCL_OK) {
	return TCL_ERROR;
    }

    if (count == 1) {
        order = CadenusGenerateKeyOrder(argv[0]);
        orderFromMalloc = 1;
    } else if (count == 2) {
        order = argv[1];
    } else if (count != 2) {
	ckfree((char *)argv);
	Tcl_AppendResult(interp, "Invalid number of items in encoding key '",
	      key, "'.  Should have found 1 or 2.", (char *)NULL);
	return TCL_ERROR;
    }

    if (strlen(argv[0]) != strlen(order)) {
	ckfree((char *)argv);
        if (orderFromMalloc) {
            ckfree((char *)order);
        }
	Tcl_SetResult(interp, "Lengths of encoding key elements must match.",
		TCL_STATIC);
	return TCL_ERROR;
    }


    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, pt) != TCL_OK) {
	ckfree((char *)argv);
        if (orderFromMalloc) {
            ckfree((char *)order);
        }
	return TCL_ERROR;
    }

    /*
     * The period of a cadenus cipher is set at the same time that the
     * ciphertext is set.  We have to postpone checking the length of the
     * key until after this.
     */
    if (strlen(argv[0]) != itemPtr->period) {
	Tcl_SetResult(interp,
		"Length of key does not match the period.", TCL_STATIC);
	ckfree((char *)argv);
        if (orderFromMalloc) {
            ckfree((char *)order);
        }
	return TCL_ERROR;
    }

    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[0], order) != TCL_OK) {
	ckfree((char *)argv);
        if (orderFromMalloc) {
            ckfree((char *)order);
        }
	return TCL_ERROR;
    }
    ct = CadenusTransform(itemPtr, itemPtr->ciphertext, ENCODE);
    if (ct == (char *)NULL) {
	ckfree((char *)argv);
        if (orderFromMalloc) {
            ckfree((char *)order);
        }
	return TCL_ERROR;
    }
    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, ct) != TCL_OK) {
	ckfree((char *)argv);
        if (orderFromMalloc) {
            ckfree((char *)order);
        }
	return TCL_ERROR;
    }
    if ((itemPtr->typePtr->restoreProc)(interp, itemPtr, argv[0], order) != TCL_OK) {
	ckfree((char *)argv);
        if (orderFromMalloc) {
            ckfree((char *)order);
        }
	return TCL_ERROR;
    }

    Tcl_SetResult(interp, ct, TCL_DYNAMIC);
    ckfree((char *)argv);
    if (orderFromMalloc) {
        ckfree((char *)order);
    }

    return TCL_OK;
}
