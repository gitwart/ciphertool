/*
 * trigramScore.c --
 *
 *	This file implements the trigram scoring methods.
 *
 * Copyright (c) 2004 Michael Thomas <wart@kobold.org>
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
#include <score.h>
#include <math.h>
#include <string.h>

double TrigramStringValue _ANSI_ARGS_((unsigned char *, double ***));
double TrigramSingleValue _ANSI_ARGS_((unsigned char, unsigned char, unsigned char, double ***));

static int CreateTrigram _ANSI_ARGS_((Tcl_Interp *, ScoreItem *, int, char **));
static int AddTrigram _ANSI_ARGS_((Tcl_Interp *, ScoreItem *, unsigned char *, double));
static void DeleteTrigram _ANSI_ARGS_((ClientData));
static int NormalizeTrigramLog _ANSI_ARGS_((Tcl_Interp *, ScoreItem *));
static double TrigramValue _ANSI_ARGS_((Tcl_Interp *, ScoreItem *, unsigned char *));
static double TrigramElementValue _ANSI_ARGS_((Tcl_Interp *, ScoreItem *, unsigned char *));
static int DumpTrigram _ANSI_ARGS_((Tcl_Interp *, ScoreItem *, char *));

typedef struct TrigramItem {
    ScoreItem header;

    double ***value;
} TrigramItem;

ScoreType TrigramLogType = {
    "trigramlog",
    sizeof(TrigramItem),
    CreateTrigram,
    AddTrigram,
    TrigramValue,
    TrigramElementValue,
    NormalizeTrigramLog,
    DeleteTrigram,
    DumpTrigram,
    ScoreMethodCmd,
    (ScoreType *)NULL
};

ScoreType TrigramCountType = {
    "trigramcount",
    sizeof(TrigramItem),
    CreateTrigram,
    AddTrigram,
    TrigramValue,
    TrigramElementValue,
    NullScoreNormalizer,
    DeleteTrigram,
    DumpTrigram,
    ScoreMethodCmd,
    (ScoreType *)NULL
};

static int
CreateTrigram(Tcl_Interp *interp, ScoreItem *itemPtr, int argc, char **argv) {
    TrigramItem *tlPtr = (TrigramItem *)itemPtr;
    char temp_ptr[TCL_DOUBLE_SPACE];
    Tcl_DString dsPtr;
    int i, j, k;

    tlPtr->header.elemSize = 3;
    tlPtr->value = (double ***)ckalloc(sizeof(double **) * 26);
    for (i=0; i < 26; i++) {
	tlPtr->value[i] = (double **)ckalloc(sizeof(double *) * 26);
	for (j=0; j < 26; j++) {
	    tlPtr->value[i][j] = (double *)ckalloc(sizeof(double) * 26);
	    for (k=0; k < 26; k++) {
		tlPtr->value[i][j][k] = 0.0;
	    }
	}
    }
    sprintf(temp_ptr, "score%d", scoreid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for (i=0; i < argc; i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, ScoreMethodCmd, itemPtr,
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
DeleteTrigram(ClientData clientData) {
    TrigramItem *tlPtr = (TrigramItem *)clientData;
    int i, j;

    if (tlPtr->value != NULL) {
	for(i=0; i < 26; i++) {
	    if (tlPtr->value[i] != NULL) {
		for (j=0; j < 26; j++) {
		    ckfree((char *)tlPtr->value[i][j]);
		}
	    }
	    ckfree((char *)tlPtr->value[i]);
	}
	ckfree((char *)tlPtr->value);
    }
    tlPtr->value = (double ***)NULL;

    DeleteScore(clientData);
}

static int
AddTrigram(Tcl_Interp *interp, ScoreItem *itemPtr, unsigned char *element, double value)  {
    TrigramItem *tlPtr = (TrigramItem *)itemPtr;

    if (element[0] < 'a' || element[0] > 'z'
	    || element[1] < 'a' || element[1] > 'z'
	    || element[2] < 'a' || element[2] > 'z') {
	Tcl_AppendResult(interp, "Invalid trigram ", element, (char *)NULL);

	return TCL_ERROR;
    }

    tlPtr->value[element[0]-'a'][element[1]-'a'][element[2]-'a'] += value;

    Tcl_SetResult(interp, element, TCL_VOLATILE);
    return TCL_OK;
}

static double
TrigramValue(Tcl_Interp *interp, ScoreItem *itemPtr, unsigned char *string) {
    TrigramItem *tlPtr = (TrigramItem *)itemPtr;

    return TrigramStringValue(string, (double ***)tlPtr->value);
}

static double
TrigramElementValue(Tcl_Interp *interp, ScoreItem *itemPtr, unsigned char *string) {
    TrigramItem *tlPtr = (TrigramItem *)itemPtr;

    return TrigramSingleValue((unsigned char)string[0], (unsigned char)string[1], (unsigned char)string[2], tlPtr->value);
}

double
TrigramStringValue(unsigned char *string, double ***table) {
    int length = strlen(string);
    double value = 0.0;
    int i;

    for (i=2; i < length; i++) {
	if ((string[i-2] >= 'a' && string[i-2] <= 'z')
		&& (string[i-1] >= 'a' && string[i-1] <= 'z')
		&& (string[i] >= 'a' && string[i] <= 'z')) {
	    value += TrigramSingleValue(string[i-2], string[i-1], string[i], table);
	}
    }
    
    return value;
}

/*
 * TODO:  Replace this with a macro
 */
double
TrigramSingleValue(unsigned char val1, unsigned char val2, unsigned char val3, double ***table) {
    return table[val1-'a'][val2-'a'][val3-'a'];
}

static int
NormalizeTrigramLog(Tcl_Interp *interp, ScoreItem *itemPtr) {
    TrigramItem *tlPtr = (TrigramItem *)itemPtr;
    int i, j, k;

    for(i=0; i < 26; i++) {
	for (j=0; j < 26; j++) {
	    for (k=0; k < 26; k++) {
		if (tlPtr->value[i][j][k] > 0.0) {
		    tlPtr->value[i][j][k] = log(tlPtr->value[i][j][k]);
		} else {
		    tlPtr->value[i][j][k] = 0.0;
		}
	    }
	}
    }

    Tcl_ResetResult(interp);
    return TCL_OK;
}

static int
DumpTrigram(Tcl_Interp *interp, ScoreItem *itemPtr, char *script) {
    TrigramItem *tlPtr = (TrigramItem *)itemPtr;
    Tcl_DString dsPtr;
    unsigned char i, j, k;
    int length;
    unsigned char element[4];
    Tcl_Obj *valueObj = Tcl_NewDoubleObj(0.0);

    element[3] = (char)NULL;

    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppend(&dsPtr, script, strlen(script));
    length = Tcl_DStringLength(&dsPtr);

    for (i='a'; i <= 'z'; i++) {
	for (j='a'; j <= 'z'; j++) {
	    for (k='a'; k <= 'z'; k++) {
		if (TrigramSingleValue(i, j, k, tlPtr->value) > 0.0) {
		    element[0] = i;
		    element[1] = j;
		    element[2] = k;

		    Tcl_DStringSetLength(&dsPtr, length);
		    Tcl_DStringStartSublist(&dsPtr);
		    Tcl_DStringAppendElement(&dsPtr, element);
		    Tcl_SetDoubleObj(valueObj, TrigramSingleValue(i, j, k, tlPtr->value));
		    Tcl_DStringAppendElement(&dsPtr, Tcl_GetString(valueObj));
		    Tcl_DStringEndSublist(&dsPtr);

		    if (Tcl_EvalEx(interp, Tcl_DStringValue(&dsPtr), Tcl_DStringLength(&dsPtr), 0) != TCL_OK) {
			return TCL_ERROR;
		    }
		}
	    }
	}
    }

    Tcl_DecrRefCount(valueObj);

    return TCL_OK;
}
