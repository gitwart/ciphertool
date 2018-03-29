/*
 * digramScore.c --
 *
 *	This file implements the digram scoring methods.
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

static int CreateDigram _ANSI_ARGS_((Tcl_Interp *, ScoreItem *, int, const char **));
static int AddDigram _ANSI_ARGS_((Tcl_Interp *, ScoreItem *, unsigned char *, double));
static void DeleteDigram _ANSI_ARGS_((ClientData));
static int NormalizeDigramLog _ANSI_ARGS_((Tcl_Interp *, ScoreItem *));
static double DigramValue _ANSI_ARGS_((Tcl_Interp *, ScoreItem *, const char *));
static double DigramElementValue _ANSI_ARGS_((Tcl_Interp *, ScoreItem *, const char *));
static int DumpDigram _ANSI_ARGS_((Tcl_Interp *, ScoreItem *, const char *));

typedef struct DigramItem {
    ScoreItem header;

    double **value;
} DigramItem;

ScoreType DigramLogType = {
    "digramlog",
    sizeof(DigramItem),
    CreateDigram,
    AddDigram,
    DigramValue,
    DigramElementValue,
    NormalizeDigramLog,
    DeleteDigram,
    DumpDigram,
    ScoreMethodCmd,
    (ScoreType *)NULL
};

ScoreType DigramCountType = {
    "digramcount",
    sizeof(DigramItem),
    CreateDigram,
    AddDigram,
    DigramValue,
    DigramElementValue,
    NullScoreNormalizer,
    DeleteDigram,
    DumpDigram,
    ScoreMethodCmd,
    (ScoreType *)NULL
};

static int
CreateDigram(Tcl_Interp *interp, ScoreItem *itemPtr, int argc, const char **argv) {
    DigramItem *dlPtr = (DigramItem *)itemPtr;
    char temp_ptr[TCL_DOUBLE_SPACE];
    Tcl_DString dsPtr;
    int i, j;

    dlPtr->header.elemSize = 2;
    dlPtr->value = (double **)ckalloc(sizeof(double *) * 256);
    for (i=0; i < 256; i++) {
	dlPtr->value[i] = (double *)ckalloc(sizeof(double) * 256);
	for (j=0; j < 256; j++) {
	    dlPtr->value[i][j] = 0;
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

static void
DeleteDigram(ClientData clientData) {
    DigramItem *dlPtr = (DigramItem *)clientData;
    int i;

    if (dlPtr->value != NULL) {
	for(i=0; i < 256; i++) {
	    if (dlPtr->value[i] != NULL) {
		ckfree((char *)dlPtr->value[i]);
	    }
	}
	ckfree((char *)dlPtr->value);
    }
    dlPtr->value = (double **)NULL;

    DeleteScore(clientData);
}

static int
AddDigram(Tcl_Interp *interp, ScoreItem *itemPtr, unsigned char *element, double value)  {
    DigramItem *dlPtr = (DigramItem *)itemPtr;

    dlPtr->value[element[0]][element[1]] += value;

    Tcl_SetResult(interp, element, TCL_VOLATILE);
    return TCL_OK;
}

static double
DigramValue(Tcl_Interp *interp, ScoreItem *itemPtr, const char *string) {
    DigramItem *dlPtr = (DigramItem *)itemPtr;

    return DigramStringValue(string, (double **)dlPtr->value);
}

static double
DigramElementValue(Tcl_Interp *interp, ScoreItem *itemPtr, const char *string) {
    DigramItem *dlPtr = (DigramItem *)itemPtr;

    return DigramSingleValue((unsigned char)string[0], (unsigned char)string[1], dlPtr->value);
}

static int
NormalizeDigramLog(Tcl_Interp *interp, ScoreItem *itemPtr) {
    DigramItem *dlPtr = (DigramItem *)itemPtr;
    int i, j;

    for(i=0; i < 256; i++) {
	for (j=0; j < 256; j++) {
	    if (dlPtr->value[i][j] > 0.0) {
		dlPtr->value[i][j] = log(dlPtr->value[i][j]);
	    } else {
		dlPtr->value[i][j] = 0.0;
	    }
	}
    }

    Tcl_ResetResult(interp);
    return TCL_OK;
}

static int
DumpDigram(Tcl_Interp *interp, ScoreItem *itemPtr, const char *script) {
    DigramItem *dlPtr = (DigramItem *)itemPtr;
    Tcl_DString dsPtr;
    int i, j;
    int length;
    char element[3];
    Tcl_Obj *valueObj = Tcl_NewDoubleObj(0.0);

    element[2] = '\0';

    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppend(&dsPtr, script, strlen(script));
    length = Tcl_DStringLength(&dsPtr);

    for (i=1; i < 256; i++) {
	for (j=1; j < 256; j++) {
	    if (DigramSingleValue(i, j, dlPtr->value) > 0.0) {
		element[0] = i;
		element[1] = j;

		Tcl_DStringSetLength(&dsPtr, length);
		Tcl_DStringStartSublist(&dsPtr);
		Tcl_DStringAppendElement(&dsPtr, (const char *)element);
		Tcl_SetDoubleObj(valueObj, DigramSingleValue(i, j, dlPtr->value));
		Tcl_DStringAppendElement(&dsPtr, Tcl_GetString(valueObj));
		Tcl_DStringEndSublist(&dsPtr);

		if (Tcl_EvalEx(interp, Tcl_DStringValue(&dsPtr), Tcl_DStringLength(&dsPtr), 0) != TCL_OK) {
		    return TCL_ERROR;
		}
	    }
	}
    }

    Tcl_DecrRefCount(valueObj);

    return TCL_OK;
}
