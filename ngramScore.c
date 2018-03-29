/*
 * ngramScore.c --
 *
 *	This file implements the generic n-gram scoring methods.
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
#include <wordtree.h>

static int CreateNgram _ANSI_ARGS_((Tcl_Interp *, ScoreItem *, int, const char **));
static int AddNgram _ANSI_ARGS_((Tcl_Interp *, ScoreItem *, unsigned char *, double));
void DeleteNgramScore _ANSI_ARGS_((ClientData));
static int NormalizeNgramLog _ANSI_ARGS_((Tcl_Interp *, ScoreItem *));
static double NgramValue _ANSI_ARGS_((Tcl_Interp *, ScoreItem *, const char *));
static double NgramElementValue _ANSI_ARGS_((Tcl_Interp *, ScoreItem *, const char *));
double  NgramStringValue _ANSI_ARGS_((const char *, double **));
double  NgramSingleValue _ANSI_ARGS_((unsigned char, unsigned char, double **));
static void NormalizeTreeNodeLog _ANSI_ARGS_((TreeNode *));
static int DumpNgramScore _ANSI_ARGS_((Tcl_Interp *, ScoreItem *, const char *));

typedef struct NgramItem {
    ScoreItem header;

    TreeNode *rootNode;
} NgramItem;

ScoreType NgramLogType = {
    "ngramlog",
    sizeof(NgramItem),
    CreateNgram,
    AddNgram,
    NgramValue,
    NgramElementValue,
    NormalizeNgramLog,
    DeleteNgramScore,
    DumpNgramScore,
    ScoreMethodCmd,
    (ScoreType *)NULL
};

ScoreType NgramCountType = {
    "ngramcount",
    sizeof(NgramItem),
    CreateNgram,
    AddNgram,
    NgramValue,
    NgramElementValue,
    NullScoreNormalizer,
    DeleteNgramScore,
    DumpNgramScore,
    ScoreMethodCmd,
    (ScoreType *)NULL
};

static int
CreateNgram(Tcl_Interp *interp, ScoreItem *itemPtr, int argc, const char **argv) {
    NgramItem *ngPtr = (NgramItem *)itemPtr;
    char temp_ptr[TCL_DOUBLE_SPACE];
    Tcl_DString dsPtr;
    int i;

    ngPtr->header.elemSize = -1;
    ngPtr->rootNode = createWordTreeRoot();
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
DeleteNgramScore(ClientData clientData) {
    NgramItem *ngPtr = (NgramItem *)clientData;

    deleteWordTree(ngPtr->rootNode);
//    ckfree((char *)(ngPtr->rootNode));

    DeleteScore(clientData);
}

static int
AddNgram(Tcl_Interp *interp, ScoreItem *itemPtr, unsigned char *element, double value)  {
    NgramItem *ngPtr = (NgramItem *)itemPtr;

    addWordToTree(ngPtr->rootNode, (char *)element, (unsigned short int) value);

    Tcl_SetResult(interp, (char *)element, TCL_VOLATILE);
    return TCL_OK;
}

static double
NgramValue(Tcl_Interp *interp, ScoreItem *itemPtr, const char *string) {
    NgramItem *ngPtr = (NgramItem *)itemPtr;
    int wordLen;
    unsigned short int value = 0;
    double totalVal = 0;
    int i;

    wordLen = strlen(string);
    for (i=0; i <= wordLen-itemPtr->elemSize; i++) {
	if (treeMatchString(ngPtr->rootNode, string+i, &value)) {
	    totalVal += (double) value;
	}
    }

    return totalVal;
}

static double
NgramElementValue(Tcl_Interp *interp, ScoreItem *itemPtr, const char *string) {
    NgramItem *ngPtr = (NgramItem *)itemPtr;
    unsigned short int value=0;

    if (! treeContainsWord(ngPtr->rootNode, string, &value, strlen(string))) {
	return 0.0;
    }

    return (double) value;
}

static int
NormalizeNgramLog(Tcl_Interp *interp, ScoreItem *itemPtr) {
    NgramItem *ngPtr = (NgramItem *)itemPtr;

    NormalizeTreeNodeLog(ngPtr->rootNode);

    Tcl_ResetResult(interp);
    return TCL_OK;
}

static void
NormalizeTreeNodeLog(TreeNode *rootNode) {
    int count = 0;

    if (rootNode == NULL) {
	return;
    }

    if (rootNode->measure > 0) {
	rootNode->measure = (unsigned short int) (log((double) (rootNode->measure)) * 1000.0);
    }

    for (count=0; rootNode->next && rootNode->next[count]; count++) {
	NormalizeTreeNodeLog(rootNode->next[count]);
    }
}

static int
DumpNgramScore(Tcl_Interp *interp, ScoreItem *itemPtr, const char *script) {
    NgramItem *ngPtr = (NgramItem *)itemPtr;
    Tcl_DString element;
    Tcl_DString command;

    Tcl_DStringInit(&element);
    Tcl_DStringInit(&command);
    Tcl_DStringAppend(&command, script, strlen(script));

    Tcl_ResetResult(interp);
    DumpTreeNode(interp, ngPtr->rootNode, &command, &element, 0);

    return TCL_OK;
}
