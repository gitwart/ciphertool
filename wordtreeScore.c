/*
 * wordtreeScore.c --
 *
 *	This file implements the word length scoring method.
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
#include <string.h>
#include <score.h>
#include <wordtree.h>

static int CreateWordtree _ANSI_ARGS_((Tcl_Interp *, ScoreItem *, int, char **));
static int AddWordtreeWord _ANSI_ARGS_((Tcl_Interp *, ScoreItem *, unsigned char *, double));
void DeleteWordtreeScore _ANSI_ARGS_((ClientData));
static double WordtreeValue _ANSI_ARGS_((Tcl_Interp *, ScoreItem *, unsigned char *));
static double WordtreeElementValue _ANSI_ARGS_((Tcl_Interp *, ScoreItem *, unsigned char *));
static int NormalizeWordtreeScore _ANSI_ARGS_((Tcl_Interp *, ScoreItem *));
static int DumpWordtreeScore _ANSI_ARGS_((Tcl_Interp *, ScoreItem *, char *));
static void NormalizeTreeNodeSquare _ANSI_ARGS_((TreeNode *, int));
double  WordtreeStringValue _ANSI_ARGS_((unsigned char *, double **));
double  WordtreeSingleValue _ANSI_ARGS_((unsigned char, unsigned char, double **));

typedef struct WordtreeItem {
    ScoreItem header;

    TreeNode *rootNode;
} WordtreeItem;

ScoreType WordtreeType = {
    "wordtree",
    sizeof(WordtreeItem),
    CreateWordtree,
    AddWordtreeWord,
    WordtreeValue,
    WordtreeElementValue,
    NormalizeWordtreeScore,
    DeleteWordtreeScore,
    DumpWordtreeScore,
    ScoreMethodCmd,
    (ScoreType *)NULL
};

static int
CreateWordtree(Tcl_Interp *interp, ScoreItem *itemPtr, int argc, char **argv) {
    WordtreeItem *wtPtr = (WordtreeItem *)itemPtr;
    char temp_ptr[TCL_DOUBLE_SPACE];
    Tcl_DString dsPtr;
    int i;

    wtPtr->header.elemSize = 0;
    wtPtr->rootNode = createWordTreeRoot();
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
DeleteWordtreeScore(ClientData clientData) {
    WordtreeItem *wtPtr = (WordtreeItem *)clientData;

    deleteWordTree(wtPtr->rootNode);
//    ckfree((char *)(wtPtr->rootNode));

    DeleteScore(clientData);
}

static int
AddWordtreeWord(Tcl_Interp *interp, ScoreItem *itemPtr, unsigned char *element, double value)  {
    WordtreeItem *wtPtr = (WordtreeItem *)itemPtr;

    addWordToTree(wtPtr->rootNode, element, (unsigned short int) value);

    Tcl_SetResult(interp, element, TCL_VOLATILE);
    return TCL_OK;
}

static double
WordtreeValue(Tcl_Interp *interp, ScoreItem *itemPtr, unsigned char *string) {
    WordtreeItem *wtPtr = (WordtreeItem *)itemPtr;
    int wordLen;
    int wVal;
    int startPos = 0;
    double totalVal = 0.0;
    unsigned short int value = 0;

    wordLen = strlen(string);
    while (startPos < wordLen) {
	wVal = treeMatchString(wtPtr->rootNode, string+startPos, &value);
	totalVal += value;
	if (wVal > 2) {
	    startPos += wVal;
	} else {
	    startPos++;
	}
    }

    return totalVal;
}

static double
WordtreeElementValue(Tcl_Interp *interp, ScoreItem *itemPtr, unsigned char *string) {
    WordtreeItem *wtPtr = (WordtreeItem *)itemPtr;
    unsigned short int value = 0;

    if (treeContainsWord(wtPtr->rootNode, string, &value, strlen(string))) {
	return (double) value;
    }

    return 0.0;
}

static int
DumpWordtreeScore(Tcl_Interp *interp, ScoreItem *itemPtr, char *script) {
    WordtreeItem *wtPtr = (WordtreeItem *)itemPtr;
    Tcl_DString element;
    Tcl_DString command;

    Tcl_DStringInit(&element);
    Tcl_DStringInit(&command);
    Tcl_DStringAppend(&command, script, strlen(script));

    Tcl_ResetResult(interp);
    DumpTreeNode(interp, wtPtr->rootNode, &command, &element, 0);

    return TCL_OK;
}

static int
NormalizeWordtreeScore(Tcl_Interp *interp, ScoreItem *itemPtr) {
    WordtreeItem *wtPtr = (WordtreeItem *)itemPtr;

    NormalizeTreeNodeSquare(wtPtr->rootNode, 0);

    Tcl_ResetResult(interp);
    return TCL_OK;
}

static void
NormalizeTreeNodeSquare(TreeNode *rootNode, int index) {
    int count = 0;

    if (rootNode == NULL) {
	return;
    }

    if (index > 1) {
	rootNode->measure = (unsigned short int) index * index;
    } else {
	rootNode->measure = 0;
    }

    for (count=0; rootNode->next && rootNode->next[count]; count++) {
	NormalizeTreeNodeSquare(rootNode->next[count], index+1);
    }
}
