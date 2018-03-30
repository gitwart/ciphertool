/*
 * score.c --
 *
 *	This file initializes the cipher scoring functionality as
 *	a Tcl procedure.
 *
 * Copyright (c) 2004-2008 Michael Thomas <wart@kobold.org>
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
#include <scoreInt.h>
#include <string.h>

#include <cipherDebug.h>

static int IsInternalScore _ANSI_ARGS_((ScoreItem *));

ScoreItem *initialScoreItem = (ScoreItem *)NULL;
ScoreItem *defaultScoreItem = (ScoreItem *)NULL;
Tcl_Obj *defaultScoreCommand = (Tcl_Obj *)NULL;
static ScoreItem **newScores = (ScoreItem **)NULL;
static ScoreType *typeList = (ScoreType *)NULL;
extern ScoreType DigramLogType;
extern ScoreType DigramCountType;
extern ScoreType TrigramLogType;
extern ScoreType TrigramCountType;
extern ScoreType NgramLogType;
extern ScoreType NgramCountType;
extern ScoreType WordtreeType;

int
InitScoreTypes(Tcl_Interp *interp)
{
    int i, j;

    if (typeList == NULL) {
	typeList = &DigramLogType;
	DigramLogType.nextPtr = &DigramCountType;
	DigramCountType.nextPtr = &TrigramLogType;
	TrigramLogType.nextPtr = &TrigramCountType;
	TrigramCountType.nextPtr = &NgramLogType;
	NgramLogType.nextPtr = &NgramCountType;
	NgramCountType.nextPtr = &WordtreeType;
	WordtreeType.nextPtr = NULL;
    }

    /*
     * Create an instance of the first type in the list to be the default
     * scoring method.
     */

    initialScoreItem = (ScoreItem *)ckalloc((unsigned)typeList->size);
    initialScoreItem->typePtr = typeList;
    initialScoreItem->elemSize = -1;
    initialScoreItem->initialized = 1;
    if ((*typeList->createProc)(interp, initialScoreItem, 0, (const char **)NULL)
	    != TCL_OK) {
	/*
	 * If the create procedure failed then we should assume that it
	 * has also performed any necessary cleanup by calling the
	 * DeleteCommand procedure for the new object.  No need to free
	 * up the memory for the itemPtr since it should have already
	 * been cleaned up.
	 */
	return TCL_ERROR;
    }
    scoreid = 0;

    /*
     * Initialize the default scoring method.  The "defaultScoreData" must
     * match the type that is the first in the type list.
     */

    for(i =0 ; i < 256; i++) {
	char temp_str[3];
	for(j=0; j < 256; j++) {
	    temp_str[0] = i;
	    temp_str[1] = j;
	    temp_str[2] = '\0';
	    (typeList->addProc)(interp, initialScoreItem, temp_str, defaultScoreData[i][j]);
	}
    }

    AddInternalScore(initialScoreItem);

    /*
     * There must be a way to get the default score command from the
     * item itself.
     */
    defaultScoreCommand = Tcl_NewStringObj("score0", 6);
    defaultScoreItem = initialScoreItem;

    return TCL_OK;
}

void
CreateScoreType(ScoreType *typePtr)
{
    ScoreType *typePtr2;
    ScoreType *prevPtr;

    for (typePtr2 = typeList, prevPtr=(ScoreType *)NULL;
	    typePtr2 != (ScoreType *)NULL;
	    prevPtr = typePtr2, typePtr2 = typePtr2->nextPtr) {

	if (strcmp(typePtr2->type, typePtr->type) == 0) {
	    if (prevPtr == (ScoreType *)NULL) {
		typeList = typePtr2->nextPtr;
	    } else {
		prevPtr->nextPtr = typePtr2->nextPtr;
	    }
	    break;
	}
    }

    typePtr->nextPtr = typeList;
    typeList = typePtr;
}

void
DeleteScoreCommand(ClientData clientData) {
    /*
     * Don't delete the initial score item because it is associated
     * with another command that either has already been deleted or
     * will be deleted later.
    (initialScoreItem->typePtr->deleteProc)(initialScoreItem);
    */

    if (newScores) {
	ckfree((char *)newScores);
    }
}

int
ScoreCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    ScoreType *typePtr, *matchPtr = NULL;
    ScoreItem *itemPtr;
    char temp_str[128];
    const char *cmd = argv[0];

    if (argc < 2) {
	Tcl_AppendResult(interp, "Usage:  ", cmd, " ?option? ?args?",
		(char *)NULL);
	return TCL_ERROR;
    }


    argc--, argv++;

    if (**argv == 'v' && (strncmp(*argv, "value", 2) == 0)) {
	double weight = 1.0;
	double value = 0.0;

	if (argc < 2 || argc > 3) {
	    Tcl_AppendResult(interp, "usage:  ", cmd, " value string ?weight?",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	if (DefaultScoreValue(interp, argv[1], &value) != TCL_OK) {
	    return TCL_ERROR;
	}

	if (argc == 3) {
	    if (Tcl_GetDouble(interp, argv[2], &weight) != TCL_OK) {
		return TCL_ERROR;
	    }

	    value *= weight;
	}

	Tcl_SetObjResult(interp, Tcl_NewDoubleObj(value));
	return TCL_OK;
    } else if (**argv == 'e' && (strncmp(*argv, "elemvalue", 2) == 0)) {
	double weight = 1.0;
	double value;

	if (argc < 2 || argc > 3) {
	    Tcl_AppendResult(interp, "usage:  ", cmd,
		    " elemvalue element ?weight?", (char *)NULL);
	    return TCL_ERROR;
	}

	if (defaultScoreItem && strlen(argv[1]) != defaultScoreItem->elemSize) {
	    sprintf(temp_str, "%ld != %d", strlen(argv[1]), defaultScoreItem->elemSize);
	    Tcl_AppendResult(interp, "Element size incorrect.  ", temp_str,
		    (char *)NULL);
	    return TCL_ERROR;
	}

	if (DefaultScoreElementValue(interp, argv[1], &value) != TCL_OK) {
	    return TCL_ERROR;
	}

	if (argc == 3) {
	    if (Tcl_GetDouble(interp, argv[2], &weight) != TCL_OK) {
		return TCL_ERROR;
	    }

	    value *= weight;
	}

	Tcl_SetObjResult(interp, Tcl_NewDoubleObj(value));
	return TCL_OK;
    } else if (**argv == 'c' && (strncmp(*argv, "create", 1) == 0)) {
	if (argc < 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " create type",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	for(typePtr = typeList; typePtr != NULL; typePtr = typePtr->nextPtr) {
	    if (strcmp(argv[1], typePtr->type) == 0) {
		matchPtr = typePtr;
	    }
	}

	if (matchPtr == NULL) {
	    Tcl_AppendResult(interp, "unknown scoring type ",
		    argv[1], (char *)NULL);
	    return TCL_ERROR;
	}

	typePtr = matchPtr;
	itemPtr = (ScoreItem *)ckalloc((unsigned)typePtr->size);
	itemPtr->typePtr = typePtr;
	scoreid++;
	itemPtr->elemSize = 0;
	itemPtr->initialized = 0;
	if ((*typePtr->createProc)(interp, itemPtr, argc-2, argv+2) != TCL_OK) {
	    /*
	     * If the create procedure failed then we should assume that it
	     * has also performed any necessary cleanup by calling the
	     * DeleteCommand procedure for the new object.  No need to free
	     * up the memory for the itemPtr since it should have already
	     * been cleaned up.
	     */
	    return TCL_ERROR;
	}

	AddInternalScore(itemPtr);

	return TCL_OK;
    } else if (**argv == 'd' && (strncmp(*argv, "default", 1) == 0)) {
	Tcl_CmdInfo cmdInfo;
	if (argc > 2) {
	    Tcl_AppendResult(interp,
		    "Wrong number of args.  Should be:  ", cmd,
		    " default ?command?", (char *)NULL);
	    return TCL_ERROR;
	}

	if (argc == 1) {
	    if (defaultScoreCommand == NULL) {
		Tcl_ResetResult(interp);
	    } else {
		Tcl_SetResult(interp, Tcl_GetString(defaultScoreCommand), TCL_VOLATILE);
	    }

	    return TCL_OK;
	}

	if (Tcl_GetCommandInfo(interp, argv[1], &cmdInfo) != 1) {
	    Tcl_AppendResult(interp, "Command '", argv[1], "' not found.",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	if (IsInternalScore(cmdInfo.clientData)) {
	    defaultScoreItem = (ScoreItem *)(cmdInfo.clientData);
	    defaultScoreCommand = Tcl_NewStringObj(argv[1], strlen(argv[1]));
	} else {
	    defaultScoreItem = (ScoreItem *)NULL;
	    defaultScoreCommand = Tcl_NewStringObj(argv[1], strlen(argv[1]));
	}

	Tcl_SetObjResult(interp, Tcl_NewStringObj(argv[1], -1));
	return TCL_OK;
    } else if (**argv == 'i' && (strncmp(*argv, "isinternal", 10) == 0)) {
	Tcl_CmdInfo cmdInfo;

	if (argc != 2) {
	    Tcl_AppendResult(interp,
		    "Wrong number of args.  Should be:  ", cmd,
		    " isinternal command", (char *)NULL);
	    return TCL_ERROR;
	}

	if (Tcl_GetCommandInfo(interp, argv[1], &cmdInfo) != 1) {
	    Tcl_AppendResult(interp, "Command '", argv[1], "' not found.",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	Tcl_SetObjResult(interp, Tcl_NewIntObj(IsInternalScore(cmdInfo.clientData)));
	return TCL_OK;
    } else if (**argv == 't' && (strncmp(*argv, "types", 5) == 0)) {
	if (argc > 1) {
	    Tcl_AppendResult(interp,
		    "Wrong number of args.  Should be:  ", cmd, " types",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	for(typePtr = typeList; typePtr; typePtr = typePtr->nextPtr) {
	    Tcl_AppendElement(interp, typePtr->type);
	}

	return TCL_OK;
    } else if (**argv == 't' && (strncmp(*argv, "type", 4) == 0)) {
	if (argc > 1) {
	    Tcl_AppendResult(interp,
		    "Wrong number of args.  Should be:  ", cmd, " type",
		    (char *)NULL);
	    return TCL_ERROR;
	}

        Tcl_SetResult(interp, defaultScoreItem->typePtr->type, TCL_VOLATILE);

	return TCL_OK;
    } else {
	Tcl_AppendResult(interp, "Usage:  ", cmd, " ?option? ?args?",
		(char *)NULL);
	return TCL_ERROR;
    }

    return TCL_ERROR;
}

void
DeleteScore(ClientData clientData)
{
    ScoreItem *itemPtr = (ScoreItem *)clientData;
    int i;

    for (i=0; i <= scoreid; i++) {
	if (newScores[i] == itemPtr) {
	    newScores[i] = (ScoreItem *)NULL;
	}
    }

    if (defaultScoreItem == itemPtr) {
	defaultScoreItem = (ScoreItem *)NULL;
	defaultScoreCommand = (Tcl_Obj *)NULL;
    }

    ckfree((char *) clientData);
}

static int
IsInternalScore(ScoreItem *itemPtr)
{
    int i;

    if (newScores == NULL) {
	return 0;
    }

    for (i=0; i <= scoreid; i++) {
	if (newScores[i] == itemPtr) {
	    return 1;
	}
    }

    return 0;
}

void
AddInternalScore(ScoreItem *itemPtr) {
    ScoreItem **scoreList = (ScoreItem **)ckalloc(sizeof(ScoreItem *) * (scoreid + 2));
    int i;

    for (i=0; newScores && i < scoreid; i++) {
	scoreList[i] = newScores[i];
    }
    scoreList[i] = itemPtr;
    scoreList[i+1] = (ScoreItem *)NULL;
    if (newScores != NULL) {
	ckfree((char *)newScores);
    }
    newScores = scoreList;
}

double
DigramStringValue(const char *string, double **table) {
    int length = strlen(string);
    double value = 0.0;
    int i;

    for (i=1; i < length; i++) {
	value += DigramSingleValue(string[i-1], string[i], table);
    }
    
    return value;
}

/*
 * This has been replaced by a macro.  See score.h for details.
 */
/*
double
DigramSingleValue(unsigned char val1, unsigned char val2, double **table) {
    return table[val1][val2];
}
*/

int
DefaultScoreValue(Tcl_Interp *interp, const char *string, double *value) {
    *value = 0.0;

    if (defaultScoreItem != NULL) {
	*value = (defaultScoreItem->typePtr->valueProc)(interp, defaultScoreItem, string);
	Tcl_SetObjResult(interp, Tcl_NewDoubleObj(*value));
    } else if (interp == NULL) {
	return TCL_ERROR;
    } else if (defaultScoreCommand != NULL) {
	int result;
	Tcl_Obj *objResult = (Tcl_Obj *)NULL;
	Tcl_DString dString;
	Tcl_DStringInit(&dString);
	Tcl_DStringAppendElement(&dString, Tcl_GetString(defaultScoreCommand));
	Tcl_DStringAppendElement(&dString, "value");
	Tcl_DStringAppendElement(&dString, string);

	result = Tcl_EvalEx(interp, Tcl_DStringValue(&dString),
		Tcl_DStringLength(&dString), 0);

	Tcl_DStringFree(&dString);

	if (result != TCL_OK) {
	    return TCL_ERROR;
	}

	objResult = Tcl_GetObjResult(interp);
	if (Tcl_GetDoubleFromObj(interp, objResult, value) != TCL_OK) {
	    return TCL_OK;
	}

	return result;
    } else {
	Tcl_SetResult(interp, "Default score command not found.", TCL_STATIC);
	return TCL_ERROR;
    }

    return TCL_OK;
}

int
DefaultScoreElementValue(Tcl_Interp *interp, const char *element, double *value) {
    *value = 0.0;

    if (defaultScoreItem != NULL) {
	*value = (defaultScoreItem->typePtr->elemValueProc)(interp, defaultScoreItem, element);
	Tcl_SetObjResult(interp, Tcl_NewDoubleObj(*value));
    } else if (interp == NULL) {
	return TCL_ERROR;
    } else if (defaultScoreCommand != NULL) {
	int result;
	Tcl_Obj *objResult = (Tcl_Obj *)NULL;
	Tcl_DString dString;
	Tcl_DStringInit(&dString);
	Tcl_DStringAppendElement(&dString, Tcl_GetString(defaultScoreCommand));
	Tcl_DStringAppendElement(&dString, "elemvalue");
	Tcl_DStringAppendElement(&dString, element);

	result = Tcl_EvalEx(interp, Tcl_DStringValue(&dString),
		Tcl_DStringLength(&dString), 0);

	Tcl_DStringFree(&dString);

	if (result != TCL_OK) {
	    return TCL_ERROR;
	}

	objResult = Tcl_GetObjResult(interp);
	if (Tcl_GetDoubleFromObj(interp, objResult, value) != TCL_OK) {
	    return TCL_OK;
	}

	return result;
    } else {
	Tcl_SetResult(interp, "Default score command not found.", TCL_STATIC);
	return TCL_ERROR;
    }

    return TCL_OK;
}

int
NullScoreNormalizer(Tcl_Interp *interp, ScoreItem *itemPtr) {
    Tcl_ResetResult(interp);
    return TCL_OK;
}

int
DumpScoreTable(Tcl_Interp *interp, ScoreItem *itemPtr, char *script) {
    Tcl_SetResult(interp, "dump is not defined for this score type.", TCL_STATIC);
    return TCL_ERROR;
}

void
DumpTreeNode(Tcl_Interp *interp, TreeNode *rootNode, Tcl_DString *command, Tcl_DString *element, int index) {
    int count = 0;

    if (rootNode == NULL) {
	return;
    }

    for (count=0; rootNode->next && rootNode->next[count]; count++) {
	if (rootNode->next[count]->val == '\0' && rootNode->measure > 0) {
	    int length = Tcl_DStringLength(command);
	    int result = TCL_OK;
	    Tcl_Obj *valueObj = Tcl_NewDoubleObj(0);

	    Tcl_DStringStartSublist(command);
	    Tcl_DStringAppendElement(command, Tcl_DStringValue(element));
	    Tcl_SetDoubleObj(valueObj, (double)rootNode->measure);
	    Tcl_DStringAppendElement(command, Tcl_GetString(valueObj));
	    Tcl_DStringEndSublist(command);

	    result = Tcl_EvalEx(interp, Tcl_DStringValue(command), Tcl_DStringLength(command), 0);

	    Tcl_DecrRefCount(valueObj);
	    Tcl_DStringSetLength(command, length);
	} else {
	    Tcl_DStringAppend(element, &(rootNode->next[count]->val), 1);
	    DumpTreeNode(interp, rootNode->next[count], command, element,
		    index+1);
	    Tcl_DStringSetLength(element, index);
	}
    }
}

int
ScoreMethodCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv) {
    ScoreItem *itemPtr = (ScoreItem *)clientData;
    const char *cmd;
    char temp_str[TCL_DOUBLE_SPACE];

    cmd = *argv;
    argv++, argc--;

    if (argc == 0) {
	Tcl_AppendResult(interp, "Usage:  ", cmd, " ?option?", (char *)NULL);
	return TCL_ERROR;
    }

    if (**argv == 'v' && (strncmp(*argv, "value", 2) == 0)) {
	double weight = 1.0;
	double value = 0.0;

	if (argc < 2 || argc > 3) {
	    Tcl_AppendResult(interp, "usage:  ", cmd, " value string ?weight?",
		    (char *)NULL);
	    return TCL_ERROR;
	}

        if (! itemPtr->initialized) {
	    Tcl_SetResult(interp, 
                    "Attempt to use uninitialized scoring object.", 
                    TCL_STATIC);
	    return TCL_ERROR;
        }

	value = (itemPtr->typePtr->valueProc(interp, itemPtr, argv[1]));

	if (argc == 3) {
	    if (Tcl_GetDouble(interp, argv[2], &weight) != TCL_OK) {
		return TCL_ERROR;
	    }

	    value *= weight;
	}

	Tcl_SetObjResult(interp, Tcl_NewDoubleObj(value));
	return TCL_OK;
    } else if (**argv == 'e' && (strncmp(*argv, "elemvalue", 9) == 0)) {
	double weight = 1.0;
	double value;

	if (argc < 2 || argc > 3) {
	    Tcl_AppendResult(interp, "usage:  ", cmd,
		    " elemvalue element ?weight?", (char *)NULL);
	    return TCL_ERROR;
	}

        if (! itemPtr->initialized) {
	    Tcl_SetResult(interp, 
                    "Attempt to use uninitialized scoring object.", 
                    TCL_STATIC);
	    return TCL_ERROR;
        }

	if (itemPtr->elemSize > 0 && strlen(argv[1]) != itemPtr->elemSize) {
	    sprintf(temp_str, "%ld != %d", strlen(argv[1]), itemPtr->elemSize);
	    Tcl_AppendResult(interp, "Element size incorrect.  ", temp_str,
		    (char *)NULL);
	    return TCL_ERROR;
	}

	value = (itemPtr->typePtr->elemValueProc(interp, itemPtr, argv[1]));

	if (argc == 3) {
	    if (Tcl_GetDouble(interp, argv[2], &weight) != TCL_OK) {
		return TCL_ERROR;
	    }

	    value *= weight;
	}

	Tcl_SetObjResult(interp, Tcl_NewDoubleObj(value));
	return TCL_OK;
    } else if (**argv == 'a' && (strncmp(*argv, "add", 2) == 0)) {
	double value = 1.0;

	if (argc < 2 || argc > 3) {
	    Tcl_AppendResult(interp, "usage:  ", cmd, " add element ?value?",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	if (itemPtr->elemSize < 0) {
	    Tcl_SetResult(interp, "Can't add elements until the element size has been set.", TCL_STATIC);
	    return TCL_ERROR;
	}

	if (itemPtr->elemSize > 0 && strlen(argv[1]) != itemPtr->elemSize) {
	    sprintf(temp_str, "%ld != %d", strlen(argv[1]), itemPtr->elemSize);
	    Tcl_AppendResult(interp, "Element size incorrect.  ", temp_str,
		    (char *)NULL);
	    return TCL_ERROR;
	}

	if (argc == 3) {
	    if (Tcl_GetDouble(interp, argv[2], &value) != TCL_OK) {
		return TCL_ERROR;
	    }
	}
        /* The addition of at least one value to the scoring table
         * is enough to consider it initialized.
         */
        itemPtr->initialized = 1;

	return (itemPtr->typePtr->addProc(interp, itemPtr, argv[1], value));
    } else if (**argv == 'n' && (strncmp(*argv, "normalize", 9) == 0)) {
	return (itemPtr->typePtr->normalProc(interp, itemPtr));
    } else if (**argv == 'e' && (strncmp(*argv, "elemsize", 8) == 0)) {
	if (argc > 2) {
	    Tcl_AppendResult(interp, "usage:  ", cmd, " elemsize ?size?",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	if (argc == 2) {
	    if (itemPtr->elemSize < 0) {
		int newSize = 0;
		if (Tcl_GetInt(interp, argv[1], &newSize) != TCL_OK) {
		    return TCL_ERROR;
		}

		if (newSize < 0) {
		    Tcl_SetResult(interp, "Element size must be >= zero.",
			    TCL_STATIC);
		    return TCL_ERROR;
		}

		itemPtr->elemSize = newSize;
		Tcl_SetObjResult(interp, Tcl_NewStringObj(argv[1], -1));
		return TCL_OK;
	    } else {
		Tcl_SetResult(interp,
			"Can't change the element size once it has been set.",
			TCL_STATIC);
		return TCL_ERROR;
	    }
	} else {
	    Tcl_SetObjResult(interp, Tcl_NewIntObj(itemPtr->elemSize));
	}

	return TCL_OK;
    } else if (**argv == 'd' && (strncmp(*argv, "dump", 4) == 0)) {
	if (argc != 2) {
	    Tcl_AppendResult(interp, "usage:  ", cmd, " dump script",
		    (char *)NULL);
	    return TCL_ERROR;
	}
	return (itemPtr->typePtr->dumpProc(interp, itemPtr, argv[1]));
    } else if (**argv == 't' && (strncmp(*argv, "type", 4) == 0)) {
	Tcl_SetResult(interp, itemPtr->typePtr->type, TCL_STATIC);
	return TCL_OK;
    } else {
	Tcl_AppendResult(interp, "Unknown option ", *argv, (char *)NULL);
	Tcl_AppendResult(interp, "\nMust be one of:  ", cmd,
			" type", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" elemsize ?newsize?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" normalize", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" value string ?weight?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" elemvalue element ?weight?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" add element ?value?", (char *)NULL);

	return TCL_ERROR;
    }
}

