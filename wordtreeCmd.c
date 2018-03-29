/*
 * wordtreeCmd.c --
 *
 *	This file implements a Tcl interface to the wordtree data structure.
 *
 * Copyright (c) 2003 Michael Thomas <wart@kobold.org>
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
#include <wordtree.h>
#include <cipherDebug.h>

static Tcl_Obj *findBestSplit _ANSI_ARGS_((Tcl_Interp *, TreeNode *root, const char *, int *, Tcl_Obj **, int *));

int
WordtreeCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    const char *cmd;
    const char *option;
    TreeNode **rootNodePtr = (TreeNode **)clientData;
    TreeNode *rootNode = *rootNodePtr;

    if (argc < 2) {
	Tcl_AppendResult(interp, "Usage:  ", *argv, " option string", (char *)NULL);
	return TCL_ERROR;
    }

    cmd = *argv;
    argv++, argc--;
    option = *argv;
    argv++, argc--;

    if (*option == 'a' && (strncmp(option, "add", 3) == 0)) {
	if (argc != 1) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " ", option,
		    " word", (char *)NULL);
	    return TCL_ERROR;
	}
	// Add word to tree
#ifdef USE_DMALLOC
    if (dmalloc_verify(NULL) == DMALLOC_VERIFY_ERROR) {
	abort();
    }
#endif
	addWordToTree(rootNode, argv[0], (unsigned short int) 1);
#ifdef USE_DMALLOC
    if (dmalloc_verify(NULL) == DMALLOC_VERIFY_ERROR) {
	abort();
    }
#endif
	Tcl_SetResult(interp, argv[0], TCL_VOLATILE);
	return TCL_OK;
    } else if (*option == 'i' && (strncmp(option, "isvalid", 7) == 0)) {
	char length[TCL_DOUBLE_SPACE];
	int foundMatch;
	unsigned short int value = 0;
	if (argc != 1) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " ", option,
		    " word", (char *)NULL);
	    return TCL_ERROR;
	}
#ifdef USE_DMALLOC
    if (dmalloc_verify(NULL) == DMALLOC_VERIFY_ERROR) {
	abort();
    }
#endif
        foundMatch = treeContainsWord(rootNode, argv[0], &value, strlen(argv[0]));
	sprintf(length, "%d", foundMatch);
        if (foundMatch == 1) {
	    Tcl_SetResult(interp, "1", TCL_STATIC);
	    /*
	    Tcl_AppendResult(interp, "1 (", length, ")", (char *)NULL);
	    */
	} else {
	    Tcl_SetResult(interp, "0", TCL_STATIC);
	    /*
	    Tcl_AppendResult(interp, "0 (", length, ")", (char *)NULL);
	    */
	}
#ifdef USE_DMALLOC
    if (dmalloc_verify(NULL) == DMALLOC_VERIFY_ERROR) {
	abort();
    }
#endif
	return TCL_OK;
    } else if (*option == 'l' && (strncmp(option, "longest", 7) == 0)) {
	char length[TCL_DOUBLE_SPACE];
	int longestMatch;
	unsigned short int value = 0;

	if (argc != 1) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " ", option,
		    " string", (char *)NULL);
	    return TCL_ERROR;
	}

	longestMatch = treeMatchString(rootNode, argv[0], &value);
	/*
	 * If the first letter of the word can't even be found, then we
	 * get back a -1.  The user should see that the longest match was
	 * zero, though.
	 */
	sprintf(length, "%d", longestMatch);

	Tcl_SetResult(interp, length, TCL_VOLATILE);
	return TCL_OK;
    } else if (*option == 's' && (strncmp(option, "splitbest", 9) == 0)) {
        Tcl_Obj **bestTextAtPosition = (Tcl_Obj **)NULL;
        int *bestValueAtPosition = (int *)NULL;
        Tcl_Obj *bestResult = (Tcl_Obj *)NULL;
        int i;

	if (argc != 1) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " ", option,
		    " string", (char *)NULL);
	    return TCL_ERROR;
	}

        bestTextAtPosition = (Tcl_Obj **)ckalloc(sizeof(Tcl_Obj *) * (strlen(argv[0])+1));
        bestValueAtPosition = (int *)ckalloc(sizeof(int) * (strlen(argv[0])+1));
        for (i=0; i <= strlen(argv[0]); i++) {
            bestTextAtPosition[i] = Tcl_NewListObj(0, (Tcl_Obj **)NULL);
            bestValueAtPosition[i] = -1;
        }
        
        bestResult = findBestSplit(interp, rootNode, argv[0], (int *)NULL, bestTextAtPosition, bestValueAtPosition);

        if (bestResult == (Tcl_Obj *)NULL) {
            return TCL_ERROR;
        }
        Tcl_SetObjResult(interp, bestResult);

        for (i=0; i < strlen(argv[0]); i++) {
            if (bestValueAtPosition) {
                Tcl_DecrRefCount(bestTextAtPosition[i]);
            }
        }
        ckfree((char *)bestValueAtPosition);
        ckfree((char *)bestTextAtPosition);

        return TCL_OK;
    } else if (*option == 's' && (strncmp(option, "split", 5) == 0)) {
	int inputLength = 0;
	int startPos = 0;
	int curWordLength = 0;
	unsigned short int value = 0;
	Tcl_Obj *resultList = (Tcl_Obj *)NULL;
	Tcl_Obj *currentWord = (Tcl_Obj *)NULL;

	if (argc != 1) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " ", option,
		    " string", (char *)NULL);
	    return TCL_ERROR;
	}
	inputLength = strlen(argv[0]);
	resultList = Tcl_NewListObj(0, NULL);

	while (startPos < inputLength) {
	    curWordLength = treeMatchString(rootNode, argv[0]+startPos, &value);
	    if (curWordLength < 1) {
		curWordLength = 1;
	    }
	    currentWord = Tcl_NewStringObj(argv[0]+startPos, curWordLength);
	    if (Tcl_ListObjAppendElement(interp, resultList, currentWord) != TCL_OK) {
		return TCL_ERROR;
	    }

	    startPos += curWordLength;
	}

	Tcl_SetObjResult(interp, resultList);
	return TCL_OK;
    } else if (*option == 'i' && (strncmp(option, "isempty", 7) == 0)) {
	Tcl_SetObjResult(interp, Tcl_NewBooleanObj(isEmptyTree(rootNode)));
	return TCL_OK;
    } else if (*option == 'd' && (strncmp(option, "delete", 6) == 0)) {
#ifdef USE_DMALLOC
    if (dmalloc_verify(NULL) == DMALLOC_VERIFY_ERROR) {
	abort();
    }
#endif
	deleteWordTree(rootNode);
	*rootNodePtr = createWordTreeRoot();
#ifdef USE_DMALLOC
    if (dmalloc_verify(NULL) == DMALLOC_VERIFY_ERROR) {
	abort();
    }
#endif
	Tcl_SetResult(interp, "", TCL_STATIC);
	return TCL_OK;
    } else {
	Tcl_SetResult(interp, "Usage:  wordtree add|delete|isvalid|longest|splitbest|split", TCL_STATIC);
	return TCL_ERROR;
    }
}

void WordtreeDelete(ClientData clientData) {
    TreeNode **root = (TreeNode **)clientData;

    if (*root != NULL) {
	deleteWordTree(*root);
    }
}

static Tcl_Obj *findBestSplit(Tcl_Interp *interp, TreeNode *rootNode, const char *text, int *value, Tcl_Obj **bestTextAtPosition, int *bestValueAtPosition) {
    int textLength;
    int testLength;
    int bestValue = -1;
    int longestMatch = 0;
    unsigned short int localWordValue = 0;
    Tcl_Obj *localBestMatch = (Tcl_Obj *)NULL;
    
    textLength = strlen(text);

    if (bestValueAtPosition[textLength] > -1) {
        if (value) {
            *value = bestValueAtPosition[textLength];
        }
        return bestTextAtPosition[textLength];
    }

    if (textLength == 0) {
        *value = 0;
        return (Tcl_Obj *)NULL;
    }

    longestMatch = treeMatchString(rootNode, text, &localWordValue);
    for (testLength=longestMatch; testLength > 0; testLength--) {
        int downstreamValue = 0;
        if (treeContainsWord(rootNode, text, &localWordValue, testLength)) {
            if (testLength > 2) {
                localWordValue = testLength * testLength;
            } else {
                localWordValue = 0;
            }
            localBestMatch = findBestSplit(interp, rootNode, text+testLength, &downstreamValue, bestTextAtPosition, bestValueAtPosition);
            if (downstreamValue + localWordValue > bestValue) {
                Tcl_Obj *wordObj = Tcl_NewStringObj(text, testLength);
                bestValue = downstreamValue + localWordValue;
                bestValueAtPosition[textLength] = bestValue;

                if (localBestMatch == (Tcl_Obj *)NULL) {
                    Tcl_ListObjAppendElement(interp, bestTextAtPosition[textLength], wordObj);
                } else {
                    int objc;
                    Tcl_Obj **objv;
                    Tcl_ListObjGetElements(interp, localBestMatch, &objc, &objv);
                    Tcl_SetListObj(bestTextAtPosition[textLength], objc, objv);

                    Tcl_ListObjReplace(interp, bestTextAtPosition[textLength], 0, 0, 1, &wordObj);
                }
            }
        }
    }

    if (value) {
        *value = bestValue;
    }

    return bestTextAtPosition[textLength];
}
