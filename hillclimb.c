/*
 * hillclimb.c --
 *
 *	This file implements some common hillclimb utility functions
 *
 * Copyright (c) 2008 Michael Thomas <wart@kobold.org>
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
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include "hillclimb.h"
#include "keygen.h"

int
HillclimbRandomizeListObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    Tcl_Obj *resultObj = (Tcl_Obj *)NULL;

    if (objc != 2) {
        Tcl_AppendResult(interp, "Usage:  ", Tcl_GetString(objv[0]), " list", (char *)NULL);
        return TCL_ERROR;
    }

    resultObj = HillclimbRandomizeList(interp, objv[1]);
    if (resultObj == NULL) {
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, resultObj);

    return TCL_OK;
}

int
HillclimbKeysquareSwapNeighborKeysObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    Tcl_Obj *resultObj = (Tcl_Obj *)NULL;

    if (objc != 2 && objc != 3) {
        Tcl_AppendResult(interp, "Usage:  ", Tcl_GetString(objv[0]), " fullKey ?fixedIndices?", (char *)NULL);
        return TCL_ERROR;
    }

    if (objc == 2 || (objc == 3 && Tcl_GetCharLength(objv[2]) == 0)) {
        resultObj = HillclimbKeysquareSwapNeighborKeys(interp, Tcl_GetString(objv[1]), (char *)NULL);
    } else {
        resultObj = HillclimbKeysquareSwapNeighborKeys(interp, Tcl_GetString(objv[1]), Tcl_GetString(objv[2]));
    }
    if (resultObj == NULL) {
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, resultObj);

    return TCL_OK;
}

int
HillclimbGenerateSwapNeighborKeysObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    Tcl_Obj *resultObj = (Tcl_Obj *)NULL;

    if (objc != 2 && objc != 3) {
        Tcl_AppendResult(interp, "Usage:  ", Tcl_GetString(objv[0]), " fullKey ?fixedIndices?", (char *)NULL);
        return TCL_ERROR;
    }

    if (objc == 2 || (objc == 3 && Tcl_GetCharLength(objv[2]) == 0)) {
        resultObj = HillclimbGenerateSwapNeighborKeys(interp, Tcl_GetString(objv[1]), (char *)NULL);
    } else {
        resultObj = HillclimbGenerateSwapNeighborKeys(interp, Tcl_GetString(objv[1]), Tcl_GetString(objv[2]));
    }
    if (resultObj == NULL) {
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, resultObj);

    return TCL_OK;
}

int
HillclimbAristocratSwapNeighborKeysObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    Tcl_Obj *resultObj = (Tcl_Obj *)NULL;
    Tcl_Obj *alphabetObj = (Tcl_Obj *)NULL;
    Tcl_Obj *replaceObj = (Tcl_Obj *)NULL;
    Tcl_Obj *tempObjList[2];
    Tcl_Obj *k2KeyObj = (Tcl_Obj *)NULL;
    char fullKey[27];
    int i;
    int resultLength;

    if (objc != 2 && objc != 3) {
        Tcl_AppendResult(interp, "Usage:  ", Tcl_GetString(objv[0]), " key ?fixedIndices?", (char *)NULL);
        return TCL_ERROR;
    }

    if (Tcl_ListObjIndex(interp, objv[1], 1, &k2KeyObj) != TCL_OK) {
        Tcl_SetResult(interp, "Could not find k2 component in aristocrat key", TCL_STATIC);
        return TCL_ERROR;
    }
    if (k2KeyObj == (Tcl_Obj *)NULL) {
        Tcl_SetResult(interp, "Could not find k2 component in aristocrat key", TCL_STATIC);
        return TCL_ERROR;
    }
    if (KeyGenerateK1(interp, Tcl_GetString(k2KeyObj), fullKey) != TCL_OK) {
        return TCL_ERROR;
    }

    if (objc == 2 || (objc == 3 && Tcl_GetCharLength(objv[2]) == 0)) {
        resultObj = HillclimbGenerateSwapNeighborKeys(interp, fullKey, (char *)NULL);
    } else {
        resultObj = HillclimbGenerateSwapNeighborKeys(interp, fullKey, Tcl_GetString(objv[2]));
    }
    
    if (resultObj == NULL) {
        return TCL_ERROR;
    }
    /*
     * Prepend the alphabet before each aristocrat key
     */
    alphabetObj = Tcl_NewStringObj("abcdefghijklmnopqrstuvwxyz", 26);
    Tcl_ListObjLength(interp, resultObj, &resultLength);
    tempObjList[0] = alphabetObj;
    for (i=0; i < resultLength; i++) {
        if (Tcl_ListObjIndex(interp, resultObj, i, &(tempObjList[1])) != TCL_OK) {
            return TCL_ERROR;
        }
        replaceObj = Tcl_NewListObj(2, tempObjList);
        if (Tcl_ListObjReplace(interp, resultObj, i, 1, 1, &replaceObj) != TCL_OK) {
            return TCL_ERROR;
        }
    }

    Tcl_SetObjResult(interp, resultObj);

    return TCL_OK;
}

Tcl_Obj *
HillclimbGenerateSwapNeighborKeys(Tcl_Interp *interp, char *fixedKey, char *fixedIndices) {
    char *swapKey = (char *)NULL;
    int i, j;
    int keyLength = strlen(fixedKey);
    Tcl_Obj *keyListObj = (Tcl_Obj *)NULL;

    if (fixedIndices && strlen(fixedIndices) != 0 && strlen(fixedIndices) != keyLength) {
        Tcl_SetResult(interp, "key and fixedIndices are not the same length", TCL_STATIC);
        return (Tcl_Obj *)NULL;
    }

    swapKey = (char *)ckalloc((sizeof(char) * (keyLength+1)));
    swapKey[keyLength] = (char)NULL;
    keyListObj = Tcl_NewObj();

    /*
     * Initialize 'swapKey' to be a duplicate of 'fixedKey'
     */
    for (i=0; i < keyLength; i++) {
        swapKey[i] = fixedKey[i];
    }

    for (i=0; i < keyLength; i++) {
        if (!fixedIndices || fixedIndices[i] == '0') {
            for (j=i+1; j < keyLength; j++) {
                if (!fixedIndices || fixedIndices[j] == '0') {
                    /*
                     * Swap positions i and j
                     */
                    swapKey[i] = fixedKey[j];
                    swapKey[j] = fixedKey[i];
                    /*
                     * Store swapKey in a new Tcl_Obj(string);
                     */
                    if (Tcl_ListObjAppendElement(interp, keyListObj, Tcl_NewStringObj(swapKey, keyLength)) != TCL_OK) {
                        ckfree(swapKey);
                        return (Tcl_Obj *)NULL;
                    }
                    /*
                     * Undo the swap of positions i and j
                     */
                    swapKey[i] = fixedKey[i];
                    swapKey[j] = fixedKey[j];
                }
            }
        }
    }
    ckfree(swapKey);

    return keyListObj;
}

Tcl_Obj *
HillclimbKeysquareSwapNeighborKeys(Tcl_Interp *interp, char *fixedKey, char *fixedIndices) {
    char *swapKey = (char *)NULL;
    int i, j;
    int rowLength = 0;
    int keyLength = strlen(fixedKey);
    Tcl_Obj *keyListObj = (Tcl_Obj *)NULL;

    if (fixedIndices && strlen(fixedIndices) != 0 && strlen(fixedIndices) != keyLength) {
        Tcl_SetResult(interp, "key and fixedIndices are not the same length", TCL_STATIC);
        return (Tcl_Obj *)NULL;
    }

    rowLength = (int) sqrt(keyLength);
    /*
     * TODO:  Move this test to the command function
     */
    if (rowLength * rowLength != keyLength) {
        char keyLengthString[32];
        sprintf(keyLengthString, "%d", keyLength);
        Tcl_AppendResult(interp, "key length is not a perfect square: ", keyLengthString, (char *)NULL);
        return (Tcl_Obj *)NULL;
    }

    swapKey = (char *)ckalloc((sizeof(char) * (keyLength+1)));
    swapKey[keyLength] = (char)NULL;
    keyListObj = Tcl_NewObj();

    /*
     * Initialize 'swapKey' to be a duplicate of 'fixedKey'
     */
    for (i=0; i < keyLength; i++) {
        swapKey[i] = fixedKey[i];
    }

    for (i=0; i < keyLength; i++) {
        if (!fixedIndices || fixedIndices[i] == '0') {
            for (j=i+1; j < keyLength; j++) {
                if (!fixedIndices || fixedIndices[j] == '0') {
                    if (i%rowLength == j%rowLength || i/rowLength == j/rowLength) {
                        /*
                         * Swap positions i and j
                         */
                        swapKey[i] = fixedKey[j];
                        swapKey[j] = fixedKey[i];
                        /*
                         * Store swapKey in a new Tcl_Obj(string);
                         */
                        if (Tcl_ListObjAppendElement(interp, keyListObj,
                                    Tcl_NewStringObj(swapKey, keyLength))
                                != TCL_OK) {
                            ckfree(swapKey);
                            return (Tcl_Obj *)NULL;
                        }
                        /*
                         * Undo the swap of positions i and j
                         */
                        swapKey[i] = fixedKey[i];
                        swapKey[j] = fixedKey[j];
                    }
                }
            }
        }
    }
    ckfree(swapKey);

    return keyListObj;
}

Tcl_Obj *
HillclimbRandomizeList(Tcl_Interp *interp, Tcl_Obj *listObj) {
    int listLength;
    int i;
    double randomValue;
    long int randomIndex;
    Tcl_Obj *tempObj;
    Tcl_Obj *newList = Tcl_NewListObj(0, (Tcl_Obj **)NULL);

    srand48((long int) time(NULL));

    Tcl_ListObjLength(interp, listObj, &listLength);
    for (i=0; i < listLength; i++) {
        randomValue = drand48();
        randomIndex = (int) (randomValue * (i+1));
        /*
        fprintf(stderr, "%g * %d = %d\n", randomValue, i+1, randomIndex);
        */
        if ( Tcl_ListObjIndex(interp, listObj, i, &tempObj) != TCL_OK) {
            return (Tcl_Obj *)NULL;
        }
        Tcl_ListObjReplace(interp, newList, randomIndex, 0, 1, &tempObj);
    }

    return newList;
}
