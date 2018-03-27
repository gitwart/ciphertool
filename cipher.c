/*
 * cipher.c --
 *
 *	This file initializes the Tcl "cipher" package.
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
#include "cipher.h"

#include <cipherDebug.h>

static CipherType *typeList = (CipherType *)NULL;
extern CipherType AmscoType;
extern CipherType AristocratType;
extern CipherType BaconianType;
extern CipherType BazeriesType;
extern CipherType BeaufortType;
extern CipherType BifidType;
extern CipherType BigbifidType;
extern CipherType BigplayfairType;
extern CipherType CadenusType;
extern CipherType CaesarType;
extern CipherType ColumnarType;
extern CipherType DigrafidType;
extern CipherType FmorseType;
extern CipherType FoursquareType;
extern CipherType GrandpreType;
extern CipherType GrilleType;
extern CipherType GromarkType;
extern CipherType GronsfeldType;
extern CipherType HomophonicType;
extern CipherType MorbitType;
extern CipherType MyszcowskiType;
extern CipherType NicodemusType;
extern CipherType NitransType;
extern CipherType PhillipsType;
extern CipherType PlayfairType;
extern CipherType PolluxType;
extern CipherType PortaType;
extern CipherType Quagmire1Type;
extern CipherType Quagmire2Type;
extern CipherType Quagmire3Type;
extern CipherType Quagmire4Type;
extern CipherType RagbabyType;
extern CipherType RailfenceType;
extern CipherType RouteType;
extern CipherType SwagmanType;
extern CipherType TrifidType;
extern CipherType TwosquareType;
extern CipherType VariantType;
extern CipherType VigenereType;

void
InitCiphertypes(void)
{
    if (typeList == NULL) {
	typeList = &AmscoType;
	AmscoType.nextPtr = &AristocratType;
	AristocratType.nextPtr = &BaconianType;
	BaconianType.nextPtr = &BeaufortType;
	BeaufortType.nextPtr = &BazeriesType;
	BazeriesType.nextPtr = &BifidType;
	BifidType.nextPtr = &BigbifidType;
	BigbifidType.nextPtr = &BigplayfairType;
	BigplayfairType.nextPtr = &CadenusType;
	CadenusType.nextPtr = &CaesarType;
	CaesarType.nextPtr = &ColumnarType;
	ColumnarType.nextPtr = &DigrafidType;
	DigrafidType.nextPtr = &FmorseType;
	FmorseType.nextPtr = &FoursquareType;
	FoursquareType.nextPtr = &GrandpreType;
	GrandpreType.nextPtr = &GrilleType;
	GrilleType.nextPtr = &GromarkType;
	GromarkType.nextPtr = &GronsfeldType;
	GronsfeldType.nextPtr = &HomophonicType;
	HomophonicType.nextPtr = &MorbitType;
	MorbitType.nextPtr = &MyszcowskiType;
	MyszcowskiType.nextPtr = &NicodemusType;
	NicodemusType.nextPtr = &NitransType;
	NitransType.nextPtr = &PhillipsType;
	PhillipsType.nextPtr = &PlayfairType;
	PlayfairType.nextPtr = &PolluxType;
	PolluxType.nextPtr = &PortaType;
	PortaType.nextPtr = &Quagmire1Type;
	Quagmire1Type.nextPtr = &Quagmire2Type;
	Quagmire2Type.nextPtr = &Quagmire3Type;
	Quagmire3Type.nextPtr = &Quagmire4Type;
	Quagmire4Type.nextPtr = &RagbabyType;
	RagbabyType.nextPtr = &RailfenceType;
	RailfenceType.nextPtr = &RouteType;
	RouteType.nextPtr = &SwagmanType;
	SwagmanType.nextPtr = &TrifidType;
	TrifidType.nextPtr = &TwosquareType;
	TwosquareType.nextPtr = &VariantType;
	VariantType.nextPtr = &VigenereType;
	VigenereType.nextPtr = NULL;
    }
    cipherid=0;
}

void
CreateCipherType(CipherType *typePtr)
{
    CipherType *typePtr2, *prevPtr;

    for(typePtr2 = typeList, prevPtr=(CipherType *)NULL;
	typePtr2 != (CipherType *)NULL;
	prevPtr = typePtr2, typePtr2 = typePtr2->nextPtr) {

	if (strcmp(typePtr2->type, typePtr->type) == 0) {
	    if (prevPtr == (CipherType *)NULL) {
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

int
CipherSetBestFitCmd(CipherItem *itemPtr, char *cmd)
{
    if (itemPtr->bestFitCommand) {
	ckfree(itemPtr->bestFitCommand);
    }
    itemPtr->bestFitCommand = (char *)NULL;

    if (strlen(cmd) > 0) {
	itemPtr->bestFitCommand = (char *)ckalloc(sizeof(char) * strlen(cmd)+1);
	strcpy(itemPtr->bestFitCommand, cmd);
    }

    return TCL_OK;
}

int
CipherSetStepCmd(CipherItem *itemPtr, char *cmd)
{
    if (itemPtr->stepCommand) {
	ckfree(itemPtr->stepCommand);
    }
    itemPtr->stepCommand = (char *)NULL;

    if (strlen(cmd) != 0) {
	itemPtr->stepCommand = (char *)ckalloc(sizeof(char) * strlen(cmd)+1);
	strcpy(itemPtr->stepCommand, cmd);
    }

    return TCL_OK;
}

void
DeleteCipher(ClientData clientData)
{
    CipherItem *itemPtr = (CipherItem *)clientData;

    if (itemPtr->ciphertext) {
	ckfree((char *)(itemPtr->ciphertext));
    }

    if (itemPtr->stepCommand) {
	ckfree((char *)(itemPtr->stepCommand));
    }

    if (itemPtr->bestFitCommand) {
	ckfree((char *)(itemPtr->bestFitCommand));
    }

    ckfree((char *) clientData);
}

int
CipherCmd(ClientData clientData, Tcl_Interp *interp, int argc, char **argv)
{
    CipherType	*typePtr,
    		*matchPtr = NULL;
    CipherItem	*itemPtr;
    char	temp_str[128];

    if (argc < 2) {
	Tcl_SetResult(interp, "Usage:  cipher ?option? ?args?", TCL_VOLATILE);
	return TCL_ERROR;
    }

    if (*argv[1] == 'c' && (strncmp(argv[1], "create", 1) == 0)) {
	if (argc < 3) {
	    /*
	     * Error:  wrong # args
	     */
	    Tcl_SetResult(interp, "Usage:  cipher create type ?args?",
		    TCL_VOLATILE);
	    return TCL_ERROR;
	}

	for(typePtr = typeList; typePtr != NULL; typePtr = typePtr->nextPtr) {
	    if (strcmp(argv[2], typePtr->type) == 0) {
		matchPtr = typePtr;
	    }
	}

	if (matchPtr == NULL) {
	    sprintf(temp_str, "unknown cipher type %s", argv[2]);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_ERROR;
	}

	typePtr = matchPtr;
	itemPtr = (CipherItem *)ckalloc((unsigned)typePtr->size);
	itemPtr->typePtr = typePtr;
	cipherid++;
	itemPtr->ciphertext = (char *)NULL;
	itemPtr->period = 0;
	itemPtr->length = 0;
	itemPtr->language = 1;
	itemPtr->id = 0;
	itemPtr->stepCommand = (char *)NULL;
	itemPtr->bestFitCommand = (char *)NULL;
	itemPtr->stepInterval = 0;
	itemPtr->curIteration = 0;
	if ((*typePtr->createProc)(interp, itemPtr, argc-3, argv+3) != TCL_OK) {
	    /*
	     * If the create procedure failed then we should assume that it
	     * has also performed any necessary cleanup by calling the
	     * DeleteCommand procedure for the new object.  No need to free
	     * up the memory for the itemPtr since it should have already
	     * been cleaned up.
	     */
	    return TCL_ERROR;
	}

	return TCL_OK;
    } else if (*argv[1] == 't' && (strncmp(argv[1], "types", 1) == 0)) {
	if (argc > 2) {
	    Tcl_SetResult(interp,
		    "Wrong number of args.  Should be:  cipher types",
		    TCL_VOLATILE);
	    return TCL_ERROR;
	}

	for(typePtr = typeList; typePtr; typePtr = typePtr->nextPtr)
	    Tcl_AppendElement(interp, typePtr->type);

	return TCL_OK;
    } else {
	Tcl_SetResult(interp, "Usage:  cipher ?option? ?args?", TCL_VOLATILE);
	return TCL_ERROR;
    }

    return TCL_ERROR;
}
