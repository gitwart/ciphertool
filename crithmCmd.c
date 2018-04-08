/*
 * crithm.c --
 *
 *	This file implements a new tcl command "crithm" that aids in the
 *	solving of cryptarithm ciphers.
 *
 * Copyright (c) 1999-2000 Michael Thomas <wart@kobold.org>
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

#include <cipher.h>
#include <crithmCmd.h>
#include <string.h>
#include "perm.h"

#include <cipherDebug.h>

int
CrithmCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    CrithmInfo	*cInfo = (CrithmInfo *)clientData;
    const char	*cmd;
    const char	*option;
    int		i;

    if (argc < 2) {
	Tcl_AppendResult(interp, "Usage:  ", *argv, " option ?args?", (char *)NULL);
	return TCL_ERROR;
    }

    cmd = *argv;
    argv++, argc--;
    option = *argv;
    argv++, argc--;

    if (*option == 'v' && (strncmp(option, "value", 5) == 0)) {
	const char	*string;
	char	temp[32];
	Tcl_WideInt	value=0;
	int	wordLen=0;

	if (argc != 1) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " ", option, " string",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	if (cInfo->base == 0) {
	    Tcl_SetResult(interp,
		    "cryptarithm state not initialized",
		    TCL_STATIC);
	    return TCL_ERROR;
	}

	string = *argv;
	wordLen = strlen(string);

	if (wordLen > BASE_STEP_COUNT) {
	    Tcl_AppendResult(interp, string, " is too long.  Please recompile with a larger value for BASE_STEP_COUNT", (char *)NULL);
	    return TCL_ERROR;
	}

	for(i=0; string[i]; i++) {
	    if (string[i] < 'a' || string[i] > 'z') {
		Tcl_SetResult(interp,
			"Letter must be between a-z",
			TCL_STATIC);
		return TCL_ERROR;
	    }

	    if (cInfo->letterList[string[i] - 'a'] == UNUSED_LETTER) {
		Tcl_SetResult(interp,
			"Letter is not used in this cipher",
			TCL_STATIC);
		return TCL_ERROR;
	    }

	    value += cInfo->baseSteps[wordLen - i - 1]
		    * cInfo->letterValue[(int)(cInfo->letterList[string[i] - 'a'])];
	}

	sprintf(temp, "%ld", value);

	Tcl_SetResult(interp, temp, TCL_VOLATILE);
	return TCL_OK;
    } else if (*option == 'c' && (strncmp(option, "cvalue", 6) == 0)) {
	char	letter;
	char	temp[16];

	if (cInfo->base == 0) {
	    Tcl_SetResult(interp,
		    "cryptarithm state not initialized",
		    TCL_STATIC);
	    return TCL_ERROR;
	}

	if (argc != 1) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " ", option, " letter",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	letter = argv[0][0];

	if (letter < 'a' || letter > 'z') {
	    Tcl_SetResult(interp,
		    "Letter must be between a-z",
		    TCL_STATIC);
	    return TCL_ERROR;
	}

	if (cInfo->letterList[letter - 'a'] == UNUSED_LETTER) {
	    Tcl_SetResult(interp,
		    "Letter is not used in this cipher",
		    TCL_STATIC);
	    return TCL_ERROR;
	}

	sprintf(temp, "%d", cInfo->letterValue[(int)(cInfo->letterList[letter - 'a'])]);

	Tcl_SetResult(interp, temp, TCL_VOLATILE);
	return TCL_OK;
    } else if (*option == 'i' && (strncmp(option, "iteration", 4) == 0)) {
	char	temp[32];
	sprintf(temp, "%ld", cInfo->count);
	Tcl_SetResult(interp, temp, TCL_VOLATILE);
	return TCL_OK;
    } else if (*option == 't' && (strncmp(option, "totaliterations", 5) == 0)) {
	char	temp[32];
	sprintf(temp, "%ld", cInfo->totalIterations);
	Tcl_SetResult(interp, temp, TCL_VOLATILE);
	return TCL_OK;
    } else if (*option == 'i' && (strncmp(option, "init", 4) == 0)) {
	const char *string = *argv;
	const char *permCmd = (char *)NULL;

	if (argc != 1 && argc != 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " ", option,
		    " string", (char *)NULL);
	    return TCL_ERROR;
	}

	if (argc == 2) {
	    permCmd = argv[1];
	}

	if (cInfo->base) {
	    Tcl_SetResult(interp,
		    "crithm init called before deleting old state",
		    TCL_STATIC);
	    return TCL_ERROR;
	}

	for(i=0; i < 26; i++) {
	    cInfo->letterList[i] = UNUSED_LETTER;
	}

	for(i=0; string[i]; i++) {
	    if (string[i] < 'a' || string[i] > 'z') {
		Tcl_SetResult(interp,
			"Invalid character found in init string",
			TCL_STATIC);
		return TCL_ERROR;
	    }

	    if (cInfo->letterList[string[i] - 'a'] != UNUSED_LETTER) {
		Tcl_SetResult(interp,
			"Duplicate character found in init string",
			TCL_STATIC);
		return TCL_ERROR;
	    }

	    cInfo->letterList[string[i] - 'a'] = i;
	}

	cInfo->base = strlen(string);
	cInfo->count = 0;
	cInfo->totalIterations = 0;
	cInfo->runState = STOP_STATE;

	cInfo->letterValue = (int *)ckalloc(sizeof(int) * cInfo->base);
	for(i=0; i < cInfo->base; i++) {
	    cInfo->letterValue[i] = i;
	}

	cInfo->baseSteps[0] = 1;
	for(i=1; i < BASE_STEP_COUNT; i++) {
	    cInfo->baseSteps[i] = cInfo->baseSteps[i-1] * cInfo->base;
	}

	if (permCmd) {
	    cInfo->iterationCmd = (char *)ckalloc(sizeof(char) * (strlen(permCmd) + 1));
	    strcpy(cInfo->iterationCmd, permCmd);
	} else {
	    cInfo->iterationCmd = (char *)NULL;
	}

	Tcl_SetObjResult(interp, Tcl_NewStringObj(string, -1));
	return TCL_OK;
    } else if (*option == 's' && (strncmp(option, "stop", 4) == 0)) {
	cInfo->runState = STOP_STATE;
	return TCL_OK;
    } else if (*option == 'd' && (strncmp(option, "delete", 6) == 0)) {
	if (argc) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " ", option,
		    (char *)NULL);
	    return TCL_ERROR;
	}

	for(i=0; i < 26; i++) {
	    cInfo->letterList[i] = UNUSED_LETTER;
	}

	if (cInfo->letterValue) {
	    ckfree((char *) (cInfo->letterValue));
	}
	if (cInfo->iterationCmd) {
	    ckfree(cInfo->iterationCmd);
	}
	cInfo->iterationCmd = (char *)NULL;
	cInfo->letterValue = (int *)NULL;
	cInfo->count = 0;
	cInfo->totalIterations = 0;

	cInfo->base = 0;

	Tcl_SetResult(interp, "", TCL_STATIC);
	return TCL_OK;
    } else if (*option == 'p' && (strncmp(option, "perm", 4) == 0)) {
	if (cInfo->base == 0) {
	    Tcl_SetResult(interp,
		    "cryptarithm state not initialized",
		    TCL_STATIC);
	    return TCL_ERROR;
	}

	if (argc) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " ", option,
		    (char *)NULL);
	    return TCL_ERROR;
	}
	cInfo->runState = RUN_STATE;

	if (_internalDoPermCmd((ClientData) cInfo, interp, cInfo->base, CrithmPermCmd) == TCL_OK) {
	    Tcl_SetResult(interp, "", TCL_STATIC);
	    return TCL_OK;
	} else {
	    return TCL_ERROR;
	}
    } else if (*option == 's' && (strncmp(option, "state", 5) == 0)) {
	Tcl_DString	dsPtr;
	char	temp[16];

	if (argc) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " ", option,
		    (char *)NULL);
	    return TCL_ERROR;
	}

	if (cInfo->base == 0) {
	    Tcl_SetResult(interp,
		    "cryptarithm state not initialized",
		    TCL_STATIC);
	    return TCL_ERROR;
	}

	Tcl_DStringInit(&dsPtr);

	for(i=0; i < 26; i++) {
	    if (cInfo->letterList[i] != UNUSED_LETTER) {
		sprintf(temp, "%c", i + 'a');
		Tcl_DStringAppendElement(&dsPtr, temp);
		sprintf(temp, "%d", cInfo->letterValue[(int)(cInfo->letterList[i])]);
		Tcl_DStringAppendElement(&dsPtr, temp);
	    }
	}

	Tcl_DStringResult(interp, &dsPtr);
	return TCL_OK;
    } else {
	Tcl_AppendResult(interp, "Unknown option ", option, (char *)NULL);
	Tcl_AppendResult(interp, "\nUsage:  ", cmd,
		" init string", (char *)NULL);
	Tcl_AppendResult(interp, "\n        ", cmd,
		" delete", (char *)NULL);
	Tcl_AppendResult(interp, "\n        ", cmd,
		" iteration", (char *)NULL);
	Tcl_AppendResult(interp, "\n        ", cmd,
		" value string", (char *)NULL);
	Tcl_AppendResult(interp, "\n        ", cmd,
		" cvalue char", (char *)NULL);
	Tcl_AppendResult(interp, "\n        ", cmd,
		" perm cmd", (char *)NULL);
	return TCL_ERROR;
    }
}

void
CrithmDelete(ClientData clientData)
{
    CrithmInfo	*cInfo = (CrithmInfo *)clientData;

    if (cInfo->letterValue) {
	ckfree((char *) (cInfo->letterValue));
        cInfo->letterValue = (int *)NULL;
    }

    if (cInfo->iterationCmd) {
	ckfree(cInfo->iterationCmd);
        cInfo->iterationCmd = (char *)NULL;
    }

    ckfree((char *)clientData);
}

int
CrithmPermCmd(Tcl_Interp *interp, ClientData clientData, int *values, int length)
{
    CrithmInfo	*cInfo = (CrithmInfo *)clientData;
    Tcl_DString dsPtr;
    int		i;

    if (cInfo->base != length) {
	fprintf(stderr,
		"Fatal error while solving cryptarithm.  base != length.  %s: line %d\n",
		__FILE__, __LINE__);
	abort();
    }

    if (cInfo->runState == STOP_STATE) {
	Tcl_SetResult(interp, "stopped", TCL_STATIC);
	return TCL_ERROR;
    }

    cInfo->count++;

    for(i=0; i < length; i++) {
	cInfo->letterValue[i] = values[i];
    }

    if (cInfo->iterationCmd) {
	Tcl_DStringInit(&dsPtr);
	Tcl_DStringAppend(&dsPtr, cInfo->iterationCmd, -1);
	if (Tcl_Eval(interp, Tcl_DStringValue(&dsPtr)) != TCL_OK) {
	    Tcl_DStringFree(&dsPtr);
	    return TCL_ERROR;
	} else {
	    Tcl_DStringFree(&dsPtr);
	    return TCL_OK;
	}
    }

    return TCL_OK;
}
