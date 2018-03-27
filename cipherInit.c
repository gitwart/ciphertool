/*
 * cipherInit.c --
 *
 *	This file contains the _Init routine for the Tcl package
 *	mechanism.
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
#include <cipher.h>
#include <stat.h>
#include <perm.h>
#include <wordtree.h>
#include <score.h>
#include <hillclimb.h>
#include <keygen.h>
#include <crithmCmd.h>
#include <wordtreeCmd.h>
#include <morseCommand.h>

#include <cipherDebug.h>

#undef TCL_STORAGE_CLASS
#define TCL_STORAGE_CLASS DLLEXPORT

EXTERN int Cipher_Init _ANSI_ARGS_((Tcl_Interp *interp));
EXTERN int Dictionary_Init _ANSI_ARGS_((Tcl_Interp *interp));

#undef TCL_STORAGE_CLASS
#define TCL_STORAGE_CLASS DLLIMPORT

extern void InitCiphertypes(void);
extern ScoreItem *defaultScoreItem;

int
Cipher_Init(Tcl_Interp *interp)
{
    CrithmInfo *cInfo;
    TreeNode **tInfo;

    if (Tcl_InitStubs(interp, "8.1", 0) == NULL) {
	return TCL_ERROR;
    }

    tInfo = (TreeNode **)ckalloc(sizeof(TreeNode *));
    *tInfo = createWordTreeRoot();

    cInfo = (CrithmInfo *)ckalloc(sizeof(CrithmInfo));
    cInfo->base = 0;
    cInfo->letterValue = (int *)NULL;
    cInfo->iterationCmd = (char *)NULL;
    
    Tcl_CreateCommand(interp, "cipher", CipherCmd, (ClientData)NULL, NULL);
    Tcl_CreateCommand(interp, "stat", StatCmd, (ClientData)NULL, NULL);
    Tcl_CreateCommand(interp, "permute", PermCmd, (ClientData)NULL, NULL);
    Tcl_CreateCommand(interp, "key", KeygenCmd, (ClientData)NULL, NULL);
    Tcl_CreateCommand(interp, "morse", MorseCmd, (ClientData)NULL, NULL);
    Tcl_CreateCommand(interp, "crithm", CrithmCmd, (ClientData)cInfo,
	    CrithmDelete);
    Tcl_CreateCommand(interp, "wordtree", WordtreeCmd, (ClientData) tInfo,
	    WordtreeDelete);
    InitCiphertypes();

    if (InitScoreTypes(interp) != TCL_OK) {
	return TCL_ERROR;
    }
    Tcl_CreateCommand(interp, "score", ScoreCmd, (ClientData)NULL, DeleteScoreCommand);
    Tcl_CreateObjCommand(interp, "Hillclimb::generateSwapNeighborKeys", HillclimbGenerateSwapNeighborKeysObjCmd, (ClientData)NULL, NULL);
    Tcl_CreateObjCommand(interp, "Hillclimb::swapKeysquareKey", HillclimbKeysquareSwapNeighborKeysObjCmd, (ClientData)NULL, NULL);
    Tcl_CreateObjCommand(interp, "Hillclimb::swapAristocratKey", HillclimbAristocratSwapNeighborKeysObjCmd, (ClientData)NULL, NULL);
    Tcl_CreateObjCommand(interp, "Hillclimb::randomizeList", HillclimbRandomizeListObjCmd, (ClientData)NULL, NULL);

    Tcl_PkgProvide(interp, PACKAGE_NAME, PACKAGE_VERSION);

    if (Dictionary_Init(interp) != TCL_OK) {
	return TCL_ERROR;
    }

    Tcl_SetResult(interp, PACKAGE_VERSION, TCL_STATIC);

    return TCL_OK;
}
