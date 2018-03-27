/*
 * route.c --
 *
 *	This file implements the route cipher type.
 *
 * Copyright (c) 1999-2005 Michael Thomas <wart@kobold.org>
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
#include <cipher.h>
#include <score.h>

#include <cipherDebug.h>

static int  CreateRoute		_ANSI_ARGS_((Tcl_Interp *interp,
				CipherItem *, int, char **));
void  DeleteRoute		_ANSI_ARGS_((ClientData));
static char *GetRoute		_ANSI_ARGS_((Tcl_Interp *, CipherItem *));
static int  SetRoute		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
static int  RestoreRoute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *));
static int  SolveRoute		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *));
int RouteCmd			_ANSI_ARGS_((ClientData, Tcl_Interp *,
				int, char **));
static int RouteUndo		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, int));
static int RouteSubstitute	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *, int));
static void RouteSetWidth	_ANSI_ARGS_((CipherItem *, int));
static int RouteLocateTip	_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *));
static int ApplyRoute		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
	    			int, int, int, char *, char *));
static void InitRouteCache	_ANSI_ARGS_((CipherItem *));
static int EncodeRoute		_ANSI_ARGS_((Tcl_Interp *, CipherItem *,
				char *, char *));

#define WRITE	1
#define READ	2

typedef struct RouteItem {
    CipherItem header;

    /*
     * Read-in/Write-out cache.  This is used to optimize repeated
     * calls to getRoute()
     */
    char *pt1;
    char *pt2;

    /*
     * Save computed routes for a given period setting.  The most common
     * use of the route cipher is to repeatedly generate keysquares of
     * the same size.  Caching the computed routes might be a performance
     * boost.
     */

    int *readCache[NUMROUTES];
    int *writeCache[NUMROUTES];

    int inDirty;
    int outDirty;

    char writeIn;	/* Route used to write in the orignal plaintext */
    char readOut;	/* Route used to read off the ciphertext */
    int width;		/* Width of block */
    int height;		/* Height of block */
} RouteItem;

CipherType RouteType = {
    "route",
    "abcdefghijklmnopqrstuvwxyz0123456789#",
    sizeof(RouteItem),
    CreateRoute,	/* create proc */
    DeleteRoute,	/* delete proc */
    RouteCmd,		/* cipher command proc */
    GetRoute,		/* get plaintext proc */
    SetRoute,		/* show ciphertext proc */
    SolveRoute,		/* solve cipher proc */
    RestoreRoute,	/* restore proc */
    RouteLocateTip,	/* locate proc */
    RouteSubstitute,	/* sub proc */
    RouteUndo,		/* undo proc */
    EncodeRoute,	/* encode proc */
    (CipherType *)NULL	/* next cipher type */
};

static int
CreateRoute(Tcl_Interp *interp, CipherItem *itemPtr, int argc, char **argv)
{
    RouteItem *routePtr = (RouteItem *)itemPtr;
    char	temp_ptr[128];
    Tcl_DString	dsPtr;
    int		i;

    routePtr->pt1 = (char *)NULL;
    routePtr->pt2 = (char *)NULL;
    routePtr->header.period = 0;
    routePtr->writeIn = NW_ROW_X_ROW;
    routePtr->readOut = NW_ROW_X_ROW;
    routePtr->inDirty = 1;
    routePtr->outDirty = 1;
    routePtr->width = 0;
    routePtr->height = 0;
    for(i=0; i < NUMROUTES; i++) {
	routePtr->readCache[i] = (int *)NULL;
	routePtr->writeCache[i] = (int *)NULL;
    }

    sprintf(temp_ptr, "cipher%d", cipherid);
    Tcl_DStringInit(&dsPtr);
    Tcl_DStringAppendElement(&dsPtr, temp_ptr);
    Tcl_DStringAppendElement(&dsPtr, "configure");
    for(i=0;i<argc;i++) {
	Tcl_DStringAppendElement(&dsPtr, argv[i]);
    }

    Tcl_CreateCommand(interp, temp_ptr, RouteCmd, itemPtr,
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
DeleteRoute(ClientData clientData)
{
    RouteItem *routePtr = (RouteItem *)clientData;
    int i;

    if (routePtr->pt1 != NULL) {
	ckfree(routePtr->pt1);
    }

    if (routePtr->pt2 != NULL) {
	ckfree(routePtr->pt2);
    }

    for(i=0; i < NUMROUTES; i++) {
	if (routePtr->readCache[i]) {
	    ckfree((char *)(routePtr->readCache[i]));
	    ckfree((char *)(routePtr->writeCache[i]));
	}
    }

    DeleteCipher(clientData);
}

static int
SetRoute(Tcl_Interp *interp, CipherItem *itemPtr, char *ctext)
{
    RouteItem *routePtr = (RouteItem *)itemPtr;
    char	*c;
    int		valid = TCL_OK,
    		length=0;

    length = CountValidChars(itemPtr, ctext);
    c = ExtractValidChars(itemPtr, ctext);

    if (!c) {
	Tcl_SetResult(interp, "No valid characters found in ciphertext",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (itemPtr->ciphertext) {
	ckfree(itemPtr->ciphertext);
    }
    itemPtr->ciphertext = c;
    /*
     * Don't bother reallocating space for the new plaintext arrays
     * if the cipher didn't change its length.
     */
    if (length != itemPtr->length) {
	itemPtr->length = length;

	if (routePtr->pt1) {
	    ckfree(routePtr->pt1);
	}
	routePtr->pt1 = (char *)ckalloc(sizeof(char) * length + 1);
	if (routePtr->pt2) {
	    ckfree(routePtr->pt2);
	}
	routePtr->pt2 = (char *)ckalloc(sizeof(char) * length + 1);

	if (itemPtr->ciphertext == NULL) {
	    routePtr->inDirty = 1;
	    routePtr->outDirty = 1;
	    Tcl_SetResult(interp, "Error mallocing memory for new cipher", TCL_STATIC);
	    return TCL_ERROR;
	}

	InitRouteCache(itemPtr);
    }

    if (routePtr->width != 0) {
	RouteSetWidth(itemPtr, routePtr->width);
    }

    Tcl_SetResult(interp, itemPtr->ciphertext, TCL_STATIC);

    routePtr->inDirty = 1;
    routePtr->outDirty = 1;
    return valid;
}

static int
RouteUndo(Tcl_Interp *interp, CipherItem *itemPtr, char *ct, int offset)
{
    return TCL_OK;
}

static int
RouteSubstitute(Tcl_Interp *interp, CipherItem *itemPtr, char *ct, char *pt, int offset)
{
    Tcl_SetResult(interp, "No substitute command for Route ciphers.",
	    TCL_STATIC);
    return TCL_ERROR;
}

static int
ApplyRoute(Tcl_Interp *interp, CipherItem *itemPtr, int route, int mode, int width, char *text, char *result)
{
    RouteItem *routePtr = (RouteItem *)itemPtr;
    int		i;
    int		length = strlen(text);
    int		height = length / width;
    int		sRow, sCol, tRow, tCol, doRow, doCol;
    int		row, col, newIndex;
    char	c[10];

    sprintf(c, "%d", route);

    if (length % width != 0) {
	Tcl_SetResult(interp, "Length is not a multiple of the specified width", TCL_STATIC);
	return TCL_ERROR;
    }

    for(i=0; i < length; i++) {
	result[i] = '-';
    }

    if (routePtr->readCache[route-1] == NULL) {
	routePtr->readCache[route-1] = (int *)ckalloc(sizeof(int) * length);
	routePtr->writeCache[route-1] = (int *)ckalloc(sizeof(int) * length);
    }
    switch (route) {
	case NW_ROW_X_ROW:
	    for(i=0; i < length; i++) {
		row = i / width;
		col = i % width;
		newIndex = row * width + col;

		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;
	    }
	    break;
	case NW_ROW_X_I_ROW:
	    for(i=0; i < length; i++) {
		row = i / width;
		col = i % width;
		if (row%2) {
		    col = width - col - 1;
		}
		newIndex = row * width + col;

		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;
	    }
	    break;
	case NW_COL_X_COL:
	    for(i=0; i < length; i++) {
		row = i % height;
		col = i / height;
		newIndex = row * width + col;

		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;
	    }
	    break;
	case NW_COL_X_I_COL:
	    for(i=0; i < length; i++) {
		row = i % height;
		col = i / height;
		if(col%2) {
		    row = height - row - 1;
		}
		newIndex = row * width + col;

		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;
	    }
	    break;
	case NE_ROW_X_ROW:
	    for(i=0; i < length; i++) {
		row = i / width;
		col = (width-1) - (i % width);
		newIndex = row * width + col;

		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;
	    }
	    break;
	case NE_ROW_X_I_ROW:
	    for(i=0; i < length; i++) {
		row = i / width;
		col = (width-1) - (i % width);
		if (row%2) {
		    col = width - col - 1;
		}
		newIndex = row * width + col;

		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;
	    }
	    break;
	case NE_COL_X_COL:
	    for(i=0; i < length; i++) {
		row = i % height;
		col = (width-1) - (i / height);
		newIndex = row * width + col;

		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;
	    }
	    break;
	case NE_COL_X_I_COL:
	    for(i=0; i < length; i++) {
		row = i % height;
		col = (width-1) - (i / height);
		if(col%2) {
		    row = height - row - 1;
		}
		newIndex = row * width + col;

		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;
	    }
	    break;
	case SW_ROW_X_ROW:
	    for(i=0; i < length; i++) {
		row = (height-1) - i / width;
		col = i % width;
		newIndex = row * width + col;

		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;
	    }
	    break;
	case SW_ROW_X_I_ROW:
	    for(i=0; i < length; i++) {
		row = (height-1) - i / width;
		col = i % width;
		if (row%2) {
		    col = width - col - 1;
		}
		newIndex = row * width + col;

		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;
	    }
	    break;
	case SW_COL_X_COL:
	    for(i=0; i < length; i++) {
		row = (height-1) - i % height;
		col = i / height;
		newIndex = row * width + col;

		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;
	    }
	    break;
	case SW_COL_X_I_COL:
	    for(i=0; i < length; i++) {
		row = (height-1) - i % height;
		col = i / height;
		if(col%2) {
		    row = height - row - 1;
		}
		newIndex = row * width + col;

		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;
	    }
	    break;
	case SE_ROW_X_ROW:
	    for(i=0; i < length; i++) {
		row = (height-1) - i / width;
		col = (width-1) - (i % width);
		newIndex = row * width + col;

		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;
	    }
	    break;
	case SE_ROW_X_I_ROW:
	    for(i=0; i < length; i++) {
		row = (height-1) - i / width;
		col = (width-1) - (i % width);
		if (row%2) {
		    col = width - col - 1;
		}
		newIndex = row * width + col;

		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;
	    }
	    break;
	case SE_COL_X_COL:
	    for(i=0; i < length; i++) {
		row = (height-1) - i % height;
		col = (width-1) - (i / height);
		newIndex = row * width + col;

		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;
	    }
	    break;
	case SE_COL_X_I_COL:
	    for(i=0; i < length; i++) {
		row = (height-1) - i % height;
		col = (width-1) - (i / height);
		if(col%2) {
		    row = height - row - 1;
		}
		newIndex = row * width + col;

		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;
	    }
	    break;
	case DIAG_W_U:
	    /*
	     * The basis for the next 4 diagonal routes
	     */
	    row = col = sRow = sCol = tRow = tCol = 0;
	    for(i=0; i < length; i++) {
		if (tRow < 0 || tCol >= width) {
		    sRow++;
		    if (sRow >= height) {
			sRow = height-1;
			sCol++;
		    } else {
			sCol = 0;
		    }

		    tCol = sCol;
		    tRow = sRow;
		}

		row = tRow;
		col = tCol;

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;

		tRow--, tCol++;
	    }
	    break;
	case DIAG_W_D:
	    /*
	     * Same as DIAG_W_U, but with each column reversed
	     */
	    row = col = sRow = sCol = tRow = tCol = 0;
	    for(i=0; i < length; i++) {
		if (tRow < 0 || tCol >= width) {
		    sRow++;
		    if (sRow >= height) {
			sRow = height-1;
			sCol++;
		    } else {
			sCol = 0;
		    }

		    tCol = sCol;
		    tRow = sRow;
		}

		row = height - tRow - 1;
		col = tCol;

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;

		tRow--, tCol++;
	    }
	    break;
	case DIAG_E_U:
	    /*
	     * Same as DIAG_W_D, but with each row reversed
	     */
	    row = col = sRow = sCol = tRow = tCol = 0;
	    for(i=0; i < length; i++) {
		if (tRow < 0 || tCol >= width) {
		    sRow++;
		    if (sRow >= height) {
			sRow = height-1;
			sCol++;
		    } else {
			sCol = 0;
		    }

		    tCol = sCol;
		    tRow = sRow;
		}

		row = tRow;
		col = width - tCol - 1;

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;

		tRow--, tCol++;
	    }
	    break;
	case DIAG_E_D:
	    /*
	     * Same as DIAG_W_D, but with each row and each column reversed
	     */
	    row = col = sRow = sCol = tRow = tCol = 0;
	    for(i=0; i < length; i++) {
		if (tRow < 0 || tCol >= width) {
		    sRow++;
		    if (sRow >= height) {
			sRow = height-1;
			sCol++;
		    } else {
			sCol = 0;
		    }

		    tCol = sCol;
		    tRow = sRow;
		}

		row = height - tRow - 1;
		col = width - tCol - 1;

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;

		tRow--, tCol++;
	    }
	    break;
	case DIAG_N_W:
	    /*
	     * Modified version of DIAG_W_U
	     */
	    row = col = sRow = sCol = tRow = tCol = 0;
	    for(i=0; i < length; i++) {
		if (tCol < 0 || tRow >= height) {
		    sCol++;
		    if (sCol >= width) {
			sCol = width-1;
			sRow++;
		    } else {
			sRow = 0;
		    }

		    tCol = sCol;
		    tRow = sRow;
		}

		row = tRow;
		col = tCol;

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;

		tRow++, tCol--;
	    }
	    break;
	case DIAG_N_E:
	    /*
	     * DIAG_N_W, with each row reversed
	     */
	    row = col = sRow = sCol = tRow = tCol = 0;
	    for(i=0; i < length; i++) {
		if (tCol < 0 || tRow >= height) {
		    sCol++;
		    if (sCol >= width) {
			sCol = width-1;
			sRow++;
		    } else {
			sRow = 0;
		    }

		    tCol = sCol;
		    tRow = sRow;
		}

		row = tRow;
		col = width - tCol - 1;

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;

		tRow++, tCol--;
	    }
	    break;
	case DIAG_S_W:
	    /*
	     * DIAG_N_W, with each column reversed
	     */
	    row = col = sRow = sCol = tRow = tCol = 0;
	    for(i=0; i < length; i++) {
		if (tCol < 0 || tRow >= height) {
		    sCol++;
		    if (sCol >= width) {
			sCol = width-1;
			sRow++;
		    } else {
			sRow = 0;
		    }

		    tCol = sCol;
		    tRow = sRow;
		}

		row = height - tRow - 1;
		col = tCol;

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;

		tRow++, tCol--;
	    }
	    break;
	case DIAG_S_E:
	    /*
	     * DIAG_N_W, with each column and row reversed
	     */
	    row = col = sRow = sCol = tRow = tCol = 0;
	    for(i=0; i < length; i++) {
		if (tCol < 0 || tRow >= height) {
		    sCol++;
		    if (sCol >= width) {
			sCol = width-1;
			sRow++;
		    } else {
			sRow = 0;
		    }

		    tCol = sCol;
		    tRow = sRow;
		}

		row = height - tRow - 1;
		col = width - tCol - 1;

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;

		tRow++, tCol--;
	    }
	    break;
	case ALT_DIAG_W_U:
	    /*
	     * Make two passes.  Fill in alternate diagonals on each pass.
	     * DIAG_W_U + DIAG_N_W
	     */
	    row = col = sRow = sCol = tRow = tCol = 0;
	    for(i=0; i < length; i++) {
		if (tRow < 0 || tCol >= width) {
		    sRow++;
		    if (sRow >= height) {
			sRow = height-1;
			sCol++;
		    } else {
			sCol = 0;
		    }

		    tCol = sCol;
		    tRow = sRow;
		}

		row = tRow;
		col = tCol;

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if ((row + col)%2 == 0) {
		    if (mode == READ) {
			result[newIndex] = text[i];
		    } else {
			result[i] = text[newIndex];
		    }
		    routePtr->readCache[route-1][i] = newIndex;
		    routePtr->writeCache[route-1][newIndex] = i;
		}

		tRow--, tCol++;
	    }
	    row = col = sRow = sCol = tRow = tCol = 0;
	    for(i=0; i < length; i++) {
		if (tCol < 0 || tRow >= height) {
		    sCol++;
		    if (sCol >= width) {
			sCol = width-1;
			sRow++;
		    } else {
			sRow = 0;
		    }

		    tCol = sCol;
		    tRow = sRow;
		}

		row = tRow;
		col = tCol;

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if ((row+col)%2 == 1) {
		    if (mode == READ) {
			result[newIndex] = text[i];
		    } else {
			result[i] = text[newIndex];
		    }
		    routePtr->readCache[route-1][i] = newIndex;
		    routePtr->writeCache[route-1][newIndex] = i;
		}

		tRow++, tCol--;
	    }
	    break;
	case ALT_DIAG_W_D:
	    /*
	     * DIAG_W_D + DIAG_S_W
	     */
	    row = col = sRow = sCol = tRow = tCol = 0;
	    for(i=0; i < length; i++) {
		if (tRow < 0 || tCol >= width) {
		    sRow++;
		    if (sRow >= height) {
			sRow = height-1;
			sCol++;
		    } else {
			sCol = 0;
		    }

		    tCol = sCol;
		    tRow = sRow;
		}

		if ((tRow + tCol)%2 == 0) {
		    row = height - tRow - 1;
		    col = tCol;

		    newIndex = row * width + col;
		    if (newIndex > length || newIndex < 0) {
			fprintf(stderr, "Fatal indexing error!\n");
			abort();
		    }
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;
		}

		tRow--, tCol++;
	    }
	    row = col = sRow = sCol = tRow = tCol = 0;
	    for(i=0; i < length; i++) {
		if (tCol < 0 || tRow >= height) {
		    sCol++;
		    if (sCol >= width) {
			sCol = width-1;
			sRow++;
		    } else {
			sRow = 0;
		    }

		    tCol = sCol;
		    tRow = sRow;
		}

		if ((tRow + tCol)%2 == 1) {
		    row = height - tRow - 1;
		    col = tCol;

		    newIndex = row * width + col;
		    if (newIndex > length || newIndex < 0) {
			fprintf(stderr, "Fatal indexing error!\n");
			abort();
		    }

		    if (mode == READ) {
			result[newIndex] = text[i];
		    } else {
			result[i] = text[newIndex];
		    }
		    routePtr->readCache[route-1][i] = newIndex;
		    routePtr->writeCache[route-1][newIndex] = i;
		}

		tRow++, tCol--;
	    }
	    break;
	case ALT_DIAG_E_U:
	    /*
	     * DIAG_E_U + DIAG_N_E
	     */
	    row = col = sRow = sCol = tRow = tCol = 0;
	    for(i=0; i < length; i++) {
		if (tRow < 0 || tCol >= width) {
		    sRow++;
		    if (sRow >= height) {
			sRow = height-1;
			sCol++;
		    } else {
			sCol = 0;
		    }

		    tCol = sCol;
		    tRow = sRow;
		}

		if ((tRow + tCol)%2 == 0) {
		    row = tRow;
		    col = width - tCol - 1;

		    newIndex = row * width + col;
		    if (newIndex > length || newIndex < 0) {
			fprintf(stderr, "Fatal indexing error!\n");
			abort();
		    }
		    if (mode == READ) {
			result[newIndex] = text[i];
		    } else {
			result[i] = text[newIndex];
		    }
		    routePtr->readCache[route-1][i] = newIndex;
		    routePtr->writeCache[route-1][newIndex] = i;
		}

		tRow--, tCol++;
	    }
	    row = col = sRow = sCol = tRow = tCol = 0;
	    for(i=0; i < length; i++) {
		if (tCol < 0 || tRow >= height) {
		    sCol++;
		    if (sCol >= width) {
			sCol = width-1;
			sRow++;
		    } else {
			sRow = 0;
		    }

		    tCol = sCol;
		    tRow = sRow;
		}

		if ((tRow + tCol)%2 == 1) {
		    row = tRow;
		    col = width - tCol - 1;

		    newIndex = row * width + col;
		    if (newIndex > length || newIndex < 0) {
			fprintf(stderr, "Fatal indexing error!\n");
			abort();
		    }

		    if (mode == READ) {
			result[newIndex] = text[i];
		    } else {
			result[i] = text[newIndex];
		    }
		    routePtr->readCache[route-1][i] = newIndex;
		    routePtr->writeCache[route-1][newIndex] = i;
		}

		tRow++, tCol--;
	    }
	    break;
	case ALT_DIAG_E_D:
	    /*
	     * DIAG_E_D + DIAG_S_E
	     */
	    row = col = sRow = sCol = tRow = tCol = 0;
	    for(i=0; i < length; i++) {
		if (tRow < 0 || tCol >= width) {
		    sRow++;
		    if (sRow >= height) {
			sRow = height-1;
			sCol++;
		    } else {
			sCol = 0;
		    }

		    tCol = sCol;
		    tRow = sRow;
		}

		if ((tRow + tCol)%2 == 0) {
		    row = height - tRow - 1;
		    col = width - tCol - 1;

		    newIndex = row * width + col;
		    if (newIndex > length || newIndex < 0) {
			fprintf(stderr, "Fatal indexing error!\n");
			abort();
		    }
		    if (mode == READ) {
			result[newIndex] = text[i];
		    } else {
			result[i] = text[newIndex];
		    }
		    routePtr->readCache[route-1][i] = newIndex;
		    routePtr->writeCache[route-1][newIndex] = i;
		}

		tRow--, tCol++;
	    }
	    row = col = sRow = sCol = tRow = tCol = 0;
	    for(i=0; i < length; i++) {
		if (tCol < 0 || tRow >= height) {
		    sCol++;
		    if (sCol >= width) {
			sCol = width-1;
			sRow++;
		    } else {
			sRow = 0;
		    }

		    tCol = sCol;
		    tRow = sRow;
		}

		if ((tRow + tCol)%2 == 1) {
		    row = height - tRow - 1;
		    col = width - tCol - 1;

		    newIndex = row * width + col;
		    if (newIndex > length || newIndex < 0) {
			fprintf(stderr, "Fatal indexing error!\n");
			abort();
		    }

		    if (mode == READ) {
			result[newIndex] = text[i];
		    } else {
			result[i] = text[newIndex];
		    }
		    routePtr->readCache[route-1][i] = newIndex;
		    routePtr->writeCache[route-1][newIndex] = i;
		}

		tRow++, tCol--;
	    }
	    break;
	case ALT_DIAG_N_W:
	    /*
	     * Make two passes.  Fill in alternate diagonals on each pass.
	     * DIAG_W_U + DIAG_N_W
	     */
	    row = col = sRow = sCol = tRow = tCol = 0;
	    for(i=0; i < length; i++) {
		if (tRow < 0 || tCol >= width) {
		    sRow++;
		    if (sRow >= height) {
			sRow = height-1;
			sCol++;
		    } else {
			sCol = 0;
		    }

		    tCol = sCol;
		    tRow = sRow;
		}

		row = tRow;
		col = tCol;

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if ((row + col)%2 == 1) {
		    if (mode == READ) {
			result[newIndex] = text[i];
		    } else {
			result[i] = text[newIndex];
		    }
		    routePtr->readCache[route-1][i] = newIndex;
		    routePtr->writeCache[route-1][newIndex] = i;
		}

		tRow--, tCol++;
	    }
	    row = col = sRow = sCol = tRow = tCol = 0;
	    for(i=0; i < length; i++) {
		if (tCol < 0 || tRow >= height) {
		    sCol++;
		    if (sCol >= width) {
			sCol = width-1;
			sRow++;
		    } else {
			sRow = 0;
		    }

		    tCol = sCol;
		    tRow = sRow;
		}

		row = tRow;
		col = tCol;

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if ((row+col)%2 == 0) {
		    if (mode == READ) {
			result[newIndex] = text[i];
		    } else {
			result[i] = text[newIndex];
		    }
		    routePtr->readCache[route-1][i] = newIndex;
		    routePtr->writeCache[route-1][newIndex] = i;
		}

		tRow++, tCol--;
	    }
	    break;
	case ALT_DIAG_N_E:
	    /*
	     * DIAG_E_U + DIAG_N_E
	     */
	    row = col = sRow = sCol = tRow = tCol = 0;
	    for(i=0; i < length; i++) {
		if (tRow < 0 || tCol >= width) {
		    sRow++;
		    if (sRow >= height) {
			sRow = height-1;
			sCol++;
		    } else {
			sCol = 0;
		    }

		    tCol = sCol;
		    tRow = sRow;
		}

		if ((tRow + tCol)%2 == 1) {
		    row = tRow;
		    col = width - tCol - 1;

		    newIndex = row * width + col;
		    if (newIndex > length || newIndex < 0) {
			fprintf(stderr, "Fatal indexing error!\n");
			abort();
		    }
		    if (mode == READ) {
			result[newIndex] = text[i];
		    } else {
			result[i] = text[newIndex];
		    }
		    routePtr->readCache[route-1][i] = newIndex;
		    routePtr->writeCache[route-1][newIndex] = i;
		}

		tRow--, tCol++;
	    }
	    row = col = sRow = sCol = tRow = tCol = 0;
	    for(i=0; i < length; i++) {
		if (tCol < 0 || tRow >= height) {
		    sCol++;
		    if (sCol >= width) {
			sCol = width-1;
			sRow++;
		    } else {
			sRow = 0;
		    }

		    tCol = sCol;
		    tRow = sRow;
		}

		if ((tRow + tCol)%2 == 0) {
		    row = tRow;
		    col = width - tCol - 1;

		    newIndex = row * width + col;
		    if (newIndex > length || newIndex < 0) {
			fprintf(stderr, "Fatal indexing error!\n");
			abort();
		    }

		    if (mode == READ) {
			result[newIndex] = text[i];
		    } else {
			result[i] = text[newIndex];
		    }
		    routePtr->readCache[route-1][i] = newIndex;
		    routePtr->writeCache[route-1][newIndex] = i;
		}

		tRow++, tCol--;
	    }
	    break;
	case ALT_DIAG_S_W:
	    /*
	     * DIAG_W_D + DIAG_S_W
	     */
	    row = col = sRow = sCol = tRow = tCol = 0;
	    for(i=0; i < length; i++) {
		if (tRow < 0 || tCol >= width) {
		    sRow++;
		    if (sRow >= height) {
			sRow = height-1;
			sCol++;
		    } else {
			sCol = 0;
		    }

		    tCol = sCol;
		    tRow = sRow;
		}

		if ((tRow + tCol)%2 == 1) {
		    row = height - tRow - 1;
		    col = tCol;

		    newIndex = row * width + col;
		    if (newIndex > length || newIndex < 0) {
			fprintf(stderr, "Fatal indexing error!\n");
			abort();
		    }
		    if (mode == READ) {
			result[newIndex] = text[i];
		    } else {
			result[i] = text[newIndex];
		    }
		    routePtr->readCache[route-1][i] = newIndex;
		    routePtr->writeCache[route-1][newIndex] = i;
		}

		tRow--, tCol++;
	    }
	    row = col = sRow = sCol = tRow = tCol = 0;
	    for(i=0; i < length; i++) {
		if (tCol < 0 || tRow >= height) {
		    sCol++;
		    if (sCol >= width) {
			sCol = width-1;
			sRow++;
		    } else {
			sRow = 0;
		    }

		    tCol = sCol;
		    tRow = sRow;
		}

		if ((tRow + tCol)%2 == 0) {
		    row = height - tRow - 1;
		    col = tCol;

		    newIndex = row * width + col;
		    if (newIndex > length || newIndex < 0) {
			fprintf(stderr, "Fatal indexing error!\n");
			abort();
		    }

		    if (mode == READ) {
			result[newIndex] = text[i];
		    } else {
			result[i] = text[newIndex];
		    }
		    routePtr->readCache[route-1][i] = newIndex;
		    routePtr->writeCache[route-1][newIndex] = i;
		}

		tRow++, tCol--;
	    }
	    break;
	case ALT_DIAG_S_E:
	    /*
	     * DIAG_E_D + DIAG_S_E
	     */
	    row = col = sRow = sCol = tRow = tCol = 0;
	    for(i=0; i < length; i++) {
		if (tRow < 0 || tCol >= width) {
		    sRow++;
		    if (sRow >= height) {
			sRow = height-1;
			sCol++;
		    } else {
			sCol = 0;
		    }

		    tCol = sCol;
		    tRow = sRow;
		}

		if ((tRow + tCol)%2 == 1) {
		    row = height - tRow - 1;
		    col = width - tCol - 1;

		    newIndex = row * width + col;
		    if (newIndex > length || newIndex < 0) {
			fprintf(stderr, "Fatal indexing error!\n");
			abort();
		    }
		    if (mode == READ) {
			result[newIndex] = text[i];
		    } else {
			result[i] = text[newIndex];
		    }
		    routePtr->readCache[route-1][i] = newIndex;
		    routePtr->writeCache[route-1][newIndex] = i;
		}

		tRow--, tCol++;
	    }
	    row = col = sRow = sCol = tRow = tCol = 0;
	    for(i=0; i < length; i++) {
		if (tCol < 0 || tRow >= height) {
		    sCol++;
		    if (sCol >= width) {
			sCol = width-1;
			sRow++;
		    } else {
			sRow = 0;
		    }

		    tCol = sCol;
		    tRow = sRow;
		}

		if ((tRow + tCol)%2 == 0) {
		    row = height - tRow - 1;
		    col = width - tCol - 1;

		    newIndex = row * width + col;
		    if (newIndex > length || newIndex < 0) {
			fprintf(stderr, "Fatal indexing error!\n");
			abort();
		    }

		    if (mode == READ) {
			result[newIndex] = text[i];
		    } else {
			result[i] = text[newIndex];
		    }
		    routePtr->readCache[route-1][i] = newIndex;
		    routePtr->writeCache[route-1][newIndex] = i;
		}

		tRow++, tCol--;
	    }
	    break;
	case I_NW_CW:
	    sRow = sCol = 0;
	    tRow = height - 1;
	    tCol = width - 1;
	    doRow = 0;
	    doCol = 1;
	    row = col = 0;
	    for(i=0; i < length; i++) {
		if (col > tCol) {
		    doRow = 1;
		    doCol = 0;
		    sRow++;
		    col = tCol;
		    row = sRow;
		} else if (col < sCol) {
		    doRow = -1;
		    doCol = 0;
		    tRow--;
		    col = sCol;
		    row = tRow;
		} else if (row > tRow) {
		    doCol = -1;
		    doRow = 0;
		    tCol--;
		    row = tRow;
		    col = tCol;
		} else if (row < sRow) {
		    doCol = 1;
		    doRow = 0;
		    row = sRow;
		    sCol++;
		    col = sCol;
		}

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;

		row += doRow;
		col += doCol;
	    }
	    break;
	case I_NW_CCW:
	    sRow = sCol = 0;
	    tRow = height - 1;
	    tCol = width - 1;
	    doRow = 1;
	    doCol = 0;
	    row = col = 0;
	    for(i=0; i < length; i++) {
		if (col > tCol) {
		    doRow = -1;
		    doCol = 0;
		    tRow--;
		    col = tCol;
		    row = tRow;
		} else if (col < sCol) {
		    doRow = 1;
		    doCol = 0;
		    sRow++;
		    col = sCol;
		    row = sRow;
		} else if (row > tRow) {
		    doCol = 1;
		    doRow = 0;
		    sCol++;
		    row = tRow;
		    col = sCol;
		} else if (row < sRow) {
		    doCol = -1;
		    doRow = 0;
		    row = sRow;
		    tCol--;
		    col = tCol;
		}

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;

		row += doRow;
		col += doCol;
	    }
	    break;
	case I_SW_CW:
	    sRow = sCol = 0;
	    tRow = height - 1;
	    tCol = width - 1;
	    doRow = -1;
	    doCol = 0;
	    row = tRow;
	    col = sCol;
	    for(i=0; i < length; i++) {
		if (col > tCol) {
		    doRow = 1;
		    doCol = 0;
		    sRow++;
		    col = tCol;
		    row = sRow;
		} else if (col < sCol) {
		    doRow = -1;
		    doCol = 0;
		    tRow--;
		    col = sCol;
		    row = tRow;
		} else if (row > tRow) {
		    doCol = -1;
		    doRow = 0;
		    tCol--;
		    row = tRow;
		    col = tCol;
		} else if (row < sRow) {
		    doCol = 1;
		    doRow = 0;
		    row = sRow;
		    sCol++;
		    col = sCol;
		}

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;

		row += doRow;
		col += doCol;
	    }
	    break;
	case I_SW_CCW:
	    sRow = sCol = 0;
	    tRow = height - 1;
	    tCol = width - 1;
	    doRow = 0;
	    doCol = 1;
	    row = tRow;
	    col = sCol;
	    for(i=0; i < length; i++) {
		if (col > tCol) {
		    doRow = -1;
		    doCol = 0;
		    tRow--;
		    col = tCol;
		    row = tRow;
		} else if (col < sCol) {
		    doRow = 1;
		    doCol = 0;
		    sRow++;
		    col = sCol;
		    row = sRow;
		} else if (row > tRow) {
		    doCol = 1;
		    doRow = 0;
		    sCol++;
		    row = tRow;
		    col = sCol;
		} else if (row < sRow) {
		    doCol = -1;
		    doRow = 0;
		    row = sRow;
		    tCol--;
		    col = tCol;
		}

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;

		row += doRow;
		col += doCol;
	    }
	    break;
	case I_NE_CW:
	    sRow = sCol = 0;
	    tRow = height - 1;
	    tCol = width - 1;
	    doRow = 1;
	    doCol = 0;
	    row = sRow;
	    col = tCol;
	    for(i=0; i < length; i++) {
		if (col > tCol) {
		    doRow = 1;
		    doCol = 0;
		    sRow++;
		    col = tCol;
		    row = sRow;
		} else if (col < sCol) {
		    doRow = -1;
		    doCol = 0;
		    tRow--;
		    col = sCol;
		    row = tRow;
		} else if (row > tRow) {
		    doCol = -1;
		    doRow = 0;
		    tCol--;
		    row = tRow;
		    col = tCol;
		} else if (row < sRow) {
		    doCol = 1;
		    doRow = 0;
		    row = sRow;
		    sCol++;
		    col = sCol;
		}

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;

		row += doRow;
		col += doCol;
	    }
	    break;
	case I_NE_CCW:
	    sRow = sCol = 0;
	    tRow = height - 1;
	    tCol = width - 1;
	    doRow = 0;
	    doCol = -1;
	    row = sRow;
	    col = tCol;
	    for(i=0; i < length; i++) {
		if (col > tCol) {
		    doRow = -1;
		    doCol = 0;
		    tRow--;
		    col = tCol;
		    row = tRow;
		} else if (col < sCol) {
		    doRow = 1;
		    doCol = 0;
		    sRow++;
		    col = sCol;
		    row = sRow;
		} else if (row > tRow) {
		    doCol = 1;
		    doRow = 0;
		    sCol++;
		    row = tRow;
		    col = sCol;
		} else if (row < sRow) {
		    doCol = -1;
		    doRow = 0;
		    row = sRow;
		    tCol--;
		    col = tCol;
		}

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;

		row += doRow;
		col += doCol;
	    }
	    break;
	case I_SE_CW:
	    sRow = sCol = 0;
	    tRow = height - 1;
	    tCol = width - 1;
	    doRow = 0;
	    doCol = -1;
	    row = tRow;
	    col = tCol;
	    for(i=0; i < length; i++) {
		if (col > tCol) {
		    doRow = 1;
		    doCol = 0;
		    sRow++;
		    col = tCol;
		    row = sRow;
		} else if (col < sCol) {
		    doRow = -1;
		    doCol = 0;
		    tRow--;
		    col = sCol;
		    row = tRow;
		} else if (row > tRow) {
		    doCol = -1;
		    doRow = 0;
		    tCol--;
		    row = tRow;
		    col = tCol;
		} else if (row < sRow) {
		    doCol = 1;
		    doRow = 0;
		    row = sRow;
		    sCol++;
		    col = sCol;
		}

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;

		row += doRow;
		col += doCol;
	    }
	    break;
	case I_SE_CCW:
	    sRow = sCol = 0;
	    tRow = height - 1;
	    tCol = width - 1;
	    doRow = -1;
	    doCol = 0;
	    row = tRow;
	    col = tCol;
	    for(i=0; i < length; i++) {
		if (col > tCol) {
		    doRow = -1;
		    doCol = 0;
		    tRow--;
		    col = tCol;
		    row = tRow;
		} else if (col < sCol) {
		    doRow = 1;
		    doCol = 0;
		    sRow++;
		    col = sCol;
		    row = sRow;
		} else if (row > tRow) {
		    doCol = 1;
		    doRow = 0;
		    sCol++;
		    row = tRow;
		    col = sCol;
		} else if (row < sRow) {
		    doCol = -1;
		    doRow = 0;
		    row = sRow;
		    tCol--;
		    col = tCol;
		}

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;

		row += doRow;
		col += doCol;
	    }
	    break;
	case O_NW_CCW:
	    sRow = sCol = 0;
	    tRow = height - 1;
	    tCol = width - 1;
	    doRow = 0;
	    doCol = 1;
	    row = col = 0;
	    for(i=length-1; i >= 0; i--) {
		if (col > tCol) {
		    doRow = 1;
		    doCol = 0;
		    sRow++;
		    col = tCol;
		    row = sRow;
		} else if (col < sCol) {
		    doRow = -1;
		    doCol = 0;
		    tRow--;
		    col = sCol;
		    row = tRow;
		} else if (row > tRow) {
		    doCol = -1;
		    doRow = 0;
		    tCol--;
		    row = tRow;
		    col = tCol;
		} else if (row < sRow) {
		    doCol = 1;
		    doRow = 0;
		    row = sRow;
		    sCol++;
		    col = sCol;
		}

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;

		row += doRow;
		col += doCol;
	    }
	    break;
	case O_NW_CW:
	    sRow = sCol = 0;
	    tRow = height - 1;
	    tCol = width - 1;
	    doRow = 1;
	    doCol = 0;
	    row = col = 0;
	    for(i=length-1; i >= 0; i--) {
		if (col > tCol) {
		    doRow = -1;
		    doCol = 0;
		    tRow--;
		    col = tCol;
		    row = tRow;
		} else if (col < sCol) {
		    doRow = 1;
		    doCol = 0;
		    sRow++;
		    col = sCol;
		    row = sRow;
		} else if (row > tRow) {
		    doCol = 1;
		    doRow = 0;
		    sCol++;
		    row = tRow;
		    col = sCol;
		} else if (row < sRow) {
		    doCol = -1;
		    doRow = 0;
		    row = sRow;
		    tCol--;
		    col = tCol;
		}

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;

		row += doRow;
		col += doCol;
	    }
	    break;
	case O_SW_CCW:
	    sRow = sCol = 0;
	    tRow = height - 1;
	    tCol = width - 1;
	    doRow = -1;
	    doCol = 0;
	    row = tRow;
	    col = sCol;
	    for(i=length-1; i >= 0; i--) {
		if (col > tCol) {
		    doRow = 1;
		    doCol = 0;
		    sRow++;
		    col = tCol;
		    row = sRow;
		} else if (col < sCol) {
		    doRow = -1;
		    doCol = 0;
		    tRow--;
		    col = sCol;
		    row = tRow;
		} else if (row > tRow) {
		    doCol = -1;
		    doRow = 0;
		    tCol--;
		    row = tRow;
		    col = tCol;
		} else if (row < sRow) {
		    doCol = 1;
		    doRow = 0;
		    row = sRow;
		    sCol++;
		    col = sCol;
		}

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;

		row += doRow;
		col += doCol;
	    }
	    break;
	case O_SW_CW:
	    sRow = sCol = 0;
	    tRow = height - 1;
	    tCol = width - 1;
	    doRow = 0;
	    doCol = 1;
	    row = tRow;
	    col = sCol;
	    for(i=length-1; i >= 0; i--) {
		if (col > tCol) {
		    doRow = -1;
		    doCol = 0;
		    tRow--;
		    col = tCol;
		    row = tRow;
		} else if (col < sCol) {
		    doRow = 1;
		    doCol = 0;
		    sRow++;
		    col = sCol;
		    row = sRow;
		} else if (row > tRow) {
		    doCol = 1;
		    doRow = 0;
		    sCol++;
		    row = tRow;
		    col = sCol;
		} else if (row < sRow) {
		    doCol = -1;
		    doRow = 0;
		    row = sRow;
		    tCol--;
		    col = tCol;
		}

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;

		row += doRow;
		col += doCol;
	    }
	    break;
	case O_NE_CCW:
	    sRow = sCol = 0;
	    tRow = height - 1;
	    tCol = width - 1;
	    doRow = 1;
	    doCol = 0;
	    row = sRow;
	    col = tCol;
	    for(i=length-1; i >= 0; i--) {
		if (col > tCol) {
		    doRow = 1;
		    doCol = 0;
		    sRow++;
		    col = tCol;
		    row = sRow;
		} else if (col < sCol) {
		    doRow = -1;
		    doCol = 0;
		    tRow--;
		    col = sCol;
		    row = tRow;
		} else if (row > tRow) {
		    doCol = -1;
		    doRow = 0;
		    tCol--;
		    row = tRow;
		    col = tCol;
		} else if (row < sRow) {
		    doCol = 1;
		    doRow = 0;
		    row = sRow;
		    sCol++;
		    col = sCol;
		}

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;

		row += doRow;
		col += doCol;
	    }
	    break;
	case O_NE_CW:
	    sRow = sCol = 0;
	    tRow = height - 1;
	    tCol = width - 1;
	    doRow = 0;
	    doCol = -1;
	    row = sRow;
	    col = tCol;
	    for(i=length-1; i >= 0; i--) {
		if (col > tCol) {
		    doRow = -1;
		    doCol = 0;
		    tRow--;
		    col = tCol;
		    row = tRow;
		} else if (col < sCol) {
		    doRow = 1;
		    doCol = 0;
		    sRow++;
		    col = sCol;
		    row = sRow;
		} else if (row > tRow) {
		    doCol = 1;
		    doRow = 0;
		    sCol++;
		    row = tRow;
		    col = sCol;
		} else if (row < sRow) {
		    doCol = -1;
		    doRow = 0;
		    row = sRow;
		    tCol--;
		    col = tCol;
		}

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;

		row += doRow;
		col += doCol;
	    }
	    break;
	case O_SE_CCW:
	    sRow = sCol = 0;
	    tRow = height - 1;
	    tCol = width - 1;
	    doRow = 0;
	    doCol = -1;
	    row = tRow;
	    col = tCol;
	    for(i=length-1; i >= 0; i--) {
		if (col > tCol) {
		    doRow = 1;
		    doCol = 0;
		    sRow++;
		    col = tCol;
		    row = sRow;
		} else if (col < sCol) {
		    doRow = -1;
		    doCol = 0;
		    tRow--;
		    col = sCol;
		    row = tRow;
		} else if (row > tRow) {
		    doCol = -1;
		    doRow = 0;
		    tCol--;
		    row = tRow;
		    col = tCol;
		} else if (row < sRow) {
		    doCol = 1;
		    doRow = 0;
		    row = sRow;
		    sCol++;
		    col = sCol;
		}

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;

		row += doRow;
		col += doCol;
	    }
	    break;
	case O_SE_CW:
	    sRow = sCol = 0;
	    tRow = height - 1;
	    tCol = width - 1;
	    doRow = -1;
	    doCol = 0;
	    row = tRow;
	    col = tCol;
	    for(i=length-1; i >= 0; i--) {
		if (col > tCol) {
		    doRow = -1;
		    doCol = 0;
		    tRow--;
		    col = tCol;
		    row = tRow;
		} else if (col < sCol) {
		    doRow = 1;
		    doCol = 0;
		    sRow++;
		    col = sCol;
		    row = sRow;
		} else if (row > tRow) {
		    doCol = 1;
		    doRow = 0;
		    sCol++;
		    row = tRow;
		    col = sCol;
		} else if (row < sRow) {
		    doCol = -1;
		    doRow = 0;
		    row = sRow;
		    tCol--;
		    col = tCol;
		}

		newIndex = row * width + col;
		if (newIndex > length || newIndex < 0) {
		    fprintf(stderr, "Fatal indexing error!\n");
		    abort();
		}
		if (mode == READ) {
		    result[newIndex] = text[i];
		} else {
		    result[i] = text[newIndex];
		}
		routePtr->readCache[route-1][i] = newIndex;
		routePtr->writeCache[route-1][newIndex] = i;

		row += doRow;
		col += doCol;
	    }
	    break;
	default:
	    Tcl_AppendResult(interp, "Unknown route:  ", c, (char *)NULL);
	    return TCL_ERROR;
    }

    result[length] = (char)NULL;

    return TCL_OK;
}

static char *
GetRoute(Tcl_Interp *interp, CipherItem *itemPtr)
{
    RouteItem *routePtr = (RouteItem *)itemPtr;
    int i;

    if (routePtr->outDirty) {
	if (routePtr->readCache[routePtr->readOut-1] != NULL) {
	    for (i=0; i < itemPtr->length; i++) {
		routePtr->pt1[i] = itemPtr->ciphertext[routePtr->readCache[routePtr->readOut-1][i]];
	    }
	    routePtr->pt1[itemPtr->length] = (char)NULL;
	} else if (ApplyRoute(interp, itemPtr, routePtr->readOut, READ, routePtr->width, itemPtr->ciphertext, routePtr->pt1) == TCL_ERROR) {
	    return (char *)NULL;
	}
    }

    if (routePtr->inDirty) {
	if (routePtr->writeCache[routePtr->writeIn-1] != NULL) {
	    for (i=0; i < itemPtr->length; i++) {
		routePtr->pt2[i] = routePtr->pt1[routePtr->writeCache[routePtr->writeIn-1][i]];
	    }
	    routePtr->pt2[itemPtr->length] = (char)NULL;
	} else if (ApplyRoute(interp, itemPtr, routePtr->writeIn, WRITE, routePtr->width, routePtr->pt1, routePtr->pt2) == TCL_ERROR) {
	    return (char *)NULL;
	}
    }

    routePtr->inDirty = 0;
    routePtr->outDirty = 0;

    return routePtr->pt2;
}

static int
RestoreRoute(Tcl_Interp *interp, CipherItem *itemPtr, char *key, char *dummy)
{
    return TCL_OK;
}

static int
SolveRoute(Tcl_Interp *interp, CipherItem *itemPtr, char *maxkey)
{
    RouteItem *routePtr = (RouteItem *)itemPtr;
    int i, j;
    double val, maxval=0.0;
    int bestIn=0;
    int bestOut=0;
    char *pt=(char *)NULL;
    Tcl_DString dsPtr;

    if (routePtr->width < 1 || routePtr->height < 1) {
	Tcl_SetResult(interp, "Can't solve route ciphers until a width or height has been set", TCL_STATIC);
	return TCL_ERROR;
    }

    itemPtr->curIteration = 0;

    for(i=1; i <=NUMROUTES; i++) {
	routePtr->writeIn = i;
	/*
	fprintf(stderr, "%d\n", i);
	*/
	for(j=1; j <= NUMROUTES; j++) {
	    routePtr->readOut = j;
	    routePtr->inDirty = 1;
	    routePtr->outDirty = 1;
	    pt = GetRoute(interp, itemPtr);
	    if (pt) {
		if (DefaultScoreValue(interp, (unsigned char *)pt, &val)
                        != TCL_OK) {
		    return TCL_ERROR;
		}
		/*
		fprintf(stdout, "%4d %2d,%2d:  %s\n", val, i, j, pt);
		fflush(stdout);
		*/
		if (val > maxval) {
                    char temp_str[128];
		    maxval = val;
		    bestIn = i;
		    bestOut = j;
                    Tcl_DStringInit(&dsPtr);

                    if (itemPtr->bestFitCommand) {
                        Tcl_DStringAppendElement(&dsPtr, itemPtr->bestFitCommand);

                        sprintf(temp_str, "%lu", itemPtr->curIteration);
                        Tcl_DStringAppendElement(&dsPtr, temp_str);

                        Tcl_DStringStartSublist(&dsPtr);
                        sprintf(temp_str, "%d %d", i, j);
                        Tcl_DStringAppendElement(&dsPtr, temp_str);
                        Tcl_DStringEndSublist(&dsPtr);

                        sprintf(temp_str, "%g", val);
                        Tcl_DStringAppendElement(&dsPtr, temp_str);

                        Tcl_DStringAppendElement(&dsPtr, pt);

                        if (Tcl_Eval(interp, Tcl_DStringValue(&dsPtr)) != TCL_OK) {
                            ckfree(pt);
                            Tcl_ResetResult(interp);
                            Tcl_AppendResult(interp, "Bad command usage:  ", Tcl_DStringValue(&dsPtr), (char *)NULL);

                            Tcl_DStringFree(&dsPtr);
                            return TCL_ERROR;
                        }
                    }

                    Tcl_DStringFree(&dsPtr);
		}
		/*
		ckfree(pt);
		*/
                if (itemPtr->stepInterval && itemPtr->curIteration % itemPtr->stepInterval == 0 && itemPtr->stepCommand && pt) {
                    char temp_str[128];

                    Tcl_DStringInit(&dsPtr);

                    Tcl_DStringAppendElement(&dsPtr, itemPtr->stepCommand);

                    sprintf(temp_str, "%lu", itemPtr->curIteration);
                    Tcl_DStringAppendElement(&dsPtr, temp_str);

                    Tcl_DStringStartSublist(&dsPtr);
                    sprintf(temp_str, "%d %d", i, j);
                    Tcl_DStringAppendElement(&dsPtr, temp_str);
                    Tcl_DStringEndSublist(&dsPtr);

                    Tcl_DStringAppendElement(&dsPtr, pt);

                    if (Tcl_Eval(interp, Tcl_DStringValue(&dsPtr)) != TCL_OK) {
                        ckfree(pt);
                        Tcl_ResetResult(interp);
                        Tcl_AppendResult(interp, "Bad command usage:  ", Tcl_DStringValue(&dsPtr), (char *)NULL);
                        Tcl_DStringFree(&dsPtr);
                        return TCL_ERROR;
                    }
                    Tcl_DStringFree(&dsPtr);
                }
	    }
	}
    }

    routePtr->writeIn = bestIn;
    routePtr->readOut = bestOut;
    routePtr->inDirty = 1;
    routePtr->outDirty = 1;
    maxkey[0] = (char)NULL;
    pt = GetRoute(interp, itemPtr);
    Tcl_SetResult(interp, pt, TCL_STATIC);

    return TCL_OK;
}

static void
RouteSetWidth(CipherItem *itemPtr, int width)
{
    RouteItem *routePtr = (RouteItem *)itemPtr;

    /*
     * We need to allow the setting of the period before the
     * ciphertext is set.  This is necessary for encoding.
     */
    if (itemPtr->length == 0) {
	routePtr->width = width;
	routePtr->height = 0;
    } else if (itemPtr->length % width == 0) {
	routePtr->width = width;
	routePtr->height = itemPtr->length / width;
    } else {
	routePtr->width = 0;
	routePtr->height = 0;
    }

    routePtr->inDirty = 1;
    routePtr->outDirty = 1;

    InitRouteCache(itemPtr);
}

static void
InitRouteCache(CipherItem *itemPtr) {
    RouteItem *routePtr = (RouteItem *)itemPtr;
    int i;

    for(i=0; i < NUMROUTES; i++) {
	if (routePtr->readCache[i]) {
	    ckfree((char *)(routePtr->readCache[i]));
	    ckfree((char *)(routePtr->writeCache[i]));
	}
	routePtr->readCache[i] = (int *)NULL;
	routePtr->writeCache[i] = (int *)NULL;
    }
}

/*
 * We probably won't need this.
 */

static int
RouteLocateTip(Tcl_Interp *interp, CipherItem *itemPtr, char *tip, char *start)
{
    Tcl_SetResult(interp, "No locate tip function defined for Route ciphers.",
	    TCL_STATIC);
    return TCL_ERROR;
}

int
RouteCmd(ClientData clientData, Tcl_Interp *interp, int argc, char **argv)
{
    RouteItem *routePtr = (RouteItem *)clientData;
    CipherItem	*itemPtr = (CipherItem *)clientData;
    char	temp_str[256];
    char	*cmd;
    int		i;
    char	*tPtr=(char *)NULL;

    cmd = *argv;

    argv++, argc--;

    if (argc == 0) {
	Tcl_AppendResult(interp, "Usage:  ", cmd, " ?option?", (char *)NULL);
	return TCL_ERROR;
    }

    if (**argv == 'c' && (strncmp(*argv, "cget", 2) == 0)) {
	if (argc != 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " cget option", (char *)NULL);
	    return TCL_ERROR;
	}
	if (strncmp(argv[1], "-ptblock", 8) == 0) {
	    Tcl_DString dsPtr;
	    int j;

	    Tcl_DStringInit(&dsPtr);

	    tPtr = (itemPtr->typePtr->decipherProc)(interp, itemPtr);

	    if (!tPtr) {
		return TCL_ERROR;
	    }

	    for(i=0; i < routePtr->height; i++) {
		for(j=0; j < routePtr->width; j++) {
		    temp_str[j] = tPtr[i*routePtr->width + j];
		}
		temp_str[j] = (char)NULL;
		Tcl_DStringAppendElement(&dsPtr, temp_str);
	    }

	    Tcl_DStringResult(interp, &dsPtr);

	    Tcl_DStringFree(&dsPtr);

	    return TCL_OK;
	} else if (strncmp(argv[1], "-plaintext", 9) == 0 ||
		   strncmp(argv[1], "-ptext", 3) == 0) {
	    tPtr = (itemPtr->typePtr->decipherProc)(interp, itemPtr);

	    if (!tPtr) {
		return TCL_ERROR;
	    }

	    Tcl_SetResult(interp, tPtr, TCL_STATIC);

	    return TCL_OK;
	} else if (strncmp(argv[1], "-numroutes", 9) == 0) {
	    sprintf(temp_str, "%d", NUMROUTES);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-length", 6) == 0) {
	    sprintf(temp_str, "%d", routePtr->header.length);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-period", 6) == 0) {
	    sprintf(temp_str, "%d", routePtr->width);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-ciphertext", 10) == 0 ||
		   strncmp(argv[1], "-ctext", 3) == 0) {
	    if (!routePtr->header.ciphertext) {
		Tcl_SetResult(interp, "{}", TCL_STATIC);
	    } else {
		Tcl_SetResult(interp, routePtr->header.ciphertext, TCL_VOLATILE);
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-key", 4) == 0) {
	    sprintf(temp_str, "%d %d", routePtr->writeIn, routePtr->readOut);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);

	    return TCL_OK;
	} else if (strncmp(argv[1], "-type", 5) == 0) {
	    Tcl_SetResult(interp, itemPtr->typePtr->type, TCL_STATIC);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-width", 6) == 0) {
	    sprintf(temp_str, "%d", routePtr->width);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-height", 7) == 0) {
	    sprintf(temp_str, "%d", routePtr->height);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-stepinterval", 6) == 0) {
	    sprintf(temp_str, "%ld", itemPtr->stepInterval);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_OK;
	} else if (strncmp(argv[1], "-stepcommand", 6) == 0) {
	    if (itemPtr->stepCommand) {
		Tcl_SetResult(interp, itemPtr->stepCommand, TCL_VOLATILE);
	    } else {
		Tcl_SetResult(interp, "", TCL_STATIC);
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-bestfitcommand", 6) == 0) {
	    if (itemPtr->bestFitCommand) {
		Tcl_SetResult(interp, itemPtr->bestFitCommand, TCL_VOLATILE);
	    } else {
		Tcl_SetResult(interp, "", TCL_STATIC);
	    }
	    return TCL_OK;
	} else if (strncmp(argv[1], "-language", 8) == 0) {
	    Tcl_SetResult(interp, cipherGetLanguage(itemPtr->language),
		    TCL_VOLATILE);
	    return TCL_OK;
	} else {
	    sprintf(temp_str, "Unknown option %s", argv[1]);
	    Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
	    return TCL_ERROR;
	}
	return TCL_OK;
    } else if (**argv == 'c' && (strncmp(*argv, "configure", 2) == 0)) {
	if (argc < 3 || (argc%2 != 1)) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " configure ?option value?", (char *)NULL);
	    return TCL_ERROR;
	}
	argc--, argv++;
	while(argc > 0) {
	    if (strncmp(*argv, "-ciphertext", 10) == 0 ||
		strncmp(*argv, "-ctext", 3) == 0) {
		if ((itemPtr->typePtr->setctProc)(interp, itemPtr, argv[1]) != TCL_OK) {
		    return TCL_ERROR;
		}
	    } else if (strncmp(*argv, "-out", 4) == 0 ||
		       strncmp(*argv, "-readout", 5) == 0) {
		int d;
		if (argc < 2) {
		    Tcl_AppendResult(interp, "Usage:  ", cmd, " configure -out val", (char *)NULL);
		    return TCL_ERROR;
		}
		if (sscanf(argv[1], "%d", &d) != 1) {
		    Tcl_AppendResult(interp, "Invalid value for readout:  ", argv[1], (char *)NULL);
		    return TCL_ERROR;
		}
		if (d < 1 || d > NUMROUTES) {
		    Tcl_AppendResult(interp, "Invalid value for readout:  ", argv[1], (char *)NULL);
		    return TCL_ERROR;
		}
		routePtr->inDirty = 1;
		routePtr->outDirty = 1;
		routePtr->readOut = d;
		Tcl_SetResult(interp, argv[2], TCL_VOLATILE);
	    } else if (strncmp(*argv, "-in", 3) == 0 ||
	               strncmp(*argv, "-writein", 6) == 0) {
		int d;
		if (argc < 2) {
		    Tcl_AppendResult(interp, "Usage:  ", cmd, " configure -in val", (char *)NULL);
		    return TCL_ERROR;
		}

		if (sscanf(argv[1], "%d", &d) != 1) {
		    Tcl_AppendResult(interp, "Invalid value for writein:  ", argv[1], (char *)NULL);
		    return TCL_ERROR;
		}
		if (d < 1 || d > NUMROUTES) {
		    Tcl_AppendResult(interp, "Invalid value for writein:  ", argv[1], (char *)NULL);
		    return TCL_ERROR;
		}
		routePtr->inDirty = 1;
		/*
		routePtr->outDirty = 1;
		*/
		routePtr->writeIn = d;
		Tcl_SetResult(interp, argv[2], TCL_VOLATILE);
	    } else if (strncmp(*argv, "-width", 7) == 0 || strncmp(*argv, "-period", 7) == 0) {
		int width;

		if (argc < 2) {
		    Tcl_AppendResult(interp, "Usage:  ", cmd, " configure ", argv[0], "val", (char *)NULL);
		    return TCL_ERROR;
		}

		if (sscanf(argv[1], "%d", &width) != 1) {
		    Tcl_SetResult(interp, "Invalid width setting.", TCL_STATIC);
		    return TCL_ERROR;
		}
		if (width < 0 || (itemPtr->length > 0 && (width > itemPtr->length || itemPtr->length%width != 0))) {
		    Tcl_SetResult(interp, "Invalid width setting.", TCL_STATIC);
		    return TCL_ERROR;
		}

		routePtr->inDirty = 1;
		routePtr->outDirty = 1;
		RouteSetWidth(itemPtr, width);
		Tcl_SetResult(interp, argv[1], TCL_VOLATILE);
	    } else if (strncmp(*argv, "-stepinterval", 12) == 0) {
		if (argc < 2) {
		    Tcl_AppendResult(interp, "Usage:  ", cmd, " configure -stepinterval val", (char *)NULL);
		    return TCL_ERROR;
		}

		if (sscanf(argv[1], "%d", &i) != 1) {
		    Tcl_SetResult(interp, "Invalid interval.", TCL_STATIC);
		    return TCL_ERROR;
		}

		if (i < 0 ) {
		    Tcl_SetResult(interp, "Invalid interval.", TCL_STATIC);
		    return TCL_ERROR;
		}

		itemPtr->stepInterval = i;
	    } else if (strncmp(*argv, "-bestfitcommand", 14) == 0) {
		if (CipherSetBestFitCmd(itemPtr, argv[1]) != TCL_OK) {
		    return TCL_ERROR;
		}
	    } else if (strncmp(*argv, "-stepcommand", 14) == 0) {
		if (CipherSetStepCmd(itemPtr, argv[1]) != TCL_OK) {
		    return TCL_ERROR;
		}
	    } else if (strncmp(*argv, "-language", 8) == 0) {
		itemPtr->language = cipherSelectLanguage(argv[1]);
		Tcl_SetResult(interp, cipherGetLanguage(itemPtr->language),
			TCL_VOLATILE);
	    } else {
		sprintf(temp_str, "Unknown option %s", *argv);
		Tcl_SetResult(interp, temp_str, TCL_VOLATILE);
		return TCL_ERROR;
	    }
	    argc-=2, argv+=2;
	}
	return TCL_OK;
    } else if (**argv == 'r' && (strncmp(*argv, "restore", 7) == 0)) {
	int d;
	if (argc < 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " restore writein readout", (char *)NULL);
	    return TCL_ERROR;
	}

	if (sscanf(argv[1], "%d", &d) != 1) {
	    Tcl_AppendResult(interp, "Invalid value for writein:  ", argv[1], (char *)NULL);
	    return TCL_ERROR;
	}
	if (d < 1 || d > NUMROUTES) {
	    Tcl_AppendResult(interp, "Invalid value for writein:  ", argv[1], (char *)NULL);
	    return TCL_ERROR;
	}
	routePtr->inDirty = 1;
	routePtr->outDirty = 1;
	routePtr->writeIn = d;

	if (sscanf(argv[2], "%d", &d) != 1) {
	    Tcl_AppendResult(interp, "Invalid value for readout:  ", argv[2], (char *)NULL);
	    return TCL_ERROR;
	}
	if (d < 1 || d > NUMROUTES) {
	    Tcl_AppendResult(interp, "Invalid value for readout:  ", argv[2], (char *)NULL);
	    return TCL_ERROR;
	}
	routePtr->inDirty = 1;
	routePtr->outDirty = 1;
	routePtr->readOut = d;

	Tcl_AppendElement(interp, argv[1]);
	Tcl_AppendElement(interp, argv[2]);
	return TCL_OK;
    } else if (**argv == 'e' && (strncmp(*argv, "encode", 1) == 0)) {
	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " encode pt key",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	return (itemPtr->typePtr->encodeProc)(interp, itemPtr, argv[1], argv[2]);
    } else if (**argv == 's' && (strncmp(*argv, "solve", 5) == 0)) {
	return (itemPtr->typePtr->solveProc)(interp, itemPtr, temp_str);
    } else {
	Tcl_AppendResult(interp, "Unknown option ", *argv, (char *)NULL);
	Tcl_AppendResult(interp, "\nMust be one of:  ", cmd,
			" cget ?option?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" configure ?option value?", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" solve", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" encode pt key", (char *)NULL);
	return TCL_ERROR;
    }
}

static int
EncodeRoute(Tcl_Interp *interp, CipherItem *itemPtr, char *pt, char *key) {
    RouteItem *routePtr = (RouteItem *)itemPtr;
    char *ct = (char *)NULL;
    int count;
    int encodeIn;
    int encodeOut;
    char **argv;
    Tcl_Obj *intObj = (Tcl_Obj *)NULL;

    if (Tcl_SplitList(interp, key, &count, &argv) != TCL_OK) {
	return TCL_ERROR;
    }

    if (count != 2) {
	ckfree((char *)argv);
	Tcl_AppendResult(interp, "Invalid number of items in encoding key '",
	      key, "'.  Should have found 2.", (char *)NULL);
	return TCL_ERROR;
    }

    if (Tcl_GetInt(interp, argv[0], &encodeIn) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    if (Tcl_GetInt(interp, argv[1], &encodeOut) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    if (encodeIn < 1 || encodeOut < 1 
	    || encodeIn > NUMROUTES || encodeOut > NUMROUTES) {
	Tcl_SetResult(interp, "Route selections out of range.", TCL_STATIC);
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, pt) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }

    routePtr->inDirty = 1;
    routePtr->outDirty = 1;
    routePtr->writeIn = encodeOut;
    routePtr->readOut = encodeIn;

    ct = (itemPtr->typePtr->decipherProc)(interp, itemPtr);
    if (ct == (char *)NULL) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }
    if ((itemPtr->typePtr->setctProc)(interp, itemPtr, ct) != TCL_OK) {
	ckfree((char *)argv);
	return TCL_ERROR;
    }
    routePtr->inDirty = 1;
    routePtr->outDirty = 1;
    routePtr->writeIn = encodeIn;
    routePtr->readOut = encodeOut;


    Tcl_SetResult(interp, itemPtr->ciphertext, TCL_VOLATILE);
    ckfree((char *)argv);

    return TCL_OK;
}

#undef WRITE
#undef READ
