/*
 * hillclimb.h --
 *
 *	This is the header file for the hillclimber routines.
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

#ifndef _HILLCLIMB_H_INCLUDED
#define _HILLCLIMB_H_INCLUDED

int	HillclimbGenerateSwapNeighborKeysObjCmd _ANSI_ARGS_((ClientData, Tcl_Interp *, int, Tcl_Obj *CONST[]));
int	HillclimbAristocratSwapNeighborKeysObjCmd _ANSI_ARGS_((ClientData, Tcl_Interp *, int, Tcl_Obj *CONST[]));
int	HillclimbKeysquareSwapNeighborKeysObjCmd _ANSI_ARGS_((ClientData, Tcl_Interp *, int, Tcl_Obj *CONST[]));
int	HillclimbRandomizeListObjCmd _ANSI_ARGS_((ClientData, Tcl_Interp *, int, Tcl_Obj *CONST[]));

Tcl_Obj *HillclimbGenerateSwapNeighborKeys _ANSI_ARGS_((Tcl_Interp *, char *, char *));
Tcl_Obj *HillclimbKeysquareSwapNeighborKeys _ANSI_ARGS_((Tcl_Interp *, char *, char *));
Tcl_Obj *HillclimbRandomizeList _ANSI_ARGS_((Tcl_Interp *, Tcl_Obj *));

#endif /* _HILLCLIMB_H_INCLUDED */
