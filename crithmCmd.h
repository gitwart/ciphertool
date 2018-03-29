/*
 * crithmCmd.h --
 *
 *	This is the header file for the crithmCmd.c file.
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

#include <tcl.h>

#define BASE_STEP_COUNT	15
#define UNUSED_LETTER	-1
#define STOP_STATE	 0
#define RUN_STATE	 1

typedef struct crithmInfo {
    int  base;
    int	 *letterValue;
    Tcl_WideInt baseSteps[BASE_STEP_COUNT];
    char letterList[26];
    char *iterationCmd;
    Tcl_WideInt  count;
    Tcl_WideInt  totalIterations;
    int runState;
} CrithmInfo;

int CrithmCmd		_ANSI_ARGS_((ClientData, Tcl_Interp *, int , const char **));
void CrithmDelete	_ANSI_ARGS_((ClientData));
int CrithmPermCmd	_ANSI_ARGS_((Tcl_Interp *, ClientData, int *,
			int));
