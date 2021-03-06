/*
 * keygen.h --
 *
 *	This is the header file for the Tcl "key" command.
 *
 * Copyright (c) 2000 Michael Thomas <wart@kobold.org>
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

#define	MAX_NUM_STRING_LENGTH 128

int		KeygenCmd(ClientData, Tcl_Interp *, int , const char **);
char *		KeyTripletToString _ANSI_ARGS_((int));
char *		KeyGenerateNum _ANSI_ARGS_((Tcl_Interp *, long));
int		KeyGenerateK1 _ANSI_ARGS_((Tcl_Interp *, const char *, char *));
