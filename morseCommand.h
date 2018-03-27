/*
 * morseCommand.h --
 *
 *	This file contains the header information for the file morseCommand.c
 *
 * Copyright (c) 2002 Michael Thomas <wart@kobold.org>
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
#ifndef _MORSECOMMAND_H_INCLUDED

#include <tcl.h>
#include <morse.h>

#define TOMORSE	1
#define TOTEXT	2

int		MorseCmd(ClientData, Tcl_Interp *, int , char **);

#define _MORSECOMMAND_H_INCLUDED

#endif