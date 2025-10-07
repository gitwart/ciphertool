/*
 * dictionaryCmds.h --
 *
 *	This is the header file for the dictionary commands.
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

#ifndef _DICTIONARY_CMDS_INCLUDED
#define _DICTIONARY_CMDS_INCLUDED

#include <dictionary.h>

int LookupByPatternObjCmd (ClientData , Tcl_Interp *, int, Tcl_Obj * const[]);
int LookupByLengthObjCmd (ClientData , Tcl_Interp *, int, Tcl_Obj * const[]);
int AvailableLengthsObjCmd (ClientData , Tcl_Interp *, int, Tcl_Obj * const[]);
int ClearCacheObjCmd (ClientData , Tcl_Interp *, int, Tcl_Obj * const[]);
int IsWordObjCmd (ClientData , Tcl_Interp *, int, Tcl_Obj * const[]);
int IsNumberObjCmd (ClientData , Tcl_Interp *, int, Tcl_Obj * const[]);
int AddWordObjCmd (ClientData , Tcl_Interp *, int, Tcl_Obj * const[]);
int IsIllegalTrigramObjCmd (ClientData , Tcl_Interp *, int, Tcl_Obj * const[]);
int ContainsIllegalTrigramObjCmd (ClientData , Tcl_Interp *, int, Tcl_Obj * const[]);
int DumpDictionaryCacheObjCmd (ClientData , Tcl_Interp *, int, Tcl_Obj * const[]);
int AllWordsMatchingObjCmd (ClientData , Tcl_Interp *, int, Tcl_Obj * const[]);
Tcl_Obj *lookupByLength	(Tcl_Interp *interp, Dictionary *dict, int length, char *pattern);

char *DictionaryDirectoryTraceProc (ClientData clientData, Tcl_Interp *, const char *, const char *, int);
char *DictionaryCacheTraceProc (ClientData clientData, Tcl_Interp *, const char *, const char *, int);

#endif
