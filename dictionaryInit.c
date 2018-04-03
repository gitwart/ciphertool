/*
 * dictionaryInit.c --
 *
 *	This file contains the _Init routine for the Tcl package
 *	mechanism.
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

#include <tcl.h>
#include <stdlib.h>
#include <string.h>
#include <dictionary.h>
#include <dictionaryCmds.h>

#undef TCL_STORAGE_CLASS
#define TCL_STORAGE_CLASS DLLEXPORT

EXTERN int Dictionary_Init _ANSI_ARGS_((Tcl_Interp *interp));

#undef TCL_STORAGE_CLASS
#define TCL_STORAGE_CLASS DLLIMPORT

Dictionary *globalDictionary = (Dictionary *)NULL;

int
Dictionary_Init(Tcl_Interp *interp) {
    Dictionary *dict = (Dictionary *)NULL;
#if defined(HAVE_GETENVIRONMENTVARIABLE)
    char dirBuf[1024];
#endif
    Tcl_Obj *directoryObj;
    Tcl_Obj *cacheObj;
    Tcl_Obj *varNameObj;

    dict = createDictionary();
    globalDictionary = dict;
    dict->directory = (char *)NULL;
    // Look for the default dictionary location in the CIPHERTOOL_DICTIONARY
    // environment variable, and in $HOME/share/dict
#if defined(HAVE_GETENV)
    if (getenv("CIPHERTOOL_DICTIONARY") != NULL) {
	dict->directory = strdup(getenv("CIPHERTOOL_DICTIONARY"));
    } else if (getenv("HOME") != NULL) {
	dict->directory = malloc(sizeof(char) * (strlen(getenv("HOME")) + 12));
	sprintf(dict->directory, "%s/share/dict", getenv("HOME"));
    }
#elif defined(HAVE_GETENVIRONMENTVARIABLE)
    GetEnvironmentVariableA("CIPHERTOOL_DICTIONARY", dirBuf, 1024);
    if (strlen(dirBuf) != 0) {
	dict->directory = strdup(dirBuf);
    } else {
	GetEnvironmentVariableA("HOME", dirBuf, 1024);
	if (strlen(dirBuf) != 0) {
	    dict->directory =
		    malloc(sizeof(char) * (strlen(getenv("HOME")) + 12));
	    sprintf(dict->directory, "%s/share/dict", getenv("HOME"));
	}
    }
#endif
    if (dict->directory == NULL) {
	dict->directory = strdup("/usr/share/dict");
    }
    dict->cacheTypes = 0;

    Tcl_CreateObjCommand(interp, "Dictionary::availableLengths", AvailableLengthsObjCmd, (ClientData) dict, NULL);
    Tcl_CreateObjCommand(interp, "Dictionary::lookupByPattern2", LookupByPatternObjCmd, (ClientData) dict, NULL);
    Tcl_CreateObjCommand(interp, "Dictionary::lookupByLength", LookupByLengthObjCmd, (ClientData) dict, NULL);
    Tcl_CreateObjCommand(interp, "Dictionary::clearCache", ClearCacheObjCmd, (ClientData) dict, NULL);
    Tcl_CreateObjCommand(interp, "Dictionary::isWord", IsWordObjCmd, (ClientData) dict, NULL);
    Tcl_CreateObjCommand(interp, "Dictionary::isNumber", IsNumberObjCmd, (ClientData) dict, NULL);
    Tcl_CreateObjCommand(interp, "Dictionary::addWord", AddWordObjCmd, (ClientData) dict, NULL);
    Tcl_CreateObjCommand(interp, "Dictionary::isIllegalTrigram", IsIllegalTrigramObjCmd, (ClientData) dict, NULL);
    Tcl_CreateObjCommand(interp, "Dictionary::containsIllegalTrigram", ContainsIllegalTrigramObjCmd, (ClientData) dict, NULL);
    Tcl_CreateObjCommand(interp, "Dictionary::dumpCache", DumpDictionaryCacheObjCmd, (ClientData) dict, NULL);
    Tcl_CreateObjCommand(interp, "Dictionary::allWordsMatching", AllWordsMatchingObjCmd, (ClientData) dict, NULL);

    /*
     * We must set the directory variable and the variable trace _after_ the
     * first command has been created or else our variable won't show up.
     */
    directoryObj = Tcl_NewStringObj(dict->directory, strlen(dict->directory));
    varNameObj = Tcl_NewStringObj("Dictionary::directory", strlen("Dictionary::directory"));
    Tcl_ObjSetVar2(interp, varNameObj, (Tcl_Obj *)NULL, directoryObj, 0);
    Tcl_TraceVar(interp, "Dictionary::directory", TCL_TRACE_WRITES, DictionaryDirectoryTraceProc, (ClientData) dict);

    cacheObj = Tcl_NewStringObj("", 0);
    varNameObj = Tcl_NewStringObj("Dictionary::cache", strlen("Dictionary::cache"));
    Tcl_ObjSetVar2(interp, varNameObj, (Tcl_Obj *)NULL, cacheObj, 0);
    Tcl_TraceVar(interp, "Dictionary::cache", TCL_TRACE_WRITES, DictionaryCacheTraceProc, (ClientData) dict);


//    Tcl_PkgProvide(interp, "Dictionary", VERSION);

    return TCL_OK;
}
