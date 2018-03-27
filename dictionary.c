/*
 * dictionary.c --
 *
 * 	Fucntions for manipulating the cipher dictionary.
 *
 * Copyright (C) 2003  Mike Thomas <wart@kobold.org>
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
 */

#include <tcl.h>
#include <stdlib.h>
#include <dictionary.h>

int dictionaryLengthSort (const void *len1, const void *len2);

/*
 * Allocate space for a new dictionary.
 */
Dictionary *createDictionary() {
    Dictionary *dict = (Dictionary *)NULL;
    
    dict = (Dictionary *) ckalloc(sizeof(Dictionary));
    dict->directory = (char *)NULL;
    dict->directoryChanged = 0;
    dict->cacheTypes = 0;
    dict->wordTable = (Tcl_HashTable *) ckalloc(sizeof(Tcl_HashTable));
    dict->patternTable = (Tcl_HashTable *) ckalloc(sizeof(Tcl_HashTable));
    dict->trigramTable = (Tcl_HashTable *) ckalloc(sizeof(Tcl_HashTable));
    dict->wordLengths = (int *)NULL;

    Tcl_InitHashTable(dict->wordTable, TCL_STRING_KEYS);
    Tcl_InitHashTable(dict->patternTable, TCL_STRING_KEYS);
    Tcl_InitHashTable(dict->trigramTable, TCL_STRING_KEYS);

    return dict;
}

/*
 * Free up a dictionary.  All of the words in the dictionary are freed,
 * as well as the space used by the dictionary itself.
 */
void deleteDictionary(Tcl_Interp *interp, Dictionary *dict) {
    clearDictionary(interp, dict, 0);
    ckfree((char *)dict);
}

/*
 * Delete all of the words in the dictionary.
 */
void clearDictionary(Tcl_Interp *interp, Dictionary *dict, int mask) {
    Tcl_Obj *listObj;
    Tcl_HashEntry *hashEntry;
    Tcl_HashSearch tableSearch;

    if (mask == 0) {
	mask = DICTIONARY_WORD_CACHE | DICTIONARY_PATTERN_CACHE | DICTIONARY_TRIGRAM_CACHE | DICTIONARY_LENGTH_CACHE;
    }

    /*
     * Delete the hash tables and any associated entries
     */

    if (mask & DICTIONARY_WORD_CACHE) {
	hashEntry = Tcl_FirstHashEntry(dict->wordTable, &tableSearch);
	while (hashEntry != NULL) {
	    listObj = (Tcl_Obj *)Tcl_GetHashValue(hashEntry);
	    if (listObj != NULL) {
		Tcl_DecrRefCount(listObj);
	    }
	    hashEntry = Tcl_NextHashEntry(&tableSearch);
	}
	Tcl_DeleteHashTable(dict->wordTable);
	ckfree((char *)dict->wordTable);
	dict->wordTable = (Tcl_HashTable *) ckalloc(sizeof(Tcl_HashTable));
	Tcl_InitHashTable(dict->wordTable, TCL_STRING_KEYS);
    }

    if (mask & DICTIONARY_PATTERN_CACHE) {
	hashEntry = Tcl_FirstHashEntry(dict->patternTable, &tableSearch);
	while (hashEntry != NULL) {
	    listObj = (Tcl_Obj *)Tcl_GetHashValue(hashEntry);
	    if (listObj != NULL) {
		Tcl_DecrRefCount(listObj);
	    }
	    hashEntry = Tcl_NextHashEntry(&tableSearch);
	}
	Tcl_DeleteHashTable(dict->patternTable);
	ckfree((char *)dict->patternTable);
	dict->patternTable = (Tcl_HashTable *) ckalloc(sizeof(Tcl_HashTable));
	Tcl_InitHashTable(dict->patternTable, TCL_STRING_KEYS);
    }

    if (mask & DICTIONARY_TRIGRAM_CACHE) {
	hashEntry = Tcl_FirstHashEntry(dict->trigramTable, &tableSearch);
	while (hashEntry != NULL) {
	    listObj = (Tcl_Obj *)Tcl_GetHashValue(hashEntry);
	    if (listObj != NULL) {
		Tcl_DecrRefCount(listObj);
	    }
	    hashEntry = Tcl_NextHashEntry(&tableSearch);
	}
	Tcl_DeleteHashTable(dict->trigramTable);
	ckfree((char *)dict->trigramTable);
	dict->trigramTable = (Tcl_HashTable *) ckalloc(sizeof(Tcl_HashTable));
	Tcl_InitHashTable(dict->trigramTable, TCL_STRING_KEYS);
    }

    if (mask & DICTIONARY_LENGTH_CACHE) {
	if (dict->wordLengths != NULL) {
	    ckfree((char *)dict->wordLengths);
	    dict->wordLengths = (int *)NULL;
	}
    }
}

int loadAvailableLengths(Tcl_Interp *interp, Dictionary *dict) {
    int numLengths = 0;
    /*
     * Locate the lengths of the dictionary words by looking at the
     * filenames in the dictionary directory.
     */
    if ((! (dict->cacheTypes & DICTIONARY_LENGTH_CACHE)) || dict->directoryChanged) {
	if (dict->wordLengths) {
	    ckfree((char *)dict->wordLengths);
	}
	dict->wordLengths = NULL;
    }

    if (dict->wordLengths == NULL) {
	Tcl_Obj *filenames = NULL;
	Tcl_Obj *filename = NULL;
	Tcl_DString globPattern;
	char *pathParts[2];
	int numFiles = 0;
	int filenameLength = 0;
	int dictFileLength = 0;
	int fileLengthIndex = 0;
	int i;
	Tcl_Obj *command[2];

	if (dict->wordLengths != NULL) {
	    ckfree((char *)dict->wordLengths);
	    dict->wordLengths = NULL;
	}
	dict->directoryChanged = 0;

	// Look on the filesystem for the word lengths.
	// Call Tcl_GlobObjCmd() manually and look at the result.
	command[0] = Tcl_NewStringObj("glob", 4);

	Tcl_DStringInit(&globPattern);
	pathParts[0] = dict->directory;
	pathParts[1] = "len*";
	Tcl_JoinPath(2, pathParts, &globPattern);
	command[1] = Tcl_NewStringObj(Tcl_DStringValue(&globPattern), Tcl_DStringLength(&globPattern));

	// Eval the command and grab the list of filenames from the interpreter.
	if (Tcl_EvalObjv(interp, 2, command, 0) != TCL_OK) {
	    Tcl_DStringFree(&globPattern);
	    return TCL_ERROR;
	}
	Tcl_DStringFree(&globPattern);
	if (! Tcl_IsShared(command[0])) {
	    Tcl_DecrRefCount(command[0]);
	}
	if (! Tcl_IsShared(command[1])) {
	    Tcl_DecrRefCount(command[1]);
	}

	filenames = Tcl_GetObjResult(interp);

	// Extract the trailing length from the last two characters in the
	// filename.
	
	if ( Tcl_ListObjLength(interp, filenames, &numFiles) != TCL_OK) {
	    return TCL_ERROR;
	}
	dict->wordLengths = (int *)ckalloc(sizeof(int) * (numFiles + 1));
	for (i=0, fileLengthIndex=0; i < numFiles; i++) {
	    char *fileString;
	    if (Tcl_ListObjIndex(interp, filenames, i, &filename) != TCL_OK) {
		ckfree((char *) (dict->wordLengths));
		dict->wordLengths = (int *)NULL;
		return TCL_ERROR;
	    }
	    fileString = Tcl_GetStringFromObj(filename, &filenameLength);

	    if (sscanf(fileString+filenameLength-2, "%2d", &dictFileLength) == 1) {
		dict->wordLengths[fileLengthIndex++] = dictFileLength;
	    }
	}
	dict->wordLengths[fileLengthIndex] = 0;
	numLengths = fileLengthIndex;

	qsort(dict->wordLengths, numLengths, sizeof(dict->wordLengths[0]),
		dictionaryLengthSort);

    }

    return TCL_OK;
}

int dictionaryLengthSort(const void *len1, const void *len2) {
    return *(int *)len2 - *(int *)len1;
}
