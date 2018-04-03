/*
 * dictionaryCmds.c --
 *
 * 	Tcl command definitions for the dictionary commands.
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
#include <string.h>
#include <dictionary.h>
#include <dictionaryCmds.h>
#include <wordtree.h>

static Tcl_Obj *lookupByPattern		_ANSI_ARGS_((Tcl_Interp *interp,
					Tcl_Obj *wordList, const char *pattern));
static Tcl_Obj *filterWordList		_ANSI_ARGS_((Tcl_Interp *interp,
					Tcl_Obj *wordList, const char *pattern));
static Tcl_Obj *readDictionaryFile	_ANSI_ARGS_((Tcl_Interp *interp,
					Dictionary *dict, int length));
static Tcl_Obj *getWordsMatchingLength	_ANSI_ARGS_((Tcl_Interp *interp,
					Dictionary *dict, int length));
static int writeDictionaryFile		_ANSI_ARGS_((Tcl_Interp *interp,
					Dictionary *dict, int length,
					Tcl_Obj *wordList));
static int addWordToDictionary		_ANSI_ARGS_((Tcl_Interp *interp,
					Dictionary *dict, char *word));
static int wordIndexInList		_ANSI_ARGS_((Tcl_Interp *interp,
					Tcl_Obj *wordList, char *word));
static int isIllegalTrigram		_ANSI_ARGS_((Tcl_Interp *interp,
					Dictionary *dict, char *trigram));

/*
 * Trap any attempts to change the dictionary directory and update the
 * dictionary structure with the new value.
 */
char *DictionaryDirectoryTraceProc(ClientData clientData, Tcl_Interp *interp, const char *name1, const char *name2, int flags) {
    Dictionary *dict = (Dictionary *)clientData;

    if (flags | TCL_TRACE_WRITES) {
	if (dict->directory) {
	    free(dict->directory);
	}
	dict->directory = strdup(Tcl_GetVar(interp, "Dictionary::directory", 0));
    }

    return NULL;
}

/*
 * Trap any attempts to change the dictionary cache setting and update the
 * dictionary structure with the new value.
 */
char *DictionaryCacheTraceProc(ClientData clientData, Tcl_Interp *interp, const char *name1, const char *name2, int flags) {
    Dictionary *dict = (Dictionary *)clientData;
    Tcl_Obj *varName = Tcl_NewStringObj("Dictionary::cache",
	    strlen("Dictionary::cache"));

    if (flags | TCL_TRACE_WRITES) {
	Tcl_Obj *value = (Tcl_Obj *)NULL;
	Tcl_Obj **cacheVals = (Tcl_Obj **)NULL;
	int valueElemCount = 0;
	int i;
	int internalVal = 0;

	value = Tcl_ObjGetVar2(interp, varName, NULL, 0);

	if (Tcl_ListObjGetElements(interp, value, &valueElemCount, &cacheVals) != TCL_OK) {
	    Tcl_DecrRefCount(varName);
	    return "value must be a list containing a combination of 'length', 'word', 'pattern', and 'trigram'.";
	}

	for (i=0; i < valueElemCount; i++) {
	    char *stringVal = Tcl_GetString(cacheVals[i]);
	    if (strcmp(stringVal, "length") == 0) {
		internalVal |= DICTIONARY_LENGTH_CACHE;
	    } else if (strcmp(stringVal, "word") == 0) {
		internalVal |= DICTIONARY_WORD_CACHE;
	    } else if (strcmp(stringVal, "pattern") == 0) {
		internalVal |= DICTIONARY_PATTERN_CACHE;
	    } else if (strcmp(stringVal, "trigram") == 0) {
		internalVal |= DICTIONARY_TRIGRAM_CACHE;
	    } else {
		return "value must be a combination of 'length', 'word', 'pattern', and 'trigram'.";
	    }
	}

	dict->cacheTypes = internalVal;
    }

    Tcl_DecrRefCount(varName);
    return NULL;
}

/*
 * Determine all of the possible valid word lengths from the dictionary
 * filenames.
 */
int AvailableLengthsObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
    Dictionary *dict = (Dictionary *)clientData;
    int min = 0;
    int max = 0;
    int i;
    Tcl_Obj *resultObj = (Tcl_Obj *)NULL;

    if (objc >= 2) {
	if (Tcl_GetIntFromObj(interp, objv[1], &min) != TCL_OK) {
	    return TCL_ERROR;
	}
    }
    if (objc == 3) {
	if (Tcl_GetIntFromObj(interp, objv[2], &max) != TCL_OK) {
	    return TCL_ERROR;
	}
    }

    if (dict->wordLengths == NULL) {
	if (loadAvailableLengths(interp, dict) != TCL_OK) {
	    return TCL_ERROR;
	}
    }

    resultObj = Tcl_NewListObj(0, NULL);
    for (i=0; dict->wordLengths[i]; i++) {
	if ((min <=0 || (min > 0 && dict->wordLengths[i] >= min))
		&& (max <= 0 || (max > 0 && dict->wordLengths[i] <= max))) {
	    Tcl_Obj *intObj = Tcl_NewIntObj(dict->wordLengths[i]);
	    if (Tcl_ListObjAppendElement(interp, resultObj, intObj) != TCL_OK) {
		Tcl_DecrRefCount(resultObj);
		return TCL_ERROR;
	    }
	}
    }

    Tcl_SetObjResult(interp, resultObj);
    return TCL_OK;
}

/*
 * Look up a list of words in the dictionary that are all of the same
 * length, and that match an optional pattern.
 */
int LookupByLengthObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
    Dictionary *dict = (Dictionary *)clientData;
    Tcl_Obj *resultObj = (Tcl_Obj *)NULL;
    char *pattern = (char *)NULL;
    int length = 0;

    if (objc < 2 || objc > 3) {
	Tcl_SetResult(interp, "Usage: lookupByLength length ?pattern?",
		TCL_STATIC);
	return TCL_ERROR;
    }

    if (Tcl_GetIntFromObj(interp, objv[1], &length) != TCL_OK) {
	return TCL_ERROR;
    }

    if (objc == 3) {
	pattern = Tcl_GetString(objv[2]);
    }

    resultObj = lookupByLength(interp, dict, length, pattern);
    if (resultObj == NULL) {
	return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, resultObj);
    Tcl_DecrRefCount(resultObj);
    return TCL_OK;
}

/*
 * Look up a list of words in the dictionary that match a given letter
 * pattern.
 */
int LookupByPatternObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
    Dictionary *dict = (Dictionary *)clientData;
    Tcl_Obj *resultObj = (Tcl_Obj *)NULL;
    Tcl_Obj *wordList = (Tcl_Obj *)NULL;
    char *pattern = (char *)NULL;
    int length = 0;

    if (objc != 2) {
	Tcl_SetResult(interp, "Usage: lookupByPattern pattern",
		TCL_STATIC);
	return TCL_ERROR;
    }

    pattern = Tcl_GetString(objv[1]);
    length = strlen(pattern);

    /*
     * Start by getting a list of words that match the pattern length
     */
    wordList = lookupByLength(interp, dict, length, (char *)NULL);
    if (wordList == NULL) {
        Tcl_DecrRefCount(wordList);
	return TCL_ERROR;
    }

    /*
     * Now filter the list to find only the words that match the pattern
     */

    resultObj = lookupByPattern(interp, wordList, pattern);

    Tcl_SetObjResult(interp, resultObj);
    //Tcl_DecrRefCount(resultObj);
    return TCL_OK;
}

int IsWordObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
    Dictionary *dict = (Dictionary *)clientData;
    Tcl_Obj *wordObj = (Tcl_Obj *)NULL;
    Tcl_Obj *wordList = (Tcl_Obj *)NULL;

    if (objc != 2) {
	Tcl_SetResult(interp, "Usage: isWord word", TCL_STATIC);
	return TCL_ERROR;
    }

    wordObj = objv[1];

    wordList = getWordsMatchingLength(interp, dict, Tcl_GetCharLength(wordObj));
    if (wordList == NULL) {
	return TCL_ERROR;
    }

    if (wordIndexInList(interp, wordList, Tcl_GetString(wordObj)) == -1) {
	Tcl_SetObjResult(interp, Tcl_NewBooleanObj(0));
    } else {
	Tcl_SetObjResult(interp, Tcl_NewBooleanObj(1));
    }

    Tcl_DecrRefCount(wordList);

    return TCL_OK;
}

int IsNumberObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
    char *wordString = (char *)NULL;

    if (objc != 2) {
	Tcl_SetResult(interp, "Usage: isNumber word", TCL_STATIC);
	return TCL_ERROR;
    }

    wordString = Tcl_GetString(objv[1]);

    if (! *wordString) {
	Tcl_SetObjResult(interp, Tcl_NewBooleanObj(0));
	return TCL_OK;
    }

    while (*wordString) {
	if (*wordString < '0' || *wordString > '9') {
	    Tcl_SetObjResult(interp, Tcl_NewBooleanObj(0));
	    return TCL_OK;
	}

	wordString++;
    }

    Tcl_SetObjResult(interp, Tcl_NewBooleanObj(1));
    return TCL_OK;
}

/*
 * Add a word t the dictionary.  If the word is already in the dictionary
 * then it is moved to the front.
 */
int AddWordObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
    Dictionary *dict = (Dictionary *)clientData;
    Tcl_Obj *wordObj = (Tcl_Obj *)NULL;

    if (objc != 2) {
	Tcl_SetResult(interp, "Usage: addWord word", TCL_STATIC);
	return TCL_ERROR;
    }

    wordObj = objv[1];
    return addWordToDictionary(interp, dict, Tcl_GetString(wordObj));
}

/*
 * Clear the cache of words.
 */
int ClearCacheObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
    Dictionary *dict = (Dictionary *)clientData;
    int mask = 0;
    int i;

    for (i=1; i < objc; i++) {
	char *stringVal = Tcl_GetString(objv[i]);
	if (strcmp(stringVal, "length") == 0) {
	    mask |= DICTIONARY_LENGTH_CACHE;
	} else if (strcmp(stringVal, "word") == 0) {
	    mask |= DICTIONARY_WORD_CACHE;
	} else if (strcmp(stringVal, "pattern") == 0) {
	    mask |= DICTIONARY_PATTERN_CACHE;
	} else if (strcmp(stringVal, "trigram") == 0) {
	    mask |= DICTIONARY_TRIGRAM_CACHE;
	} else {
	    Tcl_AppendResult(interp, "Value must be a combination of 'length', 'word', 'pattern', and 'trigram'.  Found '", stringVal, "'", (char *)NULL);
	    return TCL_ERROR;
	}
    }

    clearDictionary(interp, dict, mask);

    return TCL_OK;
}

int IsIllegalTrigramObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
    Dictionary *dict = (Dictionary *)clientData;

    if (objc != 2) {
	Tcl_SetResult(interp, "Usage: isIllegalTrigram trigram", TCL_STATIC);
	return TCL_ERROR;
    }

    return isIllegalTrigram(interp, dict, Tcl_GetString(objv[1]));
}

int DumpDictionaryCacheObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
    Dictionary *dict = (Dictionary *)clientData;
    Tcl_HashEntry *hashEntry;
    Tcl_HashSearch tableSearch;
    Tcl_Obj *listObj = (Tcl_Obj *)NULL;
    int listLength = 0;

    if (objc != 1) {
	Tcl_SetResult(interp, "Usage: dump", TCL_STATIC);
	return TCL_ERROR;
    }

    hashEntry = Tcl_FirstHashEntry(dict->wordTable, &tableSearch);
    if (hashEntry == NULL) {
	fprintf(stderr, "No entries found in the dictionary word cache.\n");
    }
    while (hashEntry != NULL) {
	listObj = (Tcl_Obj *)Tcl_GetHashValue(hashEntry);
	if (listObj != NULL) {
	    char *hashKey = Tcl_GetHashKey(dict->wordTable, hashEntry);
	    Tcl_ListObjLength(interp, listObj, &listLength);
	    fprintf(stderr, "%s:  shared %d, %d words\n",
		    hashKey, listObj->refCount, listLength);
	}
	hashEntry = Tcl_NextHashEntry(&tableSearch);
    }

    Tcl_ResetResult(interp);
    return TCL_OK;
}

int ContainsIllegalTrigramObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
    Dictionary *dict = (Dictionary *)clientData;
    int stringLength = 0;
    int i;
    char *string = (char *)NULL;
    int isIllegal = 0;

    if (objc != 2) {
	Tcl_SetResult(interp, "Usage: containsIllegalTrigram string", TCL_STATIC);
	return TCL_ERROR;
    }

    string = Tcl_GetStringFromObj(objv[1], &stringLength);

    for (i=0; i < stringLength - 2; i++) {
	if (string[i] >= 'a' && string[i] <= 'z'
		&& string[i+1] >= 'a' && string[i+1] <= 'z'
		&& string[i+2] >= 'a' && string[i+2] <= 'z' ) {

	    if (isIllegalTrigram(interp, dict, string+i) != TCL_OK) {
		return TCL_ERROR;
	    }

	    if (Tcl_GetBooleanFromObj(interp, Tcl_GetObjResult(interp), &isIllegal) != TCL_OK) {
		return TCL_ERROR;
	    }
	    if (isIllegal) {
		/*
		 * The interpreter already has the correct value.  We just
		 * checked a few lines above.
		 */
		return TCL_OK;
	    }
	}
    }

    Tcl_ResetResult(interp);
    Tcl_SetBooleanObj(Tcl_GetObjResult(interp), 0);
    return TCL_OK;
}

int AllWordsMatchingObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
    Dictionary *dict = (Dictionary *)clientData;
    int firstWildIndex = 0;
    int patternLength = 0;
    char *pattern;
    char *tempPattern;
    int *lengthPtr;
    int wLen=0;
    unsigned short int value = 0;
    Tcl_CmdInfo infoPtr;
    TreeNode *treeRoot = (TreeNode *)NULL;
    Tcl_Obj *result = (Tcl_Obj *)NULL;

    if (objc != 2) {
	Tcl_SetResult(interp, "Usage: allWordsmatching string", TCL_STATIC);
	return TCL_ERROR;
    }

    pattern = Tcl_GetStringFromObj(objv[1], &patternLength);

    if (loadAvailableLengths(interp, dict) != TCL_OK) {
	return TCL_ERROR;
    }

    for (firstWildIndex=0;
	    pattern[firstWildIndex]
		&& pattern[firstWildIndex] <= 'z'
		&& pattern[firstWildIndex] >= 'a';
	    firstWildIndex++);

    /*
     * Try to locate a word tree.  If not found, then just use
     * pattern matching for the entire pattern.
     */

    if (Tcl_GetCommandInfo(interp, "wordtree", &infoPtr) != 1) {
	treeRoot = NULL;
    } else {
	treeRoot = *((TreeNode **)(infoPtr.clientData));
	if (treeRoot == NULL) {
	    Tcl_SetResult(interp, "wordtree has not been initialized.  This should not happen.", TCL_STATIC);
	    return TCL_ERROR;
	}
    }

    result = Tcl_NewListObj(0, NULL);
    tempPattern = (char *)ckalloc(sizeof(char) * (patternLength + 1));

    /*
     * Loop over all lengths from the first wildcard character to the
     * largest length looking for pattern matches.
     */

    lengthPtr = dict->wordLengths;
    while (*lengthPtr) {
	if (*lengthPtr <= patternLength) {
	    strcpy(tempPattern, pattern);
	    tempPattern[*lengthPtr] = '\0';

	    if (*lengthPtr < firstWildIndex+1 && !isEmptyTree(treeRoot)) {
		/*
		 * Do Nothing.  The word tree will get this one.
		 */
	    } else {
		Tcl_Obj *wordList = lookupByLength(interp, dict, *lengthPtr, tempPattern);
		// If the list wasn't cached before, now it is.  Only add it
		// to the cache again if there was a filter.
		if (wordList != NULL) {
		    Tcl_ListObjAppendList(interp, result, wordList);
		    Tcl_DecrRefCount(wordList);
		}
	    }
	}

	lengthPtr++;
    }

    /*
     * Use the word tree (if found) to match all lengths up to the first
     * wildcard character.
     */
    strcpy(tempPattern, pattern);
    tempPattern[firstWildIndex] = '\0';
    if (! isEmptyTree(treeRoot)) {
	/*
	 * Duplicate the pattern so that we can modify it while searching
	 * for words.
	 */
	wLen = treeMatchString(treeRoot, tempPattern, &value);
	while (wLen > 0) {
	    Tcl_Obj *word = Tcl_NewStringObj(tempPattern, wLen);
	    Tcl_ListObjAppendElement(interp, result, word);
	    tempPattern[wLen-1] = '\0';
	    wLen = treeMatchString(treeRoot, tempPattern, &value);
	}
    }

    ckfree(tempPattern);
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

static Tcl_Obj *
lookupByPattern(Tcl_Interp *interp, Tcl_Obj *wordList, const char *pattern) {
    int i, j;
    int wordListLength = 0;
    Tcl_Obj *filteredList;
    Tcl_Obj **words = (Tcl_Obj **)NULL;
    char letterMap[26];
    char patternMap[26];


    if (Tcl_ListObjGetElements(interp, wordList, &wordListLength, &words) != TCL_OK) {
	return (Tcl_Obj *)NULL;
    }

    /*
     * This is a redundant check.  The caller should have already validated
     * that the pattern is a series of lowercase alphabetic characters.
     */
    for (int i=0; pattern[i]; i++) {
        if (pattern[i] < 'a' || pattern[i] > 'z') {
            return (Tcl_Obj *)NULL;
        }
    }

    filteredList = Tcl_NewListObj(0, NULL);
    for (i=0; i < wordListLength; i++) {
	char *cword = Tcl_GetString(words[i]);
        for (j=0; j < 26; j++) {
            letterMap[j] = '\0';
            patternMap[j] = '\0';
        }

        for (j=0; cword[j]; j++) {
            if (cword[j] < 'a' || cword[j] > 'z') {
                break;
            } else if (! letterMap[j-'a'] && ! patternMap[cword[j]-'a']) {
                letterMap[j-'a'] = cword[j];
                patternMap[cword[j]-'a'] = j-'a';
            } else if (! letterMap[j-'a'] && patternMap[cword[j] - 'a']) {
                break;
            } else if (letterMap[j-'a'] && ! patternMap[cword[j] - 'a']) {
                break;
            } else if (letterMap[j-'a'] != cword[j]) {
                break;
            }
        }

        /*
         * If we reached the end of the word, then it was a match.
         */
        if (! cword[j]) {
	    Tcl_ListObjAppendElement(interp, filteredList, words[i]);
	}
    }

    return filteredList;
}

static Tcl_Obj *
filterWordList(Tcl_Interp *interp, Tcl_Obj *wordList, const char *pattern) {
    int i;
    int wordListLength = 0;
    Tcl_Obj *filteredList;
    Tcl_Obj **words = (Tcl_Obj **)NULL;

    if (Tcl_ListObjGetElements(interp, wordList, &wordListLength, &words) != TCL_OK) {
	return (Tcl_Obj *)NULL;
    }

    filteredList = Tcl_NewListObj(0, NULL);
    for (i=0; i < wordListLength; i++) {
	char *cword = Tcl_GetString(words[i]);
	if (Tcl_StringCaseMatch(cword, pattern, 1)) {
	    Tcl_ListObjAppendElement(interp, filteredList, words[i]);
	}
    }

    return filteredList;
}

static Tcl_Obj *
readDictionaryFile(Tcl_Interp *interp, Dictionary *dict, int length) {
    Tcl_Obj *wordList = (Tcl_Obj *)NULL;
    Tcl_DString filename;
    char fileTail[TCL_DOUBLE_SPACE];
    char *pathParts[2];
    Tcl_Channel fileChannel;
    Tcl_Obj *word = (Tcl_Obj *)NULL;

    /*
     * Determine the name of the file containing the words to load.
     */
    sprintf(fileTail, "len%02d", length);

    Tcl_DStringInit(&filename);
    pathParts[0] = dict->directory;
    pathParts[1] = fileTail;
    Tcl_JoinPath(2, (const char * const *)pathParts, &filename);

    fileChannel = Tcl_OpenFileChannel(interp,
	    Tcl_DStringValue(&filename), "r", 0);

    if (fileChannel == NULL) {
        Tcl_DStringFree(&filename);
	return NULL;
    }

    /*
     * Load the words from the file.
     */
    word = Tcl_NewObj();
    wordList = Tcl_NewListObj(0, NULL);
    while (Tcl_GetsObj(fileChannel, word) != -1) {
        if (Tcl_GetCharLength(word) != length) {
            Tcl_AppendResult(interp, "Found word with invalid length in dictionary file: ", Tcl_DStringValue(&filename), " contains ", Tcl_GetString(word), (char *)NULL); 
            Tcl_DecrRefCount(word);
            Tcl_Close(interp, fileChannel);
            Tcl_DStringFree(&filename);
            return NULL;
        }
	if (Tcl_ListObjAppendElement(interp, wordList, word)) {
	    Tcl_DecrRefCount(word);
            Tcl_Close(interp, fileChannel);
            Tcl_DStringFree(&filename);
	    return NULL;
	}
	word = Tcl_NewObj();
    }
    Tcl_DecrRefCount(word);

    if (! Tcl_Eof(fileChannel)) {
	/*
	 * TODO:  Delete the memory used by the wordlist.
	 */
	Tcl_Obj *resultObj = Tcl_NewStringObj(Tcl_ErrnoMsg(Tcl_GetErrno()), -1);
	Tcl_Close(interp, fileChannel);
	Tcl_SetObjResult(interp, resultObj);
	return NULL;
    }
    Tcl_Close(interp, fileChannel);

    Tcl_IncrRefCount(wordList);

    return wordList;
}

static int
writeDictionaryFile(Tcl_Interp *interp, Dictionary *dict, int length, Tcl_Obj *wordList) {
    Tcl_DString filename;
    char fileTail[TCL_DOUBLE_SPACE];
    char *pathParts[2];
    Tcl_Channel fileChannel;
    int wordListLength = 0;
    int i;
    Tcl_Obj **words;

    /*
     * Determine the name of the file containing the words to load.
     */
    sprintf(fileTail, "len%02d", length);

    Tcl_DStringInit(&filename);
    pathParts[0] = dict->directory;
    pathParts[1] = fileTail;
    Tcl_JoinPath(2, (const char * const *)pathParts, &filename);

    fileChannel = Tcl_OpenFileChannel(interp,
	    Tcl_DStringValue(&filename), "w", 0);
    Tcl_DStringFree(&filename);

    if (fileChannel == NULL) {
	return TCL_ERROR;
    }

    /*
     * Write the words to the file.
     */

    if (Tcl_ListObjGetElements(interp, wordList, &wordListLength, &words) != TCL_OK) {
	return TCL_ERROR;
    }
    
    for (i=0; i < wordListLength; i++) {
	Tcl_WriteChars(fileChannel, Tcl_GetString(words[i]), length);
	Tcl_WriteChars(fileChannel, "\n", 1);
    }

    if (Tcl_Close(interp, fileChannel) != TCL_OK) {
	return TCL_ERROR;
    }

    return TCL_OK;
}

/*
 * Return the list of words matching a specific length.  If no words are found
 * then they are attempted to be loaded from a dictionary file.
 */
static Tcl_Obj *getWordsMatchingLength(Tcl_Interp *interp, Dictionary *dict, int length) {
    Tcl_Obj *keyObj = (Tcl_Obj *)NULL;
    Tcl_Obj *wordList = (Tcl_Obj *)NULL;
    Tcl_HashEntry *hashEntry = (Tcl_HashEntry *)NULL;
    int dummy = 0;

    keyObj = Tcl_NewIntObj(length);
    hashEntry = Tcl_FindHashEntry(dict->wordTable, Tcl_GetString(keyObj));

    if (hashEntry != NULL) {
	Tcl_DecrRefCount(keyObj);
	Tcl_IncrRefCount((Tcl_Obj *)Tcl_GetHashValue(hashEntry));
	return (Tcl_Obj *)Tcl_GetHashValue(hashEntry);
    }

    wordList = readDictionaryFile(interp, dict, length);

    if (wordList == NULL) {
	Tcl_DecrRefCount(keyObj);
	return NULL;
    }

    if ((dict->cacheTypes & DICTIONARY_WORD_CACHE)) {
	hashEntry = Tcl_CreateHashEntry(dict->wordTable, Tcl_GetString(keyObj), &dummy);
	Tcl_IncrRefCount(wordList);
	Tcl_SetHashValue(hashEntry, (ClientData) wordList);
    }

    Tcl_DecrRefCount(keyObj);
    return wordList;
}

/*
 * Add a word t the dictionary.  If the word is already in the dictionary
 * then it is moved to the front.
 */
static int
addWordToDictionary(Tcl_Interp *interp, Dictionary *dict, char *word) {
    Tcl_Obj *wordList = (Tcl_Obj *)NULL;
    Tcl_Obj *firstWord = (Tcl_Obj *)NULL;
    int wordLength = strlen(word);
    Tcl_Obj *newWord = (Tcl_Obj *)NULL;
    int wordIndex = 0;
    int result = TCL_OK;

    wordList = readDictionaryFile(interp, dict, wordLength);

    if (Tcl_ListObjIndex(interp, wordList, 0, &firstWord) != TCL_OK) {
	return TCL_ERROR;
    }

    wordIndex = wordIndexInList(interp, wordList, word);
    if (wordIndex != -1) {
	if (Tcl_ListObjReplace(interp, wordList, wordIndex, 1, 0, (Tcl_Obj **)NULL) != TCL_OK) {
	    return TCL_ERROR;
	}
	Tcl_SetObjResult(interp, Tcl_NewIntObj(0));
    } else {
	Tcl_SetObjResult(interp, Tcl_NewIntObj(1));
    }

    newWord = Tcl_NewStringObj(word, strlen(word));
    if (Tcl_ListObjReplace(interp, wordList, 0, 0, 1, &newWord) != TCL_OK) {
	return TCL_ERROR;
    }

    result = writeDictionaryFile(interp, dict, wordLength, wordList);
    Tcl_DecrRefCount(wordList);
    return result;
}

static int
wordIndexInList(Tcl_Interp *interp, Tcl_Obj *wordList, char *word) {
    int wordListLength = 0;
    Tcl_Obj **words;
    int i;

    if (Tcl_ListObjGetElements(interp, wordList, &wordListLength, &words) != TCL_OK) {
	return -1;
    }

    for (i=0; i < wordListLength; i++) {
	if (strcmp(word, Tcl_GetString(words[i])) == 0) {
	    return i;
	}
    }

    return -1;
}

Tcl_Obj *
lookupByLength(Tcl_Interp *interp, Dictionary *dict, int length, char *pattern) {
    Tcl_Obj *keyObj = (Tcl_Obj *)NULL;
    Tcl_Obj *wordList = (Tcl_Obj *)NULL;
    Tcl_Obj *filteredWordList = (Tcl_Obj *)NULL;
    Tcl_HashEntry *hashEntry = (Tcl_HashEntry *)NULL;
    int patternLength = 0;

    if (pattern != NULL) {
	patternLength = strlen(pattern);
    }

    keyObj = Tcl_NewIntObj(length);
    if (patternLength > 0) {
	Tcl_AppendToObj(keyObj, ",", 1);
	Tcl_AppendToObj(keyObj, pattern, patternLength);
    }

    // Check to see if we have this result cached
    
    hashEntry = Tcl_FindHashEntry(dict->wordTable, Tcl_GetString(keyObj));
    if (hashEntry != NULL) {
	wordList = (Tcl_Obj *)Tcl_GetHashValue(hashEntry);
	Tcl_IncrRefCount(wordList);
    } else {
	// The result isn't cached.  Find words of the appropriate length
	// and filter them.
	wordList = getWordsMatchingLength(interp, dict, length);
	// If the list wasn't cached before, now it is.  Only add it
	// to the cache again if there was a filter.
	if (wordList != NULL) {
	    if (pattern != NULL) {
		filteredWordList = filterWordList(interp, wordList, pattern);
		Tcl_DecrRefCount(wordList);

		if (filteredWordList == NULL) {
		    Tcl_DecrRefCount(keyObj);
		    return NULL;
		}
		wordList = filteredWordList;
		Tcl_IncrRefCount(wordList);

		if ((dict->cacheTypes & DICTIONARY_PATTERN_CACHE) && pattern != NULL) {
		    int wordListLength = 0;
		    int dummy;
		    Tcl_ListObjLength(interp, wordList, &wordListLength);
		    /*
		    if (wordListLength <= 200) {
		    */
		    /*
		     * Only cache patterns with length <= 5 to speed up
		     * invalid trigram searches.  The longest trigram
		     * pattern is *abc* (to determine if a trigram exists
		     * in the middle of a word)
		     */
		    if (patternLength <= 5) {
			hashEntry = Tcl_CreateHashEntry(dict->wordTable, Tcl_GetString(keyObj), &dummy);
			Tcl_SetHashValue(hashEntry, (ClientData) wordList);
			Tcl_IncrRefCount(wordList);
		    }
		}
	    } else if (wordList == NULL) {
		Tcl_DecrRefCount(keyObj);
		return NULL;
	    }
	}
    }

    // We should have returned by now.
    Tcl_DecrRefCount(keyObj);

    return wordList;
}

static int
isIllegalTrigram(Tcl_Interp *interp, Dictionary *dict, char *trigram) {
    Tcl_Obj *wordList = (Tcl_Obj *)NULL;
    int *lengthPtr = (int *)NULL;
    char pattern[6];
    int wordListLength = 0;
    Tcl_HashEntry *hashEntry = (Tcl_HashEntry *)NULL;
    int isNewEntry = 0;
    Tcl_Obj *resultPtr = Tcl_GetObjResult(interp);

    if (trigram[0] == '\0'
	    || trigram[1] == '\0'
	    || trigram[2] == '\0') {
	Tcl_SetBooleanObj(resultPtr, 1);
	return TCL_OK;
    }

    /*
     * First check the cache.
     */
    pattern[0] = trigram[0];
    pattern[1] = trigram[1];
    pattern[2] = trigram[2];
    pattern[3] = '\0';
    if (dict->cacheTypes & DICTIONARY_TRIGRAM_CACHE) {
	hashEntry = Tcl_CreateHashEntry(dict->trigramTable, pattern, &isNewEntry);
	if (!isNewEntry) {
	    Tcl_SetObjResult(interp, (Tcl_Obj *)Tcl_GetHashValue(hashEntry));
	    return TCL_OK;
	}
    }

    if (loadAvailableLengths(interp, dict) != TCL_OK) {
	if (hashEntry) {
	    Tcl_DeleteHashEntry(hashEntry);
	}
	return TCL_ERROR;
    }

    pattern[0] = '*';
    pattern[1] = trigram[0];
    pattern[2] = trigram[1];
    pattern[3] = trigram[2];
    pattern[4] = '*';
    pattern[5] = '\0';
    lengthPtr = dict->wordLengths;
    while (*lengthPtr) {
	if (*lengthPtr >= 3) {
	    wordList = lookupByLength(interp, dict, *lengthPtr, pattern);
	    if (wordList != NULL && Tcl_ListObjLength(interp, wordList, &wordListLength) != TCL_OK) {
		if (hashEntry) {
		    Tcl_DeleteHashEntry(hashEntry);
		}
		Tcl_DecrRefCount(wordList);
		return TCL_ERROR;
	    }
	    if (wordList != NULL && wordListLength > 0) {
		if ((dict->cacheTypes & DICTIONARY_TRIGRAM_CACHE)) {
		    Tcl_Obj *boolObj = Tcl_NewBooleanObj(0);
		    Tcl_IncrRefCount(boolObj);
		    Tcl_SetHashValue(hashEntry, (ClientData) boolObj);
		}
		Tcl_DecrRefCount(wordList);
		Tcl_ResetResult(interp);
		Tcl_SetBooleanObj(Tcl_GetObjResult(interp), 0);
		return TCL_OK;
	    }
	    if (wordList != NULL) {
		Tcl_DecrRefCount(wordList);
	    }
	}
	lengthPtr++;
    }

    pattern[0] = '*';
    pattern[1] = trigram[0];
    pattern[2] = trigram[1];
    pattern[3] = '\0';
    lengthPtr = dict->wordLengths;
    while (*lengthPtr) {
	if (*lengthPtr >= 2) {
	    wordList = lookupByLength(interp, dict, *lengthPtr, pattern);
	    if (wordList != NULL && Tcl_ListObjLength(interp, wordList, &wordListLength) != TCL_OK) {
		if (hashEntry) {
		    Tcl_DeleteHashEntry(hashEntry);
		}
		Tcl_DecrRefCount(wordList);
		return TCL_ERROR;
	    }
	    if (wordList != NULL && wordListLength > 0) {
		if ((dict->cacheTypes & DICTIONARY_TRIGRAM_CACHE)) {
		    Tcl_Obj *boolObj = Tcl_NewBooleanObj(0);
		    Tcl_IncrRefCount(boolObj);
		    Tcl_SetHashValue(hashEntry, (ClientData) boolObj);
		}
		Tcl_DecrRefCount(wordList);
		Tcl_ResetResult(interp);
		Tcl_SetBooleanObj(Tcl_GetObjResult(interp), 0);
		return TCL_OK;
	    }
	    if (wordList != NULL) {
		Tcl_DecrRefCount(wordList);
	    }
	}
	lengthPtr++;
    }

    pattern[0] = trigram[1];
    pattern[1] = trigram[2];
    pattern[2] = '*';
    pattern[3] = '\0';
    lengthPtr = dict->wordLengths;
    while (*lengthPtr) {
	if (*lengthPtr >= 2) {
	    wordList = lookupByLength(interp, dict, *lengthPtr, pattern);
	    if (wordList != NULL && Tcl_ListObjLength(interp, wordList, &wordListLength) != TCL_OK) {
		if (hashEntry) {
		    Tcl_DeleteHashEntry(hashEntry);
		}
		Tcl_DecrRefCount(wordList);
		return TCL_ERROR;
	    }
	    if (wordList != NULL && wordListLength > 0) {
		if ((dict->cacheTypes & DICTIONARY_TRIGRAM_CACHE)) {
		    Tcl_Obj *boolObj = Tcl_NewBooleanObj(0);
		    Tcl_IncrRefCount(boolObj);
		    Tcl_SetHashValue(hashEntry, (ClientData) boolObj);
		}
		Tcl_DecrRefCount(wordList);
		Tcl_ResetResult(interp);
		Tcl_SetBooleanObj(Tcl_GetObjResult(interp), 0);
		return TCL_OK;
	    }
	    if (wordList != NULL) {
		Tcl_DecrRefCount(wordList);
	    }
	}
	lengthPtr++;
    }

    wordList = lookupByLength(interp, dict, 1, (char *)NULL);
    pattern[0] = trigram[1];
    pattern[1] = '\0';
    if (wordList != NULL && wordIndexInList(interp, wordList, pattern) != -1) {
	if ((dict->cacheTypes & DICTIONARY_TRIGRAM_CACHE)) {
	    Tcl_Obj *boolObj = Tcl_NewBooleanObj(0);
	    Tcl_IncrRefCount(boolObj);
	    Tcl_SetHashValue(hashEntry, (ClientData) boolObj);
	}
	Tcl_DecrRefCount(wordList);
	Tcl_ResetResult(interp);
	Tcl_SetBooleanObj(Tcl_GetObjResult(interp), 0);
	return TCL_OK;
    }

    if (dict->cacheTypes & DICTIONARY_TRIGRAM_CACHE) {
	Tcl_Obj *boolObj = Tcl_NewBooleanObj(1);
	Tcl_IncrRefCount(boolObj);
	Tcl_SetHashValue(hashEntry, (ClientData) boolObj);
    }
    Tcl_DecrRefCount(wordList);
    Tcl_ResetResult(interp);
    Tcl_SetBooleanObj(Tcl_GetObjResult(interp), 1);
    return TCL_OK;
}
