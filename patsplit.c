/*
 * Returns true if the string of (len) characters starting at s form a
 * known word.
 */
int
isWord(char *s, int len) {
    if (len < 1) {
	return 0;
    }

    return 1;
}

/*
 * Returns zero if a valid word could not be found.
 */
int
findWords(char *s, int *wordLen) {
    /*
     * Termination condition.
     */

    if (s[0] == NULL) {
	/*
	 * We've found valid words all the way to the end.  Great!
	 */
	return 1;
    }

    /*
     * Look for more words.
     */

    for (length=1; length < MAXWORDLENGTH && s[length] != NULL; length++) {
	if (isWord(s, length)) {
	    *wordLen = length;
	    return findWords(s+length, wordLen+1);
	}
    }

    /*
     * Another termination condition.
     * No valid words found at this position.
     */
    return 0;
}
