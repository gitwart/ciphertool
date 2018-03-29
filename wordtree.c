/*
 * wordtree.c --
 *
 *	This file implements methods for managing a word tree.
 *
 * Copyright (c) 2003-2004 Michael Thomas <wart@kobold.org>
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

#include <stdlib.h>
#include <wordtree.h>
#include <cipherDebug.h>

TreeNode NullNode = {'\0', 0, (TreeNode **)NULL};

static TreeNode *createWordTreeNode(char val);

void addWordToTree(TreeNode *root, const char *string, unsigned short int measure) {
    TreeNode *newNode;
    TreeNode **newNextPtr;
    int count;
    int i;

#ifdef USE_DMALLOC
    if (dmalloc_verify(NULL) == DMALLOC_VERIFY_ERROR) {
	abort();
    }
#endif
    /*
     * Initialize the children of this node if it's not already been done.
     */
    if (root->next == NULL) {
	root->next = (TreeNode **)malloc(sizeof(TreeNode *));
	root->next[0] = (TreeNode *)NULL;
    }
#ifdef USE_DMALLOC
    if (dmalloc_verify(NULL) == DMALLOC_VERIFY_ERROR) {
	abort();
    }
#endif

    /*
     * Check to see if the next character in the string has already
     * been added to the tree.
     */
    for (count=0; root->next[count]; count++) {
	if (root->next[count]->val == string[0]) {
	    if (string[0] == '\0') {
		root->measure += measure;
	    } else {
		addWordToTree(root->next[count], string+1, measure);
	    }
	    return;
	}
    }

#ifdef USE_DMALLOC
    if (dmalloc_verify(NULL) == DMALLOC_VERIFY_ERROR) {
	abort();
    }
#endif

    // We can only get here if the root node doesn't have
    // an entry for the first character in the string.
    newNode = createWordTreeNode(string[0]);
    if (string[0] == '\0') {
	root->measure += measure;
    }

    // Add the new node to the current node's next list.
    newNextPtr = (TreeNode **)malloc(sizeof(TreeNode *) * (count+2));
#ifdef USE_DMALLOC
    if (dmalloc_verify(NULL) == DMALLOC_VERIFY_ERROR) {
	abort();
    }
#endif
    for(i=0; i < count; i++) {
	newNextPtr[i] = root->next[i];
    }
#ifdef USE_DMALLOC
    if (dmalloc_verify(NULL) == DMALLOC_VERIFY_ERROR) {
	abort();
    }
#endif
    newNextPtr[count] = newNode;
    newNextPtr[count+1] = (TreeNode *)NULL;
#ifdef USE_DMALLOC
    if (dmalloc_verify(NULL) == DMALLOC_VERIFY_ERROR) {
	abort();
    }
#endif
    if ((root->next) != NULL) {
	free((char *)root->next);
    }
#ifdef USE_DMALLOC
    if (dmalloc_verify(NULL) == DMALLOC_VERIFY_ERROR) {
	abort();
    }
#endif
    root->next = newNextPtr;
#ifdef USE_DMALLOC
    if (dmalloc_verify(NULL) == DMALLOC_VERIFY_ERROR) {
	abort();
    }
#endif

    if (string[0] != '\0') {
	addWordToTree(newNode, string+1, measure);
    }
#ifdef USE_DMALLOC
    if (dmalloc_verify(NULL) == DMALLOC_VERIFY_ERROR) {
	abort();
    }
#endif
}

static TreeNode *createWordTreeNode(char val) {
    TreeNode *newNode;

    if (val == '\0') {
	return &NullNode;
    }

#ifdef USE_DMALLOC
    if (dmalloc_verify(NULL) == DMALLOC_VERIFY_ERROR) {
	abort();
    }
#endif
    newNode = (TreeNode *)malloc(sizeof(TreeNode));
    newNode->val = val;
    newNode->measure = 0;
    newNode->next = (TreeNode **)NULL;
#ifdef USE_DMALLOC
    if (dmalloc_verify(NULL) == DMALLOC_VERIFY_ERROR) {
	abort();
    }
#endif

    return newNode;
}

void deleteWordTree(TreeNode *node) {
    int i;

#ifdef USE_DMALLOC
    if (dmalloc_verify(NULL) == DMALLOC_VERIFY_ERROR) {
	abort();
    }
#endif
    if (node->next != NULL) {
	for(i=0; node->next[i]; i++) {
	    if (node->next[i] != &NullNode) {
		deleteWordTree(node->next[i]);
//		free((char *) node->next[i]);
	    }
	}
#ifdef USE_DMALLOC
    if (dmalloc_verify(NULL) == DMALLOC_VERIFY_ERROR) {
	abort();
    }
#endif
	free((char *) (node->next));
#ifdef USE_DMALLOC
    if (dmalloc_verify(NULL) == DMALLOC_VERIFY_ERROR) {
	abort();
    }
#endif
    }
    node->next = NULL;

    free((char *)node);
}

int treeMatchString(TreeNode *node, const char *word, unsigned short int *measure) {
    int i;
    int result = 0;
    int foundWordEnd = 0;

    *measure = node->measure;

    if (node->next == NULL) {
	*measure = 0;
	return -1;
    }

    for(i=0; node->next[i]; i++) {
	if (node->next[i] == &NullNode) {
	    foundWordEnd = 1;
	}
	if (node->next[i]->val == word[0]) {
	    if (word[0] == '\0') {
		return 0;
	    } else {
		result = treeMatchString(node->next[i], word+1, measure);
		if (result != -1) {
		    return result+1;
		}
	    }
	}
    }

    if (foundWordEnd) {
	return 0;
    } else {
	*measure = 0;
	return -1;
    }
}

int treeContainsWord(TreeNode *node, const char *word, unsigned short int *measure, unsigned int length) {
    int i;
    int result = 0;

    if (node->next == NULL) {
	return 0;
    }

    for(i=0; node->next[i]; i++) {
	if (node->next[i]->val == word[0] || (node->next[i]->val == NULL && length == 0)) {
	    if (word[0] == '\0' || length <= 0 ) {
		*measure = node->measure;
		return 1;
	    } else {
		result = treeContainsWord(node->next[i], word+1, measure, length-1);
		return result;
	    }
	}
    }

    return 0;
}

int isEmptyTree(TreeNode *node) {
    if (node->next == NULL) {
	return 1;
    } else {
	return 0;
    }
}

TreeNode *createWordTreeRoot() {
#ifdef USE_DMALLOC
    if (dmalloc_verify(NULL) == DMALLOC_VERIFY_ERROR) {
	abort();
    }
#endif
    return createWordTreeNode('0');
#ifdef USE_DMALLOC
    if (dmalloc_verify(NULL) == DMALLOC_VERIFY_ERROR) {
	abort();
    }
#endif
}
