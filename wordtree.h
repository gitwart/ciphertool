/*
 * wordtree.c --
 *
 *	This file implements methods for managing a word tree.
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


#ifndef _WORDTREE_INCLUDED

typedef struct TreeNode {
    char val;
    unsigned short int measure;
    struct TreeNode **next;
} TreeNode;

void addWordToTree(TreeNode *root, char *string, unsigned short int measure);
void deleteWordTree(TreeNode *node);
TreeNode *createWordTreeRoot(void);
int treeContainsWord(TreeNode *root, char *word, unsigned short int *measure, unsigned int length);
int treeMatchString(TreeNode *root, char *word, unsigned short int *measure);
int isEmptyTree(TreeNode *root);

#define _WORDTREE_INCLUDED

#endif
