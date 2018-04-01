/*
 * score.h --
 *
 *	This is the header file for the plaintext score types.  All new
 *	scoring type must include this header file.
 *
 * Copyright (c) 2004-2008 Michael Thomas <wart@kobold.org>
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

#ifndef _SCORE_H_INCLUDED
#define _SCORE_H_INCLUDED

#include <tcl.h>
#include <wordtree.h>

/*
 * A counter used to generate unique score command names.
 */
int scoreid;

typedef struct {
    int elemSize;
    unsigned short int initialized;
    struct ScoreType *typePtr;
} ScoreItem;

#define DigramSingleValue(a, b, c) ( c[(unsigned char)a][(unsigned char)b] )

int ScoreMethodCmd	_ANSI_ARGS_((ClientData, Tcl_Interp *, int, const char **));

void	AddInternalScore _ANSI_ARGS_((ScoreItem *));
void	DeleteScoreCommand _ANSI_ARGS_((ClientData));
int	InitScoreTypes _ANSI_ARGS_((Tcl_Interp *));
int	NullScoreNormalizer _ANSI_ARGS_((Tcl_Interp *, ScoreItem *));
int	DumpScoreTable _ANSI_ARGS_((Tcl_Interp *, ScoreItem *, char *));
int	ScoreCmd _ANSI_ARGS_((ClientData, Tcl_Interp *, int, const char **));
void	DeleteScore _ANSI_ARGS_((ClientData));
int     DumpTreeNode _ANSI_ARGS_((Tcl_Interp *, TreeNode *, Tcl_DString *, Tcl_DString *, int));
double	DigramStringValue _ANSI_ARGS_((const char *, double **));
double	DigramSingleValue _ANSI_ARGS_((unsigned char, unsigned char, double **));
int  DefaultScoreValue _ANSI_ARGS_((Tcl_Interp *, const char *, double *));
int  DefaultScoreElementValue _ANSI_ARGS_((Tcl_Interp *, const char *, double *));

typedef int	ScoreCommandProc _ANSI_ARGS_((ClientData, Tcl_Interp *,
		int, const char **));
typedef int	ScoreCreateProc	_ANSI_ARGS_((Tcl_Interp *, ScoreItem *,
		int, const char **));
typedef void	ScoreDeleteProc _ANSI_ARGS_((ClientData));
typedef int	ScoreAddProc	_ANSI_ARGS_((Tcl_Interp *, ScoreItem *,
		const char *, double));
typedef double	ScoreValueProc  _ANSI_ARGS_((Tcl_Interp *, ScoreItem *,
		const char *));
typedef double	ScoreElementValueProc	_ANSI_ARGS_((Tcl_Interp *, ScoreItem *,
		const char *));
typedef int	ScoreNormalizeProc	_ANSI_ARGS_((Tcl_Interp *,
		ScoreItem *));
typedef int	ScoreDumpProc	_ANSI_ARGS_((Tcl_Interp *, ScoreItem *,
		const char *));

typedef struct ScoreType {
    char *type;				/* Name of scoring type */
    int size;				/* size of the container struct */
    ScoreCreateProc *createProc;
    ScoreAddProc *addProc;
    ScoreValueProc *valueProc;
    ScoreElementValueProc *elemValueProc;
    ScoreNormalizeProc *normalProc;
    ScoreDeleteProc *deleteProc;
    ScoreDumpProc *dumpProc;
    ScoreCommandProc *cmdProc;
    struct ScoreType *nextPtr;
} ScoreType;


#endif /* _SCORE_H_INCLUDED */
