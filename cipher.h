/*
 * cipher.h --
 *
 *	This is the header file for the cipher package.  All new
 *	cipher types need to include this header file.
 *
 * Copyright (c) 1995-2000 Michael Thomas <wart@kobold.org>
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

#ifndef _CIPHER_H_INCLUDED
#define _CIPHER_H_INCLUDED

#include <stdlib.h>
#include <stdarg.h>
#include <tcl.h>

/*
 * Tcl_WideInt is used in Tcl8.4.x and later.  If we want to be able to
 * use wide integers in a portable way with earlier version of Tcl then
 * we have to define it ourself.
 */
#ifndef TCL_WIDE_INT_TYPE
typedef long long Tcl_WideInt;
#endif


#define BAD_SUB 0
#define NEW_SUB	1
#define ALT_SUB	2

#define ENCODE 1
#define DECODE 2

#define ATOZ "abcdefghijklmnopqrstuvwxyz"
#define ATOZONETONINE "abcdefghijklmnopqrstuvwxyz0123456789"
#define ATOZNOJ "abcdefghiklmnopqrstuvwxyz"
#define ONETONINE "123456789"
#define ZEROTONINE "0123456789"

#define NUMROUTES 48

#define NW_ROW_X_ROW   1 /* Row by row, left to right, top to bottom */
#define NW_ROW_X_I_ROW 2 /* Row by row, left to right then right to left */
#define NW_COL_X_COL   3 /* COL by COL, top to bottom, left to right */
#define NW_COL_X_I_COL 4 /* COL by COL, top to bottom then bottom to top */
/*
 * Normal diagonal routes.  Start on the specified side and move in the
 * direction shown.
 */
#define DIAG_W_U    5
#define DIAG_W_D    6
#define DIAG_E_U    7
#define DIAG_E_D    8
#define DIAG_N_W    9
#define DIAG_N_E    10
#define DIAG_S_W    11
#define DIAG_S_E    12
/*
 * Alternate diagonal routes.  The first row starts on the specified side
 * moving in the direction shown.  The next goes in the opposite direction
 */
#define ALT_DIAG_W_U	13
#define ALT_DIAG_W_D	14
#define ALT_DIAG_E_U	15
#define ALT_DIAG_E_D	16
#define ALT_DIAG_N_W	17
#define ALT_DIAG_N_E	18
#define ALT_DIAG_S_W	19
#define ALT_DIAG_S_E	20
/*
 * Inside spiral routes.  Start in the specified corner and more in the
 * direction shown
 */
#define I_NW_CW		21
#define I_NW_CCW	22
#define I_SW_CW		23
#define I_SW_CCW	24
#define I_NE_CW		25
#define I_NE_CCW	26
#define I_SE_CW		27
#define I_SE_CCW	28
/*
 * Outside spirals.  Like above, but start on the inside and end in
 * the specified corner.
 */

#define O_NW_CW		29
#define O_NW_CCW	30
#define O_SW_CW		31
#define O_SW_CCW	32
#define O_NE_CW		33
#define O_NE_CCW	34
#define O_SE_CW		35
#define O_SE_CCW	36

/*
 * TODO:  Move these to a more readable position
 */
#define NE_ROW_X_ROW   37 /* Row by row, right to left, top to bottom */
#define NE_ROW_X_I_ROW 38 /* Row by row, right to left then left to right */
#define NE_COL_X_COL   39 /* COL by COL, top to bottom, right to left */
#define NE_COL_X_I_COL 40 /* COL by COL, top to bottom then bottom to top */

#define SW_ROW_X_ROW   41 /* Row by row, left to right, bottom to top */
#define SW_ROW_X_I_ROW 42 /* Row by row, left to right then right to left */
#define SW_COL_X_COL   43 /* COL by COL, bottom to top, left to right */
#define SW_COL_X_I_COL 44 /* COL by COL, bottom to top then top to bottom */

#define SE_ROW_X_ROW   45 /* Row by row, left to right, bottom to top */
#define SE_ROW_X_I_ROW 46 /* Row by row, left to right then right to left */
#define SE_COL_X_COL   47 /* COL by COL, bottom to top, right to left */
#define SE_COL_X_I_COL 48 /* COL by COL, bottom to top then top to bottom */

int CipherCmd(ClientData, Tcl_Interp *, int , const char **);
int cipherid;

typedef struct {
    char *ciphertext;
    int period;
    int length;
    int id;
    int language;

    /*
     * These are used for progress meters during long operations.
     */

    char *stepCommand;
    char *bestFitCommand;
    long stepInterval;
    unsigned long curIteration;

    struct CipherType *typePtr;
} CipherItem;

int	CountValidChars _ANSI_ARGS_((CipherItem *, const char *, int *));
char *	ExtractValidChars _ANSI_ARGS_((CipherItem *, const char *));
char *	ExtractValidCharsJtoI _ANSI_ARGS_((CipherItem *, const char *));
int *	TextToInt _ANSI_ARGS_((Tcl_Interp *, CipherItem *, const char *,
	int *, const char *, int));
int	IsValidChar _ANSI_ARGS_((CipherItem *, char));
char    FindFirstDuplicate _ANSI_ARGS_((const char *inputString, const char *ignoreVals));
int	cipherSelectLanguage _ANSI_ARGS_((const char *));
char *	cipherGetLanguage _ANSI_ARGS_((int));
int	CipherSetStepCmd _ANSI_ARGS_((CipherItem *, const char *));
int	CipherSetBestFitCmd _ANSI_ARGS_((CipherItem *, const char *));
void	DeleteCipher _ANSI_ARGS_((ClientData));
int 	CipherNullEncoder _ANSI_ARGS_((Tcl_Interp *, CipherItem *,
	char *, char *));

typedef int	CipherCreateProc _ANSI_ARGS_((Tcl_Interp *, CipherItem *,
		int, const char **));
typedef void	CipherDeleteProc _ANSI_ARGS_((ClientData));
typedef int	CipherCmdProc _ANSI_ARGS_((ClientData, Tcl_Interp *,
		int, const char **));
typedef char *	GetPlaintextProc _ANSI_ARGS_((Tcl_Interp *, CipherItem *));
typedef int	SetCiphertextProc _ANSI_ARGS_((Tcl_Interp *, CipherItem *,
		const char *));
typedef int	SolveCiphertextProc _ANSI_ARGS_((Tcl_Interp *, CipherItem *,
		char *));
typedef int	RestoreCiphertextProc _ANSI_ARGS_((Tcl_Interp *, CipherItem *,
		const char *, const char *));
typedef int	LocateTipProc _ANSI_ARGS_((Tcl_Interp *, CipherItem *,
		const char *, const char *));
typedef int	SubstituteProc _ANSI_ARGS_((Tcl_Interp *, CipherItem *,
		const char *, const char *, int));
typedef int	UndoProc _ANSI_ARGS_((Tcl_Interp *, CipherItem *,
		const char *, int));
typedef int	EncodeProc _ANSI_ARGS_((Tcl_Interp *, CipherItem *,
		const char *, const char *));

typedef struct CipherType {
    char *type;				/* name of cipher type */
    char *valid_chars;			/* valid characters for cipher */
    int size;				/* size of container struct */
    CipherCreateProc *createProc;
    CipherDeleteProc *deleteProc;
    CipherCmdProc *cmdProc;
    GetPlaintextProc *decipherProc;
    SetCiphertextProc *setctProc;
    SolveCiphertextProc *solveProc;
    RestoreCiphertextProc *restoreProc;
    LocateTipProc *locateProc;
    SubstituteProc *subProc;
    UndoProc *undoProc;
    EncodeProc *encodeProc;
    struct CipherType *nextPtr;
} CipherType;

#endif /* _CIPHER_H_INCLUDED */
