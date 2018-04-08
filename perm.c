/*===================================================================*/
/* C program for distribution from the Combinatorial Object Server.  */
/* Generate permutations by transposing adjacent elements            */
/* via the Steinhaus-Johnson-Trotter algorithm.  This is             */
/* the same version used in the book "Combinatorial Generation."     */
/* Both the permutation (in one-line notation) and the positions     */
/* being transposed (as a 2-cycle) are output.                       */
/* The program can be modified, translated to other languages, etc., */
/* so long as proper acknowledgement is given (author and source).   */  
/* Programmer: Frank Ruskey, 1995.                                   */
/* The latest version of this program may be found at the site       */
/* http://sue.uvic.ca/~cos/inf/perm/PermInfo.html                    */
/*===================================================================*/

/*
 * Original code for this was borrowed from the above.  It has been
 * modified and simplified to work with the rest of the code
 * in the cipher software package.
 *
 * Modified by wart@kobold.org for use with the cipher
 * software.
 */

#include <perm.h>
#include <string.h>

#include <cipherDebug.h>

typedef struct PermInfo {
    int length;
    int *dir;
    int *p;
    int *pi;
    char *cmd_prefix;
    int (*testFunc)(Tcl_Interp *, ClientData, int *, int);
} PermInfo;

int
_internalDoPerm(Tcl_Interp *interp, ClientData clientData, int n, PermInfo *pInfo)
{
    int i, result;

    if (n >= pInfo->length) {
	return pInfo->testFunc(interp, clientData, pInfo->p, pInfo->length);
    } else {
	result = _internalDoPerm(interp, clientData, n+1, pInfo);
	if (result != TCL_OK) {
	    return result;
	}
	for (i=0; i<n; ++i) {
	    int z;
	    /*
	     * Move(n, dir[n]);
	     */
	    z = pInfo->p[pInfo->pi[n]+pInfo->dir[n]];
	    pInfo->p[pInfo->pi[n]] = z;
	    pInfo->p[pInfo->pi[n]+pInfo->dir[n]] = n;
	    pInfo->pi[z] = pInfo->pi[n];
	    pInfo->pi[n] = pInfo->pi[n] + pInfo->dir[n];

	    result = _internalDoPerm(interp, clientData, n+1, pInfo);
	    if (result != TCL_OK) {
		return result;
	    }
	}
	pInfo->dir[n] = -pInfo->dir[n];
    }

    return TCL_OK;
}

/*
 * Call this to perform a search of all permutations of a list
 * of integers.  The given command is called whenever a new permutation
 * is computed.  Using this routine is faster than PermCmd because
 * PermCmd calls Tcl_Eval for every permutation, whereas this will
 * call a user-defined C function for every permutation.
 */

int
_internalDoPermCmd(ClientData clientData, Tcl_Interp *interp, int n, int (*testFunc)(Tcl_Interp *, ClientData, int *, int))
{
    PermInfo pInfo;
    int i, result;

    if (n <= 1) {
	Tcl_SetResult(interp, "Length of permuted array must be > 1\n", TCL_STATIC);
	return TCL_ERROR;
    }

    pInfo.length = n;
    pInfo.dir = (int *)ckalloc(sizeof(int) * (n + 1));
    pInfo.p = (int *)ckalloc(sizeof(int) * (n + 1));
    pInfo.pi = (int *)ckalloc(sizeof(int) * (n + 1));
    pInfo.cmd_prefix = (char *)NULL;
    pInfo.testFunc = testFunc;

    for(i=0; i < n; i++) {
	pInfo.dir[i] = -1;
	pInfo.p[i] = i;
	pInfo.pi[i] = i;
    }

    result = _internalDoPerm(interp, clientData, 0, &pInfo);

    ckfree((char *)pInfo.dir);
    ckfree((char *)pInfo.p);
    ckfree((char *)pInfo.pi);

    return result;
}

/*
 * Function called by PermCmd.  This does all of the work.
 */

int
doPerm (Tcl_Interp *interp, int n, PermInfo *pInfo)
{
    int i, result;

    if (n >= pInfo->length) {
	char elem[8];
	Tcl_DString dsPtr;

	Tcl_DStringInit(&dsPtr);
	Tcl_DStringAppend(&dsPtr, pInfo->cmd_prefix, -1);
	Tcl_DStringStartSublist(&dsPtr);
	for(i=0; i < pInfo->length; i++) {
	    sprintf(elem, "%d", pInfo->p[i]);
	    Tcl_DStringAppendElement(&dsPtr, elem);
	}
	Tcl_DStringEndSublist(&dsPtr);

	return Tcl_Eval(interp, Tcl_DStringValue(&dsPtr));
    } else {
	result = doPerm(interp, n+1, pInfo);
	if (result != TCL_OK) {
	    return result;
	}

	for (i=0; i<n; ++i) {
	    int z;
	    /*
	     * Move(n, dir[n]);
	     */
	    z = pInfo->p[pInfo->pi[n]+pInfo->dir[n]];
	    pInfo->p[pInfo->pi[n]] = z;
	    pInfo->p[pInfo->pi[n]+pInfo->dir[n]] = n;
	    pInfo->pi[z] = pInfo->pi[n];
	    pInfo->pi[n] = pInfo->pi[n] + pInfo->dir[n];

	    result = doPerm(interp, n+1, pInfo);
	    if (result != TCL_OK) {
		return result;
	    }
	}
	pInfo->dir[n] = -pInfo->dir[n];
    }

    return TCL_OK;
}

/*
 * Usage:  permute n cmdPrefix
 */

int
PermCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    int n, i, result;
    PermInfo pInfo;

    if (argc != 3) {
	Tcl_SetResult(interp, "Usage:  permute n cmd", TCL_STATIC);
	return TCL_ERROR;
    }

    if (sscanf(argv[1], "%d", &n) != 1) {
	Tcl_SetResult(interp, "n must be an integer\n", TCL_STATIC);
	return TCL_ERROR;
    }

    pInfo.length = n;
    pInfo.dir = (int *)ckalloc(sizeof(int) * (n + 1));
    pInfo.p = (int *)ckalloc(sizeof(int) * (n + 1));
    pInfo.pi = (int *)ckalloc(sizeof(int) * (n + 1));
    pInfo.cmd_prefix = (char *)ckalloc(sizeof(char)*strlen(argv[2])+2);
    strcpy(pInfo.cmd_prefix, argv[2]);

    for(i=0; i < n; i++) {
	pInfo.dir[i] = -1;
	pInfo.p[i] = i;
	pInfo.pi[i] = i;
    }

    result = doPerm(interp, 0, &pInfo);

    ckfree((char *)pInfo.cmd_prefix);
    ckfree((char *)pInfo.dir);
    ckfree((char *)pInfo.p);
    ckfree((char *)pInfo.pi);

    return result;
}
