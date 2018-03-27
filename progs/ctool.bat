@echo off

rem This batch file attempts to find a Tcl/Tk interpreter
rem and the 'ctool' file to run in that interpreter.
rem A script like this should be unnecessary in unix since you can enter
rem ctool
rem which should do the same thing as this script.
rem A better way of identifying the Tcl/Tk interpreter is probably possible.

rem Find the version of wish on the computer.
rem The order here is important.
rem In user installs, only the first path will be found.
rem In development environments, one of the others may be found.
rem
rem RCS: @(#) $Id: ctool.bat,v 1.3 2004/09/08 16:57:49 wart Exp $

set WISHPROG=""
if exist C:\Tcl\bin\wish.exe set WISHPROG=C:\tcl\bin\wish
if exist wish84g.exe set WISHPROG=wish84g
if exist wish84.exe set WISHPROG=wish84
if exist wish.exe set WISHPROG=wish

rem Find ctool on the computer.
set CTOOLPROG=""
if exist ctool set CTOOLPROG=ctool

rem Report errors.
rem Don't leave the script yet, since we want to report
rem all the errors we can before leaving.
if %WISHPROG% == "" (
  echo Error: No version of the 'wish' Tcl/Tk interpreter environment could be found.
)
if %CTOOLPROG% == "" (
  echo Error: The file 'ctool' could not be found.
)

rem Quit if we have found an error.
rem We've already told the user about all the errors we've found.
if %WISHPROG% == "" goto end
if %CTOOLPROG% == "" goto end

@echo on
%WISHPROG% %CTOOLPROG%
@echo off

:end
