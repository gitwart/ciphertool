#
# Makefile.  Generated from Makefile.in by configure.
#

#========================================================================
# The object files are used for linking into the final library.
#========================================================================

GENERIC_OBJECTS = cipherInit.o \
	cipherUtil.o \
	cipher.o \
	hillclimb.o \
	stat.o \
	digram.o \
	keygen.o \
	vigTypes.o \
	crithmCmd.o \
	morseCommand.o \
	morse.o \
	perm.o \
	score.o \
	digramScore.o \
	trigramScore.o \
	ngramScore.o \
	wordtreeScore.o \
	wordtree.o \
	wordtreeCmd.o \
	dictionary.o \
	dictionaryCmds.o \
	dictionaryInit.o \
	amsco.o \
	aristocrat.o \
	bacon.o \
	bazeries.o \
	bifid.o \
	bigbifid.o \
	cadenus.o \
	caesar.o \
	columnar.o \
	digrafid.o \
	fmorse.o \
	grandpre.o \
	grille.o \
	gromark.o \
	homophonic.o \
	morbit.o \
	myszcowski.o \
	nicodemus.o \
	nitrans.o \
	phillips.o \
	playfair.o \
	pollux.o \
	quagmire.o \
	ragbaby.o \
	railfence.o \
	route.o \
	swagman.o \
	trifid.o \
	twosquare.o \
	vvb.o

script_PROGRAMS=\
	$(srcdir)/progs/checkerboard2pat \
	$(srcdir)/progs/ctool \
	$(srcdir)/progs/ctool.bat \
	$(srcdir)/progs/dumproute \
	$(srcdir)/progs/key2col \
	$(srcdir)/progs/csolve \
	$(srcdir)/progs/bazsol \
	$(srcdir)/progs/genboard \
	$(srcdir)/progs/genscores \
	$(srcdir)/progs/grandpresol \
	$(srcdir)/progs/hillclimb \
	$(srcdir)/progs/histogram \
	$(srcdir)/progs/ioc \
	$(srcdir)/progs/kasiski \
	$(srcdir)/progs/k3search \
	$(srcdir)/progs/k4search \
	$(srcdir)/progs/keysearch \
	$(srcdir)/progs/keysquaresearch \
	$(srcdir)/progs/lethist \
	$(srcdir)/progs/makedictionary \
	$(srcdir)/progs/nicsolve \
	$(srcdir)/progs/patsearch \
	$(srcdir)/progs/rot \
	$(srcdir)/progs/solvemysz \
	$(srcdir)/progs/tkcrithm \
	$(srcdir)/progs/trifidkeysearch \
	$(srcdir)/progs/txt2crithm

SCRIPT_FILES = $(srcdir)/library/aristocrat.tcl \
	$(srcdir)/library/baconian.tcl \
	$(srcdir)/library/beaufort.tcl \
	$(srcdir)/library/bifid.tcl \
	$(srcdir)/library/cadenus.tcl \
	$(srcdir)/library/columnar.tcl \
	$(srcdir)/library/crithm.tcl \
	$(srcdir)/library/crithm_gui.tcl \
	$(srcdir)/library/ctool.tcl \
	$(srcdir)/library/ctool_inputs.tcl \
	$(srcdir)/library/dictionary.tcl \
	$(srcdir)/library/digramcountData.tcl \
	$(srcdir)/library/digramlogData.tcl \
	$(srcdir)/library/digramcountData_gaines.tcl \
	$(srcdir)/library/digramlogData_gaines.tcl \
	$(srcdir)/library/4gramlogData.tcl \
	$(srcdir)/library/fmorse.tcl \
	$(srcdir)/library/geneticPerm.tcl \
	$(srcdir)/library/grandpre.tcl \
	$(srcdir)/library/grille.tcl \
	$(srcdir)/library/gronsfeld.tcl \
	$(srcdir)/library/hillclimb.tcl \
	$(srcdir)/library/hillclimbCiphers.tcl \
	$(srcdir)/library/homophonic.tcl \
	$(srcdir)/library/k3board.tcl \
	$(srcdir)/library/keyphrase.tcl \
	$(srcdir)/library/morbit.tcl \
	$(srcdir)/library/myszcowski.tcl \
	$(srcdir)/library/nitrans.tcl \
	$(srcdir)/library/patword.tcl \
	$(srcdir)/library/patwordui.tcl \
	$(srcdir)/library/pollux.tcl \
	$(srcdir)/library/porta.tcl \
	$(srcdir)/library/railfence.tcl \
	$(srcdir)/library/scoredata.tcl \
	$(srcdir)/library/scoretypes.tcl \
	$(srcdir)/library/swagman.tcl \
	$(srcdir)/library/trigramcountData.tcl \
	$(srcdir)/library/trigramlogData.tcl \
	$(srcdir)/library/utils.tcl \
	$(srcdir)/library/variant.tcl \
	$(srcdir)/library/vigenere.tcl

PKG_OBJECTS	= $(GENERIC_OBJECTS) 
PKG_SHELL_OBJECTS = $(PKG_OBJECTS) tclAppInit.o
# This is used for generating documentation
cipher_PACKAGES = cipher Crithm CipherUtil Dictionary Scoredata Hillclimb

#========================================================================
# This is a list of public header files to be installed, if any.
#========================================================================

PKG_HEADERS	=

#========================================================================
# "PKG_LIB_FILE" refers to the library (dynamic or static as per
# configuration options) composed of the named objects.
#========================================================================

PKG_LIB_FILE	= libcipher1.6.2.so
PKG_STUB_LIB_FILE = libcipherstub1.6.2.a

EXE_BINARIES    = $(PKG_SHELL) \
                  solvemysz \
                  solver \
                  lethist

BINARIES	= $(PKG_LIB_FILE) $(EXE_BINARIES)

SHELL		= /bin/sh

srcdir		= .
prefix		= /usr
exec_prefix	= /usr

bindir		= ${exec_prefix}/bin
datadir		= ${prefix}/share
libdir		= ${exec_prefix}/lib
docdir		= ${prefix}/share/doc/cipher-1.6.2
includedir	= ${prefix}/include

DESTDIR		=

PKG_DIR		= $(PACKAGE_NAME)$(PACKAGE_VERSION)
pkglibdir	= $(libdir)/$(PKG_DIR)
pkgdatadir	= $(datadir)/$(PKG_DIR)

top_builddir	= .

INSTALL		= /usr/bin/install -c
INSTALL_PROGRAM	= ${INSTALL}
INSTALL_DATA	= ${INSTALL} -m 644
INSTALL_SCRIPT	= ${INSTALL}

CVSPACKAGE_NAME	= ciphertool
PACKAGE_NAME	= cipher
PACKAGE_VERSION	= 1.6.2
CC		= gcc -pipe
CFLAGS_DEFAULT	= $(CFLAGS_OPTIMIZE)
CFLAGS_WARNING	= -Wall -Wno-implicit-int
CLEANFILES	= pkgIndex.tcl
DMALLOC_LIBS    = 
EXEEXT		= 
LDFLAGS_DEFAULT	= $(LDFLAGS)
MAKE_LIB	= ${SHLIB_LD} -o $@ $(PKG_OBJECTS) ${SHLIB_LD_LIBS} 
MAKE_SHARED_LIB	= ${SHLIB_LD} -o $@ $(PKG_OBJECTS) ${SHLIB_LD_LIBS}
MAKE_STATIC_LIB	= ${STLIB_LD} $@ $(PKG_OBJECTS)
MAKE_STUB_LIB	= ${STLIB_LD} $@ $(PKG_STUB_OBJECTS)
OBJEXT		= o
RANLIB		= :
RANLIB_STUB	= ranlib
SHLIB_CFLAGS	= -fPIC
SHLIB_LD	= gcc -pipe -shared
SHLIB_LD_LIBS	= ${LIBS} -L/usr/lib64 -ltclstub8.5
STLIB_LD	= ${AR} cr
TCL_SRC_DIR	= /usr/include/tcl-private
TCL_BIN_DIR	= /usr/lib64
TK_SRC_DIR	= @TK_SRC_DIR@
TK_BIN_DIR	= @TK_BIN_DIR@

# Not used by sample, but retained for reference of what Tcl required
TCL_LIBS	= ${DL_LIBS} ${LIBS} ${MATH_LIBS}
TK_LIBS		= @TK_LIBS@

TCL_LIB_SPEC    = -L/usr/lib64 -ltcl8.5
TCL_STUB_LIB_SPEC    = -L/usr/lib64 -ltclstub8.5

#========================================================================
# TCLLIBPATH seeds the auto_path in Tcl's init.tcl so we can test our
# package without installing.  The other environment variables allow us
# to test against an uninstalled Tcl.  Add special env vars that you
# require for testing here (like TCLX_LIBRARY).
#========================================================================

EXTRA_PATH	= $(top_builddir):$(TCL_BIN_DIR):$(TK_BIN_DIR)
TCLSH_ENV	= TCL_LIBRARY="`echo $(TCL_SRC_DIR)/library`" \
		  TK_LIBRARY="`echo $(TK_SRC_DIR)/library`" \
		  TILE_LIBRARY="`echo $(srcdir)/library`" \
		  LD_LIBRARY_PATH="$(EXTRA_PATH):$(LD_LIBRARY_PATH)" \
		  PATH="$(EXTRA_PATH):$(PATH)" \
		  TCLLIBPATH="$(top_builddir)"
TCLSH_PROG	= /usr/bin/tclsh8.5
WISH_PROG	= @WISH_PROG@
TCLSH		= $(TCLSH_ENV) $(TCLSH_PROG)
WISH		= $(TCLSH_ENV) $(WISH_PROG)
PKG_SHELL       = tcipher

# The local includes must come first, because the TK_XINCLUDES can be
# just a comment
INCLUDES	=  -I. -I"." \
		  -I"/usr/include"

EXTRA_CFLAGS	= 

DEFS		= -DPACKAGE_NAME=\"cipher\" -DPACKAGE_TARNAME=\"cipher\" -DPACKAGE_VERSION=\"1.6.2\" -DPACKAGE_STRING=\"cipher\ 1.6.2\" -DPACKAGE_BUGREPORT=\"\" -DHAVE_GETENV=1 -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -DHAVE_LIMITS_H=1 -DHAVE_SYS_PARAM_H=1 -DUSE_THREAD_ALLOC=1 -D_REENTRANT=1 -D_THREAD_SAFE=1 -DTCL_THREADS=1 -D_LARGEFILE64_SOURCE=1 -DTCL_WIDE_INT_IS_LONG=1 -D_LARGEFILE64_SOURCE=1 -DTCL_WIDE_INT_IS_LONG=1 -DUSE_TCL_STUBS=1 -DBUILD_cipher=1 $(EXTRA_CFLAGS)

CONFIG_CLEAN_FILES = Makefile

CPPFLAGS	= 
LIBS		=   -lieee -lm
AR		= ar
CFLAGS		= -g -O2 ${CFLAGS_DEFAULT} ${CFLAGS_WARNING} ${SHLIB_CFLAGS}
COMPILE		= $(CC) $(DEFS) $(INCLUDES) $(CPPFLAGS) $(CFLAGS)

VPATH = $(srcdir)/generic:$(srcdir)/win:$(srcdir)/macosx

all: package binaries libraries doc

package: $(PKG_LIB_FILE) pkgIndex.tcl

binaries: $(EXE_BINARIES)

libraries:

#
# Installation rules:
#

install : install-libraries install-doc

install-libraries: libraries install-lib-binaries
	mkdir -p $(DESTDIR)$(pkglibdir)
	mkdir -p $(DESTDIR)$(bindir)
	@echo "Installing script files in $(DESTDIR)$(pkglibdir)"
	@for i in $(SCRIPT_FILES) ; do \
	    $(INSTALL_DATA) $$i $(DESTDIR)$(pkglibdir) ; \
	done;
	@echo "Installing script programs in $(DESTDIR)$(bindir)"
	@for i in $(script_PROGRAMS) ; do \
	    $(INSTALL_SCRIPT) $$i $(DESTDIR)$(bindir) ; \
	done;
	cd $(DESTDIR)$(pkglibdir) && ( echo \
	  pkg_mkIndex . \;\
	  exit; ) | \
	$(TCLSH_PROG)

install-lib-binaries:
	mkdir -p $(DESTDIR)$(pkglibdir) $(DESTDIR)$(bindir)
	@list='$(PKG_LIB_FILE)'; for p in $$list; do \
	  if test -f $$p; then \
	    ext=`echo $$p|sed -e "s/.*\.//"`; \
	    if test "x$$ext" = "xdll"; then \
	        echo " $(INSTALL_PROGRAM) $$p $(bindir)/$$p"; \
	        $(INSTALL_PROGRAM) $$p $(bindir)/$$p; \
		lib=`basename $$p|sed -e 's/.[^.]*$$//'`.lib; \
		if test -f $$lib; then \
		    echo " $(INSTALL_DATA) $$lib $(DESTDIR)$(libdir)/$$lib"; \
	            $(INSTALL_DATA) $$lib $(DESTDIR)$(libdir)/$$lib; \
		fi; \
	    fi; \
            echo " $(INSTALL_PROGRAM) $$p $(DESTDIR)$(pkglibdir)/$$p"; \
            $(INSTALL_PROGRAM) $$p $(DESTDIR)$(pkglibdir)/$$p; \
	  else :; fi; \
	done
	@list='$(bin_PROGRAMS)'; for p in $$list; do \
	    echo "$(INSTALL_PROGRAM) $$p $(DESTDIR)$(bindir)" ; \
	    $(INSTALL_PROGRAM) $$p $(DESTDIR)$(bindir) ; \
	done
	@list='$(lib_BINARIES)'; for p in $$list; do \
	  if test -f $$p; then \
	    echo " $(RANLIB) $(DESTDIR)$(bindir)/$$p"; \
	    $(RANLIB) $(DESTDIR)$(bindir)/$$p; \
	  else :; fi; \
	done

# Test section.
# 

TESTLOAD	= -load "load ./$(PKG_LIB_FILE)"
TESTFLAGS	= 

# Piping to cat is necessary on Windows to see the output, and
# harmless on Unix

#test: binaries libraries
#	$(TCLSH) `echo $(srcdir)/tests/all.tcl` $(TESTLOAD) $(TESTFLAGS) | cat

pkgIndex.tcl: $(PKG_LIB_FILE)
	( echo \
	  pkg_mkIndex . $(PKG_LIB_FILE) $(srcdir)/library/*.tcl \;\
	  exit; ) | \
	$(TCLSH_PROG)

test: $(PKG_LIB_FILE) pkgIndex.tcl
	TCL_LIBRARY=$(TCL_LIBRARY_DIR) \
	LD_LIBRARY_PATH=$(BUILD_DIR):$(TCL_BIN_DIR):$(LD_LIBRARY_PATH) \
	TCLLIBPATH=. \
	PATH="$(BUILD_DIR)":"$(TCL_BIN_DIR)/../bin":"$(TCL_BIN_DIR)":"$(PATH)" \
	$(TCLSH_PROG) `echo $(srcdir)/tests/all.tcl` $(TESTFLAGS)

doc: $(PKG_LIB_FILE) pkgIndex.tcl
	mkdir -p doc
	TCL_LIBRARY=$(TCL_LIBRARY_DIR) \
	LD_LIBRARY_PATH=$(BUILD_DIR):$(TCL_BIN_DIR):$(LD_LIBRARY_PATH) \
	TCLLIBPATH=. \
	PATH="$(BUILD_DIR)":"$(TCL_BIN_DIR)/../bin":"$(TCL_BIN_DIR)":"$(PATH)" \
	$(TCLSH_PROG) $(srcdir)/doc/gendocs.tcl $(srcdir)/doc doc 1>/dev/null
	@for i in $(cipher_PACKAGES) ; do \
	    mkdir -p doc/$$i ; \
	    TCL_LIBRARY=$(TCL_LIBRARY_DIR) \
	    LD_LIBRARY_PATH=$(BUILD_DIR):$(TCL_BIN_DIR):$(LD_LIBRARY_PATH) \
	    TCLLIBPATH=. \
	    PATH="$(BUILD_DIR)":"$(TCL_BIN_DIR)/../bin":"$(TCL_BIN_DIR)":"$(PATH)" \
	    $(TCLSH_PROG) $(srcdir)/doc/gendocs.tcl $(srcdir)/doc/$$i doc/$$i 1>/dev/null ; \
	done;

install-doc: doc
	mkdir -p $(DESTDIR)$(docdir)
	for i in doc/*.html ; do \
	    $(INSTALL_DATA) $$i $(DESTDIR)$(docdir) ; \
	done
	for i in $(cipher_PACKAGES) ; do \
	    mkdir -p $(DESTDIR)$(docdir)/$$i ; \
	    for j in doc/$$i/*.html ; do \
		$(INSTALL_DATA) $$j $(DESTDIR)$(docdir)/$$i ; \
	    done; \
	done;

pdf:
	htmldoc --book -f doc/ciphertool.pdf doc/index.html doc/cipher.html doc/key.html doc/morse.html doc/permute.html doc/stat.html doc/csolve.html doc/ctool.html doc/dumproute.html doc/k3search.html doc/k4search.html doc/key2col.html doc/nicsolve.html doc/patsearch.html doc/aristocrat.html doc/baconian.html doc/bazeries.html doc/beaufort.html doc/bifid.html doc/bigbifid.html doc/cadenus.html doc/columnar.html doc/fmorse.html doc/gengromarkboard.html doc/grandpre.html doc/grille.html doc/gronsfeld.html doc/homophonic.html doc/keysquaresearch.html doc/morbit.html doc/myszcowski.html doc/nicodemus.html doc/nitrans.html doc/phillips.html doc/playfair.html doc/pollux.html doc/porta.html doc/ragbaby.html doc/railfence.html doc/route.html doc/swagman.html doc/trifid.html doc/variant.html doc/vigenere.html

$(PKG_LIB_FILE): $(PKG_OBJECTS)
	-rm -f $(PKG_LIB_FILE)
	${MAKE_LIB}
	$(RANLIB) $(PKG_LIB_FILE)

$(PKG_STUB_LIB_FILE): $(PKG_STUB_OBJECTS)
	-rm -f $(PKG_STUB_LIB_FILE)
	${MAKE_STUB_LIB}
	$(RANLIB_STUB) $(PKG_STUB_LIB_FILE)

.SUFFIXES: .c .$(OBJEXT)

.c.o:
	$(COMPILE) -c `echo $<` -o $@

lethist$(EXEEXT): $(srcdir)/lethist.c
	$(CC) $(RPM_OPT_FLAGS) -I$(srcdir) -o lethist $(srcdir)/lethist.c

solvemysz$(EXEEXT): $(srcdir)/solvemysz.c $(srcdir)/englishFrequencies.h
	$(CC) $(RPM_OPT_FLAGS) -I$(srcdir) -o solvemysz $(srcdir)/solvemysz.c

solver$(EXEEXT): $(srcdir)/solver.c $(srcdir)/solver.h
	$(CC) $(RPM_OPT_FLAGS) -o solver -I$(srcdir) $(srcdir)/solver.c

$(PKG_SHELL): $(PKG_SHELL_OBJECTS)
	-rm -f $@
	$(CC) -o $@ $(PKG_SHELL_OBJECTS) $(TCL_LIB_SPEC) $(TCL_LIBS) $(DMALLOC_LIBS)

Makefile: $(srcdir)/Makefile.in $(top_builddir)/config.status
	cd $(top_builddir) \
	  && CONFIG_FILES=$@ CONFIG_HEADERS= $(SHELL) ./config.status

dist:
	@if test -z "$(CVSROOT)" ; then \
	    echo "CVSROOT must be set to the CVS repository before making a source archive." ; \
	    exit 1 ; \
	fi
	rm -rf dist
	mkdir -p dist/SPECS
	mkdir -p dist/SRPMS
	mkdir -p dist/RPMS
	mkdir -p dist/SOURCES
	mkdir -p dist/BUILD
	(cd dist && cvs export $(RELEASETAG) -d $(CVSPACKAGE_NAME)-$(PACKAGE_VERSION) $(CVSPACKAGE_NAME))
	(cd dist/$(CVSPACKAGE_NAME)-$(PACKAGE_VERSION) && autoconf)
	(cd dist && tar czf SOURCES/$(CVSPACKAGE_NAME)-$(PACKAGE_VERSION).tar.gz ./$(CVSPACKAGE_NAME)-$(PACKAGE_VERSION))

wininstaller:
	C:/Progra~1/NSIS/makensis install.nsi

#========================================================================
# Don't modify the file to clean here.  Instead, set the "CLEANFILES"
# variable in configure.in
#========================================================================

clean:  
	-test -z "$(BINARIES)" || rm -f $(BINARIES)
	-rm -f *.$(OBJEXT) core *.core core.* *.gcda *.gcno *.gcov
	-test -z "$(CLEANFILES)" || rm -f $(CLEANFILES)

distclean: clean
	-rm -f *.tab.c
	-rm -f $(CONFIG_CLEAN_FILES)
	-rm -f config.cache config.log config.status

.PHONY: all binaries clean depend distclean doc install libraries test dist

# *EOF*
