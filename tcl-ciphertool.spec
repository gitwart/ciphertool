%{!?tcl_version: %global tcl_version %(echo 'puts $tcl_version' | tclsh)}
%{!?tcl_sitearch: %global tcl_sitearch %{_libdir}/tcl%{tcl_version}}

Name:           tcl-ciphertool
Version:        1.6.4
Release:        1%{?dist}
Summary: Tools for working with American Cryptogram Association ciphers

Group: Applications/Text
License:        GPL
URL:            http://ciphertool.sourceforge.net/
Source0:        http://dl.sf.net/ciphertool/ciphertool-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  tcl-devel
BuildRequires:  desktop-file-utils
Requires:       tk tcllib
Requires:       tcl(abi) = 8.6
Provides:       ciphertool = %{version}-%{release}

%description
This package contains tools for viewing, manipulating, analyzing, and solving
simple cipher types in use by the American Cryptogram Association.

%prep
%setup -q -n ciphertool-%{version}


%build
%configure --libdir=%{tcl_sitearch}
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
rm $RPM_BUILD_ROOT/%{_bindir}/ctool.bat

desktop-file-install --vendor fedora                            \
        --dir ${RPM_BUILD_ROOT}%{_datadir}/applications         \
        --add-category X-Fedora                                 \
        ciphertool.desktop

desktop-file-install --vendor fedora                            \
        --dir ${RPM_BUILD_ROOT}%{_datadir}/applications         \
        --add-category X-Fedora                                 \
        tkcrithm.desktop

%check
make test
#make check

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig


%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_bindir}/*
%{tcl_sitearch}/cipher%{version}
%{_prefix}/share/doc/cipher-%{version}
%{_prefix}/share/applications/*.desktop

%changelog
* Sun Apr 8 2018 <wart at kobold.org> - 1.6.4-1
- Update to 1.6.4
- Code cleanup, with more unit tests and minor bug fixes

* Fri Mar 30 2018 <wart at kobold.org> - 1.6.3-1
- Updated to build with Tcl 8.6
- Cleaned up many compiler warnings

* Tue Jan 17 2006 <wart at kobold.org> - 1.6.1-1
- Updated to 1.6.1

* Mon Jan 16 2006 <wart at kobold.org> - 1.6.0-7
- Added desktop integration files.
- Added TEA 3.4 support.

* Tue Oct 18 2005 <wart at kobold.org> - 1.6.0-6
- ??

* Sun Mar  6 2005 <wart at kobold.org> - 1.6.0-5
- progs/ctool:  Change interpreter from 'wish8.3' to 'wish'.
- configure:
- configure.in:  Bumped release from '4' to '5'.

* Tue Sep  7 2004 <wart at kobold.org> - 1.6.0-4
- Initial rpm release with a Fedora-compatible spec file.
