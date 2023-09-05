Name:           wdns
Version:        0.12.0
Release:        1%{?dist}
Summary:        low-level DNS library

License:        Apache-2.0
URL:            https://github.com/farsightsec/wdns
Source0:        https://dl.farsightsecurity.com/dist/%{name}/%{name}-%{version}.tar.gz

BuildRequires:  gcc
#Requires:       

%description
wdns is a low-level DNS library. It contains a fast DNS message parser
and utility functions for manipulating wire-format DNS data.

This package contains the shared library for libwdns.

%package devel
Summary:	low-level DNS library (development files)
Requires:	%{name}%{?_isa} = %{version}-%{release}

%description devel
wdns is a low-level DNS library. It contains a fast DNS message parser
and utility functions for manipulating wire-format DNS data.

This package contains the static library and header file for libwdns.

%prep
%setup -q


%build
[ -x configure ] || autoreconf -fvi
%configure
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
%make_install


%files
%defattr(-,root,root,-)
%{_libdir}/*.so.*
%exclude %{_libdir}/libwdns.la

%files devel
%{_libdir}/*.so
%{_libdir}/*.a
%{_libdir}/pkgconfig/*
%{_includedir}/*

%doc

%changelog
