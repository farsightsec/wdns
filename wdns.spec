%define name            wdns
%define version         0.6

BuildRoot:              %{_tmppath}/%{name}-%{version}-build
Summary:                low-level DNS library
License:                Apache-2.0
URL:                    https://github.com/farsightsec/wdns
Name:                   %{name}
Version:                %{version}
Release:                1
Source:                 https://dl.farsightsecurity.com/dist/wdns/%{name}-%{version}.tar.gz
Packager:               John Heidemann <johnh@isi.edu>, Robert Edmonds <edmonds@fsi.io>
Prefix:                 /usr
Group:                  System/Libraries
BuildRequires:          gcc-c++

%description
wdns is a lowel-level DNS library. It contains a fast DNS message parser
and various utility functions for manipulating wire-format DNS data.

This package contains the shared library for libwdns.

%package devel
Summary:                low-level DNS library (development files)

%description devel
wdns is a lowel-level DNS library. It contains a fast DNS message parser
and various utility functions for manipulating wire-format DNS data.

This package contains the static library and header file for libwdns.

%prep
%setup -q

%build
# ./autogen.sh
./configure --prefix %{_prefix} --libdir=%{_libdir}
make %{?_smp_mflags}

%install
make DESTDIR=%{buildroot} install

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_libdir}/*.so.*
%exclude %{_libdir}/libwdns.la
# we ignore the test code that ends up in /usr/bin
%exclude /usr/bin/*

%files devel
%{_libdir}/*.so
%{_libdir}/*.a
%{_libdir}/pkgconfig/*
%{_includedir}/*
