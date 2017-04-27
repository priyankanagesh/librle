Summary:        rle
Name:           rle
Version:        1.2.1
Release:        1.el6%{?ci_flag}
License:        GPLv3 xor TAS
Group:          System Environment/Libraries
Source:         %{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires:  cmake doxygen libpcap-devel libcmocka-devel
Provides:       %{name}.%{version}.so

%define prefix /usr

%description
A C library that implements the RLE (Return Link Encapsulation) protocol
as defined by ETSI TS 103 179 V1.1.1 (2013-08).

%package devel
Summary: Header files for librle
Group: Development/Libraries
Requires: %{name} = %{version}

%description devel
Header files for librle

%prep
%setup

# Generate version tag
echo %{version}-%{release} > VERSION

%build
mkdir build_tree
cd build_tree
cmake -DCMAKE_INSTALL_PREFIX=%{prefix} ..
make
  
%install 
cd build_tree
DESTDIR=$RPM_BUILD_ROOT make install

%post

%postun

%clean
rm -rf %{srcdirname}
rm -rf build_tree

%files
%defattr(-,root,root,-)
%{_libdir}/lib%{name}.so*

%files devel
%defattr(-,root,root,-)
%{_libdir}/pkgconfig/%{name}.pc
%{_includedir}/rle.h

%changelog
* Mon Jan 8 2016 Remy FONTAYNE
  File creation
