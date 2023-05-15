# Do not build with zstd for RHEL < 8
%if (0%{?rhel} && 0%{?rhel} < 8) || (0%{?suse_version} && 0%{?suse_version} < 1500)
%bcond_with zstd
%else
%bcond_without zstd
%endif

Name:           drpm
Version:        0.5.2
Release:        1%{?dist}
Summary:        A library for making, reading and applying deltarpm packages
# the entire source code is LGPLv2+, except src/drpm_diff.c and src/drpm_search.c which are BSD
License:        LGPLv2+ and BSD
URL:            https://github.com/rpm-software-management/%{name}
Source:         %{url}/releases/download/%{version}/%{name}-%{version}.tar.bz2

BuildRequires:  cmake >= 2.8.5
BuildRequires:  gcc

BuildRequires:  rpm-devel
BuildRequires:  openssl-devel
BuildRequires:  zlib-devel
BuildRequires:  bzip2-devel
BuildRequires:  xz-devel
%if 0%{?suse_version}
BuildRequires:  lzlib-devel
%endif
%if %{with zstd}
BuildRequires:  pkgconfig(libzstd)
%endif

BuildRequires:  pkgconfig
BuildRequires:  doxygen

BuildRequires:  libcmocka-devel >= 1.0
%ifarch %{ix86} x86_64 ppc ppc64 ppc64le s390x armv7hl aarch64
BuildRequires:  valgrind
%endif

%description
The drpm package provides a library for making, reading and applying deltarpms,
compatible with the original deltarpm packages.

%package devel
Summary:        C interface for the drpm library
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description devel
The drpm-devel package provides a C interface (drpm.h) for the drpm library.

%prep
%autosetup -p1

%build
%cmake -DWITH_ZSTD:BOOL=%{?with_zstd:ON}%{!?with_zstd:OFF} -DHAVE_LZLIB_DEVEL:BOOL=%{?suse_version:ON}%{!?suse_version:OFF}
%cmake_build
%cmake_build --target doc

%install
%cmake_install

%check
%ctest

%if (0%{?rhel} && 0%{?rhel} < 8) || 0%{?suse_version}
%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig
%endif

%files
%{_libdir}/lib%{name}.so.*
%license COPYING LICENSE.BSD

%files devel
%doc %{_vpath_builddir}/doc/html/
%{_libdir}/lib%{name}.so
%{_includedir}/%{name}.h
%{_libdir}/pkgconfig/%{name}.pc

%changelog
* Mon May 15 2023 Jan Kolarik <jkolarik@redhat.com> - 0.5.2-1
- Avoid using obsolete RPM API
- Small memory and compatibility fixes

* Tue Mar 08 2022 Pavla Kratochvilova <pkratoch@redhat.com> - 0.5.1-1
- Fix SIGSEGV when an errors occurs in `rpm_get_file_info` (RhBug:1968594)
- For rpms without any files return file count 0 (RhBug:1968594)

* Tue Jun 02 2020 Neal Gompa <ngompa13@gmail.com> 0.5.0-1
- Enable zstd support for RHEL 8
- Fix license file entry in files list in spec
- Fix a memory leak on invalid input
- Hide the internal library symbols

* Wed Sep 11 2019 Neal Gompa <ngompa13@gmail.com> 0.4.1-1
- Relicense to LGPLv2+

* Wed Aug 14 2019 Neal Gompa <ngompa13@gmail.com> 0.4.0-1
- Add support for zstd drpms
- CMake cleanups
- Make running tests optional
- Small spec improvements

* Tue May 3 2016 Matej Chalk <mchalk@redhat.com> 0.3.0-3
- Now contains makedeltarpm and applydeltarpm functionality
- Added lzlib-devel dependency for OpenSUSE

* Tue Apr 12 2016 Igor Gnatenko <ignatenko@redhat.com> - 0.3.0-2
- Cleanup spec
- Make build out-of-tree
- Sync with valgrind arches
- Build documentation

* Thu Sep 3 2015 Matej Chalk <mchalk@redhat.com> 0.3.0-1
- Bumped minor version (deltarpm creation added)

* Tue Aug 4 2015 Matej Chalk <mchalk@redhat.com> 0.2.1-1
- Added openssl dependency

* Fri Jul 24 2015 Matej Chalk <mchalk@redhat.com> 0.2.0-2
- Fixed bug in test suite

* Tue Jun 23 2015 Matej Chalk <mchalk@redhat.com> 0.2.0-1
- Bumped minor version

* Fri Jun 19 2015 Matej Chalk <mchalk@redhat.com> 0.1.3-4
- Memory test only for architectures that have valgrind (#1232157)

* Wed Mar 11 2015 Matej Chalk <mchalk@redhat.com> 0.1.3-3
- Added cmocka and valgrind package dependencies

* Fri Mar 6 2015 Matej Chalk <mchalk@redhat.com> 0.1.3-2
- Added check section

* Fri Feb 13 2015 Matej Chalk <mchalk@redhat.com> 0.1.3-1
- Bumped version to 0.1.3
- Added CMake tool

* Fri Dec 19 2014 Matej Chalk <mchalk@redhat.com> 0.1.2-4
- Enabled hardened build

* Mon Dec 15 2014 Matej Chalk <mchalk@redhat.com> 0.1.2-3
- Added unversioned .so to package to enable linking with -ldrpm

* Thu Dec 11 2014 Matej Chalk <mchalk@redhat.com> 0.1.2-2
- Removed unversioned .so from package
- Included copies of both GPLv3 and LGPLv3

* Wed Dec 3 2014 Matej Chalk <mchalk@redhat.com> 0.1.2-1
- Bumped version to 0.1.2
- Added drpm.pc file for pkgconfig tool

* Thu Nov 6 2014 Matej Chalk <mchalk@redhat.com> 0.1.1-1
- Bumped version to 0.1.1

* Wed Nov 5 2014 Matej Chalk <mchalk@redhat.com> 0.1.0-1
- Initial RPM release
