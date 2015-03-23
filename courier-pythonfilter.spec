%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

Name:      courier-pythonfilter
Version:   1.4
Release:   1%{?dist}
Summary:   Python filtering architecture for the Courier MTA.

Group:     Development/Libraries
License:   GPL
Url:       http://www.dragonsdawn.net/~gordon/courier-pythonfilter/
Source0:   %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArchitectures: noarch

BuildRequires: python
Requires:  courier

%description
Pythonfilter provides a framework for writing message filters in 
Python, as well as a selection of common filters.


%prep
%setup -q


%build
python setup.py build


%install
rm -rf $RPM_BUILD_ROOT
python setup.py install --skip-build --root=$RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{_localstatedir}/lib/pythonfilter/quarantine


%clean
rm -rf $RPM_BUILD_ROOT


%post
if [ $1 -eq 1 ]; then
    test -f /etc/profile.d/courier.sh && . /etc/profile.d/courier.sh
    type -p courier-config > /dev/null || exit 0
    libexecdir=$(courier-config | grep ^libexecdir | cut -f2 -d=)
    test -n "${libexecdir}" -a -d "${libexecdir}" || exit 0
    ln -s %{_bindir}/pythonfilter ${libexecdir}/filters
fi

%preun
if [ $1 -eq 0 ]; then
    test -f /etc/profile.d/courier.sh && . /etc/profile.d/courier.sh
    type -p courier-config > /dev/null || exit 0
    libexecdir=$(courier-config | grep ^libexecdir | cut -f2 -d=)
    test -n "${libexecdir}" -a -d "${libexecdir}" || exit 0
    rm ${libexecdir}/filters/pythonfilter
fi


%files
%defattr(-,root,root)
%dir %{python_sitelib}/pythonfilter
%{python_sitelib}/pythonfilter/*
%dir %{python_sitelib}/courier
%{python_sitelib}/courier/*
%{_bindir}/*
%config(noreplace) %{_sysconfdir}/*
%dir %{_localstatedir}/lib/pythonfilter
%dir %{_localstatedir}/lib/pythonfilter/quarantine