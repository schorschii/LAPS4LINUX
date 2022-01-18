Name:           laps4linux
Version:        1.5.2
Release:        1%{?dist}
Summary:        Laps4linux - auto-rotate the root password for AD bound (samba net, pbis, adcli) linux servers
BuildArch:      noarch

License:        GPL-3.0
URL:            https://github.com/schorschii/LAPS4LINUX
Source0:        %{name}-%{version}.tar.gz

Requires:       python3 python3-pip krb5-devel python3-gssapi python3-ldap3 python3-wheel python3-cryptography python3-dns

%description
This RPM contains the script and personalized config to run the lap4linux python script


%prep
%setup -q

%build

%install
rpm -fr $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%{_sbindir}
cp usr/sbin/laps-runner.py $RPM_BUILD_ROOT/%{_sbindir}/laps-runner
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}
cp etc/laps-runner.json $RPM_BUILD_ROOT/%{_sysconfdir}
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/cron.hourly/
cp etc/cron.hourly/laps-runner $RPM_BUILD_ROOT/%{_sysconfdir}/cron.hourly/

%clean
rm -rf $RPM_BUILD_ROOT


%files
%{_sbindir}/laps-runner
%{_sysconfdir}/laps-runner.json
%{_sysconfdir}/cron.hourly/laps-runner



%changelog
* Thu Jan 13 2022 novaksam
- Initial build
