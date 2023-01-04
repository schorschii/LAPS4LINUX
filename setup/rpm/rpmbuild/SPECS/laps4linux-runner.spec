Name:           laps4linux-runner
Version:        1.5.2
Release:        1%{?dist}
Summary:        Laps4linux - auto-rotate the root password for AD bound (samba net, pbis, adcli) linux servers
BuildArch:      noarch

License:        GPL-3.0
URL:            https://github.com/schorschii/LAPS4LINUX
Source0:        %{name}-%{version}.tar.gz

Requires:       python3 python3-pip python3-gssapi python3-cryptography python3-dns krb5-workstation

%description
This RPM contains the script and personalized config to run the lap4linux python script


%prep
%setup -q


%build


%install
rm -rf $RPM_BUILD_ROOT

mkdir -p $RPM_BUILD_ROOT/%{_sbindir}
cp usr/sbin/laps-runner $RPM_BUILD_ROOT/%{_sbindir}/laps-runner
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}
cp etc/laps-runner.json $RPM_BUILD_ROOT/%{_sysconfdir}
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/cron.hourly/
cp etc/cron.hourly/laps-runner $RPM_BUILD_ROOT/%{_sysconfdir}/cron.hourly/

%post
sudo -H pip3 install ldap3


%clean
rm -rf $RPM_BUILD_ROOT


%files
%{_sbindir}/laps-runner
%{_sysconfdir}/laps-runner.json
%{_sysconfdir}/cron.hourly/laps-runner


%changelog
* Thu Jan 13 2022 novaksam
- Initial build
