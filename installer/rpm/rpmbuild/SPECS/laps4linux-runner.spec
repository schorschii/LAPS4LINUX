Name:           laps4linux-runner
Version:        1.10.2
Release:        1%{?dist}
Summary:        Laps4linux - auto-rotate the root password for AD bound (samba net, pbis, adcli) linux servers
BuildArch:      noarch

License:        GPL-3.0
URL:            https://github.com/schorschii/LAPS4LINUX
Source0:        %{name}-%{version}.tar.gz

Requires:       python3 python3-pip python3-gssapi python3-cryptography python3-dns python3-devel krb5-workstation krb5-devel gcc

%description
This RPM contains the script and personalized config to run the lap4linux python script


%prep
%setup -q


%build


%install
rm -rf $RPM_BUILD_ROOT

mkdir -p $RPM_BUILD_ROOT/usr/share
cp -R usr/share/laps4linux-runner $RPM_BUILD_ROOT/usr/share
mkdir -p $RPM_BUILD_ROOT/%{_sbindir}
cp -P usr/sbin/laps-runner $RPM_BUILD_ROOT/%{_sbindir}/laps-runner
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}
cp etc/laps-runner.json $RPM_BUILD_ROOT/%{_sysconfdir}
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/cron.hourly/
cp etc/cron.hourly/laps-runner $RPM_BUILD_ROOT/%{_sysconfdir}/cron.hourly/

%post
DIR=/usr/share/laps4linux-runner
python3 -m venv --system-site-packages $DIR/venv
$DIR/venv/bin/pip3 install --upgrade $DIR
$DIR/venv/bin/pip3 uninstall -y pip


%clean
rm -rf $RPM_BUILD_ROOT


%files
%{_sbindir}/laps-runner
%{_sysconfdir}/laps-runner.json
%{_sysconfdir}/cron.hourly/laps-runner
/usr/share/laps4linux-runner/laps_runner/filetime.py
/usr/share/laps4linux-runner/laps_runner/__init__.py
/usr/share/laps4linux-runner/laps_runner/laps_runner.py
/usr/share/laps4linux-runner/README.md
/usr/share/laps4linux-runner/requirements.txt
/usr/share/laps4linux-runner/setup.py


%changelog
* Wed Jan 04 2023 schorschii
- Renamed packages to laps4linux-client and laps4linux-runner
- Adjusted dependencies for CentOS 9

* Thu Jan 13 2022 novaksam
- Initial build
