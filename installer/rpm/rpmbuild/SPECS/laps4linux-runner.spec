Name:           laps4linux-runner
Version:        1.13.0
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
mkdir -p $RPM_BUILD_ROOT/%{_sbindir}
cp usr/sbin/laps-runner-pam $RPM_BUILD_ROOT/%{_sbindir}/laps-runner-pam

%post
DIR=/usr/share/laps4linux-runner
PYTHON_BIN=python3
if [[ "$(python3 --version)" == "Python 3.0"* ]] \
|| [[ "$(python3 --version)" == "Python 3.1"* ]] \
|| [[ "$(python3 --version)" == "Python 3.2"* ]] \
|| [[ "$(python3 --version)" == "Python 3.3"* ]] \
|| [[ "$(python3 --version)" == "Python 3.4"* ]] \
|| [[ "$(python3 --version)" == "Python 3.5"* ]] \
|| [[ "$(python3 --version)" == "Python 3.6"* ]] \
|| [[ "$(python3 --version)" == "Python 3.7"* ]]; then
	echo "Default Python version on this system ($(python3 --version)) is not compatible with LAPS4LINUX! Install at least Python 3.8."
	if command -v python3.8; then
		PYTHON_BIN=python3.8
		echo "Found compatible Python version: $PYTHON_BIN"
	fi
fi
$PYTHON_BIN -m venv --system-site-packages --clear $DIR/venv
$DIR/venv/bin/pip3 install --upgrade pip==25.0.0 setuptools==80.8.0
$DIR/venv/bin/pip3 install --upgrade $DIR
$DIR/venv/bin/pip3 uninstall -y pip setuptools


%clean
rm -rf $RPM_BUILD_ROOT


%files
%{_sbindir}/laps-runner
%{_sbindir}/laps-runner-pam
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
