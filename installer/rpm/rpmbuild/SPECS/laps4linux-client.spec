Name:           laps4linux-client
Version:        1.13.0
Release:        1%{?dist}
Summary:        Laps4linux - auto-rotate the root password for AD bound (samba net, pbis, adcli) linux servers
BuildArch:      noarch

License:        GPL-3.0
URL:            https://github.com/schorschii/LAPS4LINUX
Source0:        %{name}-%{version}.tar.gz

Requires:       python3 python3-pip python3-gssapi python3-qt5 python3-dns python3-devel krb5-devel gcc

%description
This RPM contains the script and personalized config to run the lap4linux python script


%prep
%setup -q


%build


%install
rm -rf $RPM_BUILD_ROOT

mkdir -p $RPM_BUILD_ROOT/usr/share
cp -R usr/share/laps4linux-client $RPM_BUILD_ROOT/usr/share
mkdir -p $RPM_BUILD_ROOT/%{_bindir}
cp -P usr/bin/laps-gui $RPM_BUILD_ROOT/%{_bindir}/laps-gui
cp -P usr/bin/laps-cli $RPM_BUILD_ROOT/%{_bindir}/laps-cli
mkdir -p $RPM_BUILD_ROOT/usr/share/applications
cp usr/share/applications/LAPS4LINUX.desktop $RPM_BUILD_ROOT/usr/share/applications
mkdir -p $RPM_BUILD_ROOT/usr/share/pixmaps
cp usr/share/pixmaps/laps.png $RPM_BUILD_ROOT/usr/share/pixmaps


%post
DIR=/usr/share/laps4linux-client
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
$DIR/venv/bin/pip3 install --upgrade $DIR[barcode]
$DIR/venv/bin/pip3 uninstall -y pip setuptools
if command -v update-desktop-database; then
	update-desktop-database
fi


%clean
rm -rf $RPM_BUILD_ROOT


%files
%{_bindir}/laps-gui
%{_bindir}/laps-cli
/usr/share/laps4linux-client/laps_client/filetime.py
/usr/share/laps4linux-client/laps_client/__init__.py
/usr/share/laps4linux-client/laps_client/laps_cli.py
/usr/share/laps4linux-client/laps_client/laps_gui.py
/usr/share/laps4linux-client/README.md
/usr/share/laps4linux-client/requirements.txt
/usr/share/laps4linux-client/requirements-barcode.txt
/usr/share/laps4linux-client/setup.py
/usr/share/applications/LAPS4LINUX.desktop
/usr/share/pixmaps/laps.png


%changelog
* Wed Jan 04 2023 schorschii
- Initial build
