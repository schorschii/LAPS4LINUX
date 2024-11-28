#!/bin/bash
set -e

# cd to working dir
cd "$(dirname "$0")"


# build client .deb package
INSTALLDIR=/usr/share/laps4linux-client
BUILDDIR=laps4linux-client

# empty / create necessary directories
if [ -d "$BUILDDIR/usr" ]; then
	rm -r $BUILDDIR/usr
fi

# copy files in place
install -D -m 644 ../../README.md                         -t $BUILDDIR/$INSTALLDIR
install -D -m 644 ../../assets/laps.png                   -t $BUILDDIR/usr/share/pixmaps
install -D -m 644 ../../assets/LAPS4LINUX.desktop         -t $BUILDDIR/usr/share/applications
install -D -m 644 ../../laps-client/laps_client/*.py      -t $BUILDDIR/$INSTALLDIR/laps_client
install -D -m 644 ../../laps-client/requirements.txt      -t $BUILDDIR/$INSTALLDIR
install -D -m 644 ../../laps-client/requirements-barcode.txt -t $BUILDDIR/$INSTALLDIR
install -D -m 644 ../../laps-client/setup.py              -t $BUILDDIR/$INSTALLDIR

# make binaries available in PATH
mkdir -p $BUILDDIR/usr/bin
ln -sf   $INSTALLDIR/venv/bin/laps-gui     $BUILDDIR/usr/bin/laps-gui
ln -sf   $INSTALLDIR/venv/bin/laps-cli     $BUILDDIR/usr/bin/laps-cli


# build runner .deb package
INSTALLDIR=/usr/share/laps4linux-runner
BUILDDIR=laps4linux-runner

# empty / create necessary directories
if [ -d "$BUILDDIR/usr" ]; then
	rm -r $BUILDDIR/usr
fi

# copy files in place
install -D -m 644 ../../README.md                         -t $BUILDDIR/$INSTALLDIR
install -D -m 755 ../../assets/laps-runner.cron              $BUILDDIR/etc/cron.hourly/laps-runner
install -D -m 755 ../../laps-runner/laps-runner-pam       -t $BUILDDIR/usr/sbin
install -D -m 644 ../../laps-runner/laps_runner/*.py      -t $BUILDDIR/$INSTALLDIR/laps_runner
install -D -m 644 ../../laps-runner/requirements.txt      -t $BUILDDIR/$INSTALLDIR
install -D -m 644 ../../laps-runner/setup.py              -t $BUILDDIR/$INSTALLDIR
# test if we have our own laps-runner config
if [ -f ../../laps-runner/laps-runner.json ]; then
	install -D -m 644 ../../laps-runner/laps-runner.json         $BUILDDIR/etc/laps-runner.json
else
	echo 'WARNING: You are using the example json config file, make sure this is intended'
	install -D -m 644 ../../laps-runner/laps-runner.json.example $BUILDDIR/etc/laps-runner.json
fi

# make binaries available in PATH
mkdir -p $BUILDDIR/usr/sbin
ln -sf   $INSTALLDIR/venv/bin/laps-runner     $BUILDDIR/usr/sbin/laps-runner


# build debs
dpkg-deb -Zxz --root-owner-group --build laps4linux-client
dpkg-deb -Zxz --root-owner-group --build laps4linux-runner

echo "Build finished"
