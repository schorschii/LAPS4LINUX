#!/bin/bash
set -e

# check root permissions
if [ "$EUID" -ne 0 ] && ! groups | grep -q sudo ; then
	echo "Please run this script as root!"
	#exit 1 # disabled for github workflow. don't know why this check fails here but sudo works.
fi

# cd to working dir
cd "$(dirname "$0")"


# build client .deb package
INSTALLDIR=/usr/share/laps4linux-client
BUILDDIR=laps4linux-client

# empty / create necessary directories
if [ -d "$BUILDDIR/usr" ]; then
	sudo rm -r $BUILDDIR/usr
fi

# copy files in place
sudo install -D -m 644 ../../README.md                         -t $BUILDDIR/$INSTALLDIR
sudo install -D -m 644 ../../assets/laps.png                   -t $BUILDDIR/usr/share/pixmaps
sudo install -D -m 644 ../../assets/LAPS4LINUX.desktop         -t $BUILDDIR/usr/share/applications
sudo install -D -m 644 ../../laps-client/laps_client/*.py      -t $BUILDDIR/$INSTALLDIR/laps_client
sudo install -D -m 644 ../../laps-client/requirements.txt      -t $BUILDDIR/$INSTALLDIR
sudo install -D -m 644 ../../laps-client/setup.py              -t $BUILDDIR/$INSTALLDIR

# set file permissions
sudo chown -R root:root $BUILDDIR

# make binaries available in PATH
sudo mkdir -p $BUILDDIR/usr/bin
sudo ln -sf   $INSTALLDIR/venv/bin/laps-gui     $BUILDDIR/usr/bin/laps-gui
sudo ln -sf   $INSTALLDIR/venv/bin/laps-cli     $BUILDDIR/usr/bin/laps-cli


# build runner .deb package
INSTALLDIR=/usr/share/laps4linux-runner
BUILDDIR=laps4linux-runner

# empty / create necessary directories
if [ -d "$BUILDDIR/usr" ]; then
	sudo rm -r $BUILDDIR/usr
fi

# copy files in place
sudo install -D -m 644 ../../assets/laps-runner.cron              $BUILDDIR/etc/cron.hourly/laps-runner
sudo install -D -m 644 ../../laps-runner/laps_runner/*.py      -t $BUILDDIR/$INSTALLDIR/laps_runner
sudo install -D -m 644 ../../laps-runner/requirements.txt      -t $BUILDDIR/$INSTALLDIR
sudo install -D -m 644 ../../laps-runner/setup.py              -t $BUILDDIR/$INSTALLDIR
# test if we have our own laps-runner config
if [ -f ../../laps-runner/laps-runner.json ]; then
	sudo install -D -m 644 ../../laps-runner/laps-runner.json         $BUILDDIR/etc/laps-runner.json
else
	echo 'WARNING: You are using the example json config file, make sure this is intended'
	sudo install -D -m 644 ../../laps-runner/laps-runner.json.example $BUILDDIR/etc/laps-runner.json
fi

# set file permissions
sudo chown -R root:root $BUILDDIR

# make binaries available in PATH
sudo mkdir -p $BUILDDIR/usr/sbin
sudo ln -sf   $INSTALLDIR/venv/bin/laps-runner     $BUILDDIR/usr/sbin/laps-runner


# build debs
sudo dpkg-deb -Zxz --build laps4linux-client
sudo dpkg-deb -Zxz --build laps4linux-runner

echo "Build finished"
