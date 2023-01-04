#!/bin/bash
set -e

# build .deb packages

# check root permissions
if [ "$EUID" -ne 0 ]
	then echo "Please run this script as root!"
	exit
fi

# cd to working dir
cd "$(dirname "$0")"

# create necessary directories
mkdir -p laps4linux-client/usr/bin
mkdir -p laps4linux-client/usr/share/applications
mkdir -p laps4linux-client/usr/share/pixmaps
mkdir -p laps4linux-runner/etc/cron.hourly
mkdir -p laps4linux-runner/usr/sbin

# copy files in place
cp ../../laps-gui.py laps4linux-client/usr/bin/laps-gui
cp ../../laps-cli.py laps4linux-client/usr/bin/laps-cli
cp ../../assets/LAPS4LINUX.desktop laps4linux-client/usr/share/applications
cp ../../assets/laps.png laps4linux-client/usr/share/pixmaps
cp ../../laps-runner.py laps4linux-runner/usr/sbin/laps-runner
# test if we have our own laps-runner config
if [ -f ../../laps-runner.json ]; then
    cp ../../laps-runner.json laps4linux-runner/etc
else
    echo 'WARNING: You are using the example json config file, make sure this is intended'
    cp ../../laps-runner.example.json laps4linux-runner/etc/laps-runner.json
fi

# set file permissions
chown -R root:root laps4linux-client
chown -R root:root laps4linux-runner
chmod +x laps4linux-client/usr/bin/laps-gui
chmod +x laps4linux-client/usr/bin/laps-cli
chmod +x laps4linux-runner/usr/sbin/laps-runner

# build debs
dpkg-deb -Zxz --build laps4linux-client
dpkg-deb -Zxz --build laps4linux-runner

echo "Build finished"
