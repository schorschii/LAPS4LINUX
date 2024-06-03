#!/bin/bash
set -e

# build .rpm packages

# cd to working dir
cd "$(dirname "$0")"

# ensure that the rpm build tools are installed
if command -v yum; then
    yum install -y rpmdevtools rpmlint
fi
if command -v rpmdev-setuptree; then
    rpmdev-setuptree
fi

# get the version from the python script
VERSION=$(awk '/__version__\s+=/ { print $3 }' ../../laps-runner/laps_runner/__init__.py | tr -d \')

# generate and fill the source folders
mkdir -p laps4linux-client-$VERSION/usr/bin
mkdir -p laps4linux-client-$VERSION/usr/share/laps4linux-client/laps_client
mkdir -p laps4linux-client-$VERSION/usr/share/applications
mkdir -p laps4linux-client-$VERSION/usr/share/pixmaps
mkdir -p laps4linux-runner-$VERSION/usr/sbin
mkdir -p laps4linux-runner-$VERSION/usr/share/laps4linux-runner/laps_runner
mkdir -p laps4linux-runner-$VERSION/etc/cron.hourly
cp ../../laps-client/laps_client/*.py laps4linux-client-$VERSION/usr/share/laps4linux-client/laps_client
cp ../../laps-client/requirements.txt laps4linux-client-$VERSION/usr/share/laps4linux-client
cp ../../laps-client/setup.py         laps4linux-client-$VERSION/usr/share/laps4linux-client
cp ../../README.md                    laps4linux-client-$VERSION/usr/share/laps4linux-client
cp ../../assets/LAPS4LINUX.desktop    laps4linux-client-$VERSION/usr/share/applications
cp ../../assets/laps.png              laps4linux-client-$VERSION/usr/share/pixmaps
cp ../../assets/laps-runner.cron      laps4linux-runner-$VERSION/etc/cron.hourly/laps-runner
cp ../../laps-runner/laps_runner/*.py laps4linux-runner-$VERSION/usr/share/laps4linux-runner/laps_runner
cp ../../laps-runner/requirements.txt laps4linux-runner-$VERSION/usr/share/laps4linux-runner
cp ../../laps-runner/setup.py         laps4linux-runner-$VERSION/usr/share/laps4linux-runner
cp ../../README.md                    laps4linux-runner-$VERSION/usr/share/laps4linux-runner
ln -sf /usr/share/laps4linux-client/venv/bin/laps-cli laps4linux-client-$VERSION/usr/bin/laps-cli
ln -sf /usr/share/laps4linux-client/venv/bin/laps-gui laps4linux-client-$VERSION/usr/bin/laps-gui
ln -sf /usr/share/laps4linux-runner/venv/bin/laps-runner laps4linux-runner-$VERSION/usr/sbin/laps-runner
chmod +x laps4linux-runner-$VERSION/etc/cron.hourly/laps-runner

# test if we have our own laps-runner config
if [ -f ../../laps-runner/laps-runner.json ]; then
    cp ../../laps-runner/laps-runner.json laps4linux-runner-$VERSION/etc
else
    echo 'WARNING: You are using the example json config file, make sure this is intended'
    cp ../../laps-runner/laps-runner.json.example laps4linux-runner-$VERSION/etc/laps-runner.json
fi

# create .tar.gz source package
tar --create --file laps4linux-client-$VERSION.tar.gz laps4linux-client-$VERSION
tar --create --file laps4linux-runner-$VERSION.tar.gz laps4linux-runner-$VERSION
if [ ! -f laps4linux-runner-$VERSION.tar.gz ] || [ ! -f laps4linux-client-$VERSION.tar.gz ]; then
    echo 'Tar file was not detected, exiting'
    exit 1
fi

# remove out build directory, now that we have our tarball
rm -fr laps4linux-client-$VERSION
rm -fr laps4linux-runner-$VERSION
mkdir -p rpmbuild/SOURCES
mv laps4linux-client-$VERSION.tar.gz rpmbuild/SOURCES/
mv laps4linux-runner-$VERSION.tar.gz rpmbuild/SOURCES/

# build the rpm package
cd rpmbuild
rpmbuild --define "_topdir $(pwd)" -bb SPECS/laps4linux-client.spec
rpmbuild --define "_topdir $(pwd)" -bb SPECS/laps4linux-runner.spec

# uninstall: rpm -e laps4linux-client
# install:   rpm -i ...rpm
# list:      rpm -qlp ...rpm
