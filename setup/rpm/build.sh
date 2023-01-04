#!/bin/bash
set -e

# build .rpm packages

# cd to working dir
cd "$(dirname "$0")"

# ensure that the rpm build tools are installed
yum install -y rpmdevtools rpmlint
rpmdev-setuptree

# get the version from the python script
VERSION=$(awk '/PRODUCT_VERSION\s+=/ { print $3 }' ../../laps-runner.py | tr -d \' )

# generate and fill the source folders
mkdir -p laps4linux-client-$VERSION/usr/bin
mkdir -p laps4linux-client-$VERSION/usr/share/applications
mkdir -p laps4linux-client-$VERSION/usr/share/pixmaps
mkdir -p laps4linux-runner-$VERSION/usr/sbin
mkdir -p laps4linux-runner-$VERSION/etc/cron.hourly
cp ../../laps-gui.py laps4linux-client-$VERSION/usr/bin/laps-gui
cp ../../laps-cli.py laps4linux-client-$VERSION/usr/bin/laps-cli
cp ../../assets/LAPS4LINUX.desktop laps4linux-client-$VERSION/usr/share/applications
cp ../../assets/laps.png laps4linux-client-$VERSION/usr/share/pixmaps
cp ../../laps-runner.py laps4linux-runner-$VERSION/usr/sbin/laps-runner
chmod +x laps4linux-client-$VERSION/usr/bin/laps-gui
chmod +x laps4linux-client-$VERSION/usr/bin/laps-cli
chmod +x laps4linux-runner-$VERSION/usr/sbin/laps-runner

# test if we have our own laps-runner config
if [ -f ../../laps-runner.json ]; then
    cp ../../laps-runner.json laps4linux-runner-$VERSION/etc
else
    echo 'WARNING: You are using the example json config file, make sure this is intended'
    cp ../../laps-runner.example.json laps4linux-runner-$VERSION/etc/laps-runner.json
fi

# add cron script
echo '#!/bin/sh' > laps4linux-runner-$VERSION/etc/cron.hourly/laps-runner
echo '/usr/sbin/laps-runner --config /etc/laps-runner.json' >> laps4linux-runner-$VERSION/etc/cron.hourly/laps-runner
chmod +x laps4linux-runner-$VERSION/etc/cron.hourly/laps-runner

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

