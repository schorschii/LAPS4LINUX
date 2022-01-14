#!/bin/bash
# Ensure that the rpm build tools are installed
yum install -y rpmdevtools rpmlint
rpmdev-setuptree
# Get the version from the python script
VERSION=$(awk '/PRODUCT_VERSION\s+=/ { print $3 }' ../../laps-runner.py | tr -d \' )
# Generate and fill the source folders
mkdir -p laps4linux-$VERSION/usr/sbin
mkdir -p laps4linux-$VERSION/etc/cron.hourly
cp ../../laps-runner.py laps4linux-$VERSION/usr/sbin
chmod +x laps4linux-$VERSION/usr/sbin/laps-runner.py
# Test if we have our own laps-runner config
if [ -f ../laps-runner.json ]; then
    cp ../laps-runner.json laps4linux-$VERSION/etc
else
    echo 'WARNING: You are using the provided json file, make sure this is intended'
    cp ../laps-runner.example.json laps4linux-$VERSION/etc/laps-runner.json
fi
chown 600 ../laps-runner.json
echo '#!/bin/sh' > laps4linux-$VERSION/etc/cron.hourly/laps-runner
echo '/usr/sbin/laps-runner.py --config /etc/laps-runner.json' >> laps4linux-$VERSION/etc/cron.hourly/laps-runner
chmod +x laps4linux-$VERSION/etc/cron.hourly/laps-runner
tar --create --file laps4linux-$VERSION.tar.gz laps4linux-$VERSION
if [ ! -f laps4linux-$VERSION.tar.gz ]; then
    echo 'Tar file was not detected, exiting'
    exit 1
fi
# Remove out build directory, now that we have our tarball
rm -fr laps4linux-$VERSION
mv laps4linux-$VERSION.tar.gz rpmbuild/SOURCES/
echo 'Modify the SPECS/laps4linux.spec file for the new version, and any change notes'
echo 'Then run rpmbuild -bb SPECS/laps4linux.spec to generate the RPM'