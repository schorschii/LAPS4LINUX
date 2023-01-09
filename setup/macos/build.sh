#!/bin/bash

cd "$(dirname "$0")"

# remove temp build folder
rm -r "../../dist/LAPS4MAC"

# check if mount point is free
if [ -d "/Volumes/LAPS4MAC" ]; then
	echo "ERROR: /Volumes/LAPS4MAC already mounted"
	exit 1
fi

# create DMG with .app directory and /Applications link
rm "../../dist/.DS_Store"
hdiutil create -srcfolder "../../dist" -volname "LAPS4MAC" -fs HFS+ -fsargs "-c c=64,a=16,e=16" -format UDRW LAPS4MAC-rw.dmg
hdiutil attach -readwrite -noverify -noautoopen LAPS4MAC-rw.dmg
ln -s /Applications /Volumes/LAPS4MAC/Applications

# set volume icon
cp "../../assets/setup.icns" "/Volumes/LAPS4MAC/.VolumeIcon.icns"
SetFile -c icnC "/Volumes/LAPS4MAC/.VolumeIcon.icns"
SetFile -a C "/Volumes/LAPS4MAC"

# create final DMG
sleep 1
hdiutil detach /Volumes/LAPS4MAC
sleep 1
hdiutil convert LAPS4MAC-rw.dmg -format UDZO -o LAPS4MAC.dmg
rm LAPS4MAC-rw.dmg
