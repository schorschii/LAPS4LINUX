#!/bin/bash

cd "$(dirname "$0")"

SRC_DIR="../../laps-client/dist"
DMG_FILE_TMP_MOUNT="/Volumes/LAPS4LINUX"
DMG_FILE_TMP="laps4linux-rw.dmg"
DMG_FILE="laps4linux-client.dmg"
#DEVELOPER_ACCOUNT_USERNAME=""
#DEVELOPER_ACCOUNT_PASSWORD=""
#DEVELOPER_ACCOUNT_TEAM=""


# remove temp build folder
rm -r "$SRC_DIR/LAPS4LINUX"


# check if mount point is free
if [ -d "$DMG_FILE_TMP_MOUNT" ]; then
	echo "ERROR: $DMG_FILE_TMP_MOUNT already mounted"
	exit 1
fi


# create DMG with .app directory and /Applications link
rm "$SRC_DIR/.DS_Store"
hdiutil create -srcfolder "$SRC_DIR" -volname "LAPS4LINUX" -fs HFS+ -fsargs "-c c=64,a=16,e=16" -format UDRW "$DMG_FILE_TMP"
hdiutil attach -readwrite -noverify -noautoopen "$DMG_FILE_TMP"
ln -s "/Applications" "$DMG_FILE_TMP_MOUNT/Applications"


# set volume icon
cp "../../assets/setup.icns" "$DMG_FILE_TMP_MOUNT/.VolumeIcon.icns"
SetFile -c icnC "$DMG_FILE_TMP_MOUNT/.VolumeIcon.icns"
SetFile -a C "$DMG_FILE_TMP_MOUNT"


# create final DMG
sleep 1
rm -rf "$DMG_FILE_TMP_MOUNT/.fseventsd"
hdiutil detach "$DMG_FILE_TMP_MOUNT"
sleep 1
hdiutil convert "$DMG_FILE_TMP" -format UDZO -o "$DMG_FILE"
rm "$DMG_FILE_TMP"


# notarize (only possible with valid signature)
if [ "$DEVELOPER_ACCOUNT_USERNAME" != "" ] && [ "$DEVELOPER_ACCOUNT_PASSWORD" != "" ] && [ "$DEVELOPER_ACCOUNT_TEAM" != "" ]; then
	echo "Store credentials for notarization ..."
	xcrun notarytool store-credentials "notarytool-password" --apple-id "$DEVELOPER_ACCOUNT_USERNAME" --password "$DEVELOPER_ACCOUNT_PASSWORD" --team-id "$DEVELOPER_ACCOUNT_TEAM"
fi

echo "Notarize package ..."
xcrun notarytool submit "$DMG_FILE" --wait --keychain-profile "notarytool-password"

# get logfile with additional information:
# xcrun notarytool log --keychain-profile "notarytool-password" xxx-xxx-xxx-xxx developer_log.json


echo "Build finished"
