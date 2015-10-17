#!/bin/bash

set -e

ENCRYPTION="AES-256"
INTEGRITY="SHA2-256"
DHGROUP="modp2048"
FILE="/Library/Preferences/com.apple.networkextension.plist"

TOOL="python macos-networkextensiontool.py"

# Don't need root privs for this.
defaults export $FILE - > plist.xml

echo "Before:"
$TOOL -l -f plist.xml
first_config=$($TOOL -l -f plist.xml|grep '^[^ ]')
$TOOL -f plist.xml -E $ENCRYPTION -I $INTEGRITY -D $DHGROUP "$first_config"
echo "After:"
$TOOL -l -f plist.xml

# Do need root privs for this.
echo "The new plist can only be imported by the superuser.  The following command will be executed with root privileges."
set -x
sudo -k defaults import $FILE - < plist.xml
set +x
echo "In order to active the new settings, you'll need to direct the GUI to 'Apply'. The simplest way to do that is to change one of the main text fields temporarily and click 'Apply.'" | fmt -w 74
