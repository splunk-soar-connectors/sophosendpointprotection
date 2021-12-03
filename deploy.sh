#!/bin/bash
# Deploy App on Phantom Platform
# Author: Phantom FDSE
# Purpose: This script can be used for remote installation of a phantom app
# Set this to phantom's HOST/IP
PHANTOM_HOST=54.215.252.70
PHANTOM_USER=centos
# Set the install file name to the name of the file that wget downloads
INSTALL_DIR=/home/centos/appdev/
APP_DIR_NAME=${PWD##*/}
# scp -R . phantom@ /home/phantom/appdev/
# Create init script to run remotely before SCP.
REMOTE_SCRIPT_INIT="
echo '| Switch to /home/(user)/ directory'
cd $INSTALL_DIR
echo '| Create Directory (if not exist)'
mkdir -p $INSTALL_DIR/$APP_DIR_NAME
echo '| Clean App Directory'
echo 'cd $INSTALL_DIR/$APP_DIR_NAME && pwd && rm -rf ./* && ls -la'
echo '| Current User'
whoami
"
# Create deploy script to run remotely after SCP.
REMOTE_SCRIPT_DEPLOY="
echo '| Switch to /home/(user)/ directory'
cd $INSTALL_DIR/$APP_DIR_NAME/
pwd
echo '| Current User'
whoami
echo '| Compile and Install App'
sudo phenv python2.7 /opt/phantom/bin/compile_app.pyc -i -d
echo '| :)'
"

echo "[-] In 1 seconds, Magic wand will run the following script on phantom:"
echo
echo "===================="
echo "$REMOTE_SCRIPT_INIT"
echo "[-] scp . remote"
echo "$REMOTE_SCRIPT_DEPLOY"
echo "===================="
sleep 1
echo "🐚 "

# Pre Deploy - INIT
echo "[-] Initialize 🛠 "
ssh -n "$PHANTOM_USER"@"$PHANTOM_HOST" "$REMOTE_SCRIPT_INIT"

# Transfer Changes
echo "[-] Changes on the way to Phantom 🛫 "
# scp -r . "$PHANTOM_USER"@"$PHANTOM_HOST":$INSTALL_DIR/$APP_DIR_NAME/
# Using rsync instead of scp for increamental remote push saving us couple of seconds!
rsync -ru . "$PHANTOM_USER"@"$PHANTOM_HOST":$INSTALL_DIR/$APP_DIR_NAME/
echo "Phantom received files 🛬 "

# Deploy
echo "[-] Deploying ⌛ "
ssh -n "$PHANTOM_USER"@"$PHANTOM_HOST" "$REMOTE_SCRIPT_DEPLOY"

# For macOS, open App Url
echo "[-] Open Apps Url"
# sleep 1
# open -a "Google Chrome"

echo "---"
echo "[-] Done executing deploy script :)"