#!/bin/bash

# fail if any command in script fails
set -e 

# This script handling the publishing of the current 
# commits generated binaries as an unstable package

# Example if the current package.json version reads 0.1.0 
# then the release will be tagged with 0.1.0

# Add dev dependencies to current path
export PATH="$PATH:node_modules/.bin"

# Add in the install script to package.json
node scripts/add_stable_install_script.js

# Move out the generated index.node file
copyfiles -f native/index.node .

# Recursively delete the contents of the native folder
rimraf native/*

# Copy back in the binary
copyfiles index.node native

# Package the binary
yarn package

# Publish the binary to github packages using strict
# so that this script can catch failures (network, auth, etc.)
node --unhandled-rejections=strict ./node_modules/.bin/node-pre-gyp-github publish --release

# Reset changes to the package.json
git checkout -- package.json

# Reset changes to the native folder
git checkout -- native/
    