#!/bin/bash

# This script handling the publishing of the current 
# commits generated binaries as an unstable package

# Example if the current package.json version reads 0.1.0 
# then the release will be tagged with 0.1.0

# Add dev dependencies to current path
export PATH="$PATH:node_modules/.bin"

# Add in the install script to package.json
node scripts/add_stable_install_script.js

# Package the binary
yarn package

# Publish the binary to github packages
node-pre-gyp-github publish --release

# Reset changes to the package.json
git checkout -- package.json
    