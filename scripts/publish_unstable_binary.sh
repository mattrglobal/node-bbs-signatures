#!/bin/bash

# This script handling the publishing of the current 
# commits generated binaries as an unstable package

# Example if the current package.json version reads 0.1.0 
# then the unstable release of 0.1.1-unstable.(current git commit reference)

# Add dev dependencies to current path
export PATH="$PATH:node_modules/.bin"

# Add in the install script to package.json
node scripts/add_unstable_install_script.js

# Minor version the current package
yarn version --no-git-tag-version --patch

# Fetch the current version from the package.json
new_version=$(node -pe "require('./package.json').version")

# Fetch the new unstable version
new_unstable_version=$new_version"-unstable.$(git rev-parse --short HEAD)"

# Version to this new unstable version
yarn version --no-git-tag-version --new-version $new_unstable_version

# Package the binary
yarn package

# Publish the binary to github packages
node-pre-gyp-github publish --release

# Reset changes to the package.json
git checkout -- package.json
    