'use strict';

const fs = require('fs');
let packageJson = require('../package.json');

// Add the post install script that will fetch the native node module from gh packages
packageJson.scripts.install = "node-pre-gyp install --fallback-to-build=false";

// Update the package json so that the RUST is not compiled into the released package
packageJson.files = [
    "lib",
    "native/index.node"
];

fs.writeFileSync('package.json', JSON.stringify(packageJson, null, 2));