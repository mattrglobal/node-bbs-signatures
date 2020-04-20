'use strict';

const fs = require('fs');
let packageJson = require('../package.json');

packageJson.scripts.install = "yarn build:neon";

fs.writeFileSync('package.json', JSON.stringify(packageJson, null, 2));