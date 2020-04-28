"use strict";

const fs = require("fs");
let packageJson = require("../package.json");

// Add the post install script that will fetch the native node module from gh packages
packageJson.scripts.install = "node-pre-gyp install --fallback-to-build=false";

fs.writeFileSync("package.json", JSON.stringify(packageJson, null, 2));
