"use strict";

const fs = require("fs");
let packageJson = require("../package.json");

// Add the post install script that will build the rust using neon
packageJson.scripts.install = "yarn build:neon";

packageJson.directories = ["lib"];

packageJson.files = ["lib", "native"];

fs.writeFileSync("package.json", JSON.stringify(packageJson, null, 2));
