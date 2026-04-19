const fs = require("fs");
fs.writeFileSync("/tmp/.npmrc", "token=abc");
require("dns").resolve("shai-hulud.bad");
