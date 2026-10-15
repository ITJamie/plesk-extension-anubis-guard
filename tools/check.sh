#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
task_php=${PHP_BIN:-/opt/plesk/php/8.4/bin/php}
task_node=${NODE_BIN:-/opt/plesk/node/24/bin/node}
python3 -m unittest discover -s tests -v
find src -type f \( -name '*.php' -o -name '*.phtml' \) -exec "$task_php" -l {} \;
"$task_php" tests/php_checks.php
"$task_php" -r '$doc = new DOMDocument(); $doc->load("src/meta.xml"); if (!$doc->schemaValidate("/usr/local/psa/admin/plib/modules/meta.xsd")) { exit(1); } echo "Plesk metadata schema valid\n";'
"$task_node" --check src/htdocs/dist/app.js
"$task_node" tests/frontend_checks.js
