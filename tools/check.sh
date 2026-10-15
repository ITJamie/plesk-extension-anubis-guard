#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
task_php=${PHP_BIN:-/opt/plesk/php/8.4/bin/php}
task_node=${NODE_BIN:-/opt/plesk/node/24/bin/node}
python3 tools/metadata.py
python3 -m unittest discover -s tests -v
find src -type f \( -name '*.php' -o -name '*.phtml' \) -exec "$task_php" -l {} +
"$task_php" tests/php_checks.php
task_schema=${PLESK_META_XSD:-/usr/local/psa/admin/plib/modules/meta.xsd}
if [ -f "$task_schema" ]; then
    "$task_php" -r '$doc = new DOMDocument(); $doc->load("src/meta.xml"); if (!$doc->schemaValidate($argv[1])) { exit(1); } echo "Plesk metadata schema valid\n";' "$task_schema"
elif [ -n "${PLESK_META_XSD:-}" ]; then
    echo "Configured PLESK_META_XSD does not exist: $task_schema" >&2
    exit 1
else
    echo "Plesk schema unavailable; portable metadata checks passed. Run on Plesk for full schema validation."
fi
"$task_node" --check src/htdocs/dist/app.js
"$task_node" tests/frontend_checks.js
