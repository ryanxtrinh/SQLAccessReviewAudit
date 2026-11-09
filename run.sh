#!/usr/bin/env bash
# Builds and runs the audit. Needs Java 17+ and an internet connection the first time
# (to download the SQLite JDBC driver into lib/).
#
#   ./run.sh           run the audit and write the report
#   ./run.sh verify    check the results against the planted issues
#   ./run.sh generate  rebuild the fictional dataset (data/seed.sql)
set -euo pipefail
cd "$(dirname "$0")"

DRIVER=lib/sqlite-jdbc.jar
if [ ! -f "$DRIVER" ]; then
  echo "Downloading SQLite JDBC driver..."
  mkdir -p lib
  curl -fsSL -o "$DRIVER" https://github.com/xerial/sqlite-jdbc/releases/download/3.50.3.0/sqlite-jdbc-3.50.3.0.jar
fi

mkdir -p build
javac -d build $(find src/main/java -name '*.java')

if [ "${1:-}" = "verify" ]; then
  java -cp "build:$DRIVER" audit.Verify
elif [ "${1:-}" = "generate" ]; then
  java -cp build audit.DataGenerator
else
  java -cp "build:$DRIVER" audit.AuditRunner
fi
