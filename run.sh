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
VERSION=3.50.3.0
MIRRORS=(
  "https://repo1.maven.org/maven2/org/xerial/sqlite-jdbc/$VERSION/sqlite-jdbc-$VERSION.jar"
  "https://github.com/xerial/sqlite-jdbc/releases/download/$VERSION/sqlite-jdbc-$VERSION.jar"
)
if [ ! -s "$DRIVER" ]; then
  mkdir -p lib
  for url in "${MIRRORS[@]}"; do
    echo "Downloading SQLite JDBC driver (${url#https://}) ..."
    if curl -fL --retry 3 --retry-delay 2 --connect-timeout 20 -o "$DRIVER.tmp" "$url"; then
      mv "$DRIVER.tmp" "$DRIVER"
      break
    fi
    rm -f "$DRIVER.tmp"
  done
  if [ ! -s "$DRIVER" ]; then
    echo "Could not download the driver. Check your internet connection and run ./run.sh again."
    exit 1
  fi
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
