#!/bin/sh
set -eu

safe_identifier() {
  printf '%s' "$1" | grep -Eq '^[A-Za-z0-9_]{1,64}$'
}
read_secret() {
  value=$(sed -n '1p' "$1")
  case "$value" in ''|*[!A-Za-z0-9_-]*) return 1 ;; esac
  [ "${#value}" -ge 32 ] || return 1
  printf '%s' "$value"
}

database=${MAILTRAIN_DB_NAME:?}
migration_user=${MAILTRAIN_DB_MIGRATION_USER:?}
runtime_user=${MAILTRAIN_DB_RUNTIME_USER:?}
report_user=${MAILTRAIN_DB_REPORT_USER:?}
safe_identifier "$database" && safe_identifier "$migration_user" && safe_identifier "$runtime_user" && safe_identifier "$report_user" || {
  echo 'Database and principal names must be simple identifiers' >&2
  exit 1
}
migration_secret=$(read_secret "${MAILTRAIN_DB_MIGRATION_SECRET_FILE:?}")
runtime_secret=$(read_secret "${MAILTRAIN_DB_RUNTIME_SECRET_FILE:?}")
report_secret=$(read_secret "${MAILTRAIN_DB_REPORT_SECRET_FILE:?}")
root_secret=$(sed -n '1p' /run/secrets/db_root_secret)

MYSQL_PWD=$root_secret mariadb --protocol=socket -uroot <<SQL
CREATE DATABASE IF NOT EXISTS \`$database\` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
CREATE USER IF NOT EXISTS '$migration_user'@'%' IDENTIFIED BY '$migration_secret' REQUIRE SSL;
CREATE USER IF NOT EXISTS '$runtime_user'@'%' IDENTIFIED BY '$runtime_secret' REQUIRE SSL;
CREATE USER IF NOT EXISTS '$report_user'@'%' IDENTIFIED BY '$report_secret' REQUIRE SSL;
GRANT ALL PRIVILEGES ON \`$database\`.* TO '$migration_user'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON \`$database\`.* TO '$runtime_user'@'%';
GRANT CREATE, ALTER, DROP, INDEX, CREATE TEMPORARY TABLES ON \`$database\`.* TO '$runtime_user'@'%';
GRANT SELECT ON \`$database\`.* TO '$report_user'@'%';
FLUSH PRIVILEGES;
SQL
