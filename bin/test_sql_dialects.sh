#!/usr/bin/env bash
set -euo pipefail

sesame_postgres_container="sesame-storage-postgres-$$"
sesame_mysql_container="sesame-storage-mysql-$$"

cleanup() {
  docker stop "$sesame_postgres_container" "$sesame_mysql_container" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run --rm -d \
  --name "$sesame_postgres_container" \
  -e POSTGRES_USER=sesame_test \
  -e POSTGRES_PASSWORD=sesame_test \
  -e POSTGRES_DB=sesame_test \
  -p 127.0.0.1::5432 \
  postgres:16-alpine >/dev/null

docker run --rm -d \
  --name "$sesame_mysql_container" \
  -e MYSQL_ROOT_PASSWORD=sesame_root \
  -e MYSQL_DATABASE=sesame_test \
  -e MYSQL_USER=sesame_test \
  -e MYSQL_PASSWORD=sesame_test \
  -p 127.0.0.1::3306 \
  mysql:8.4 >/dev/null

for attempt in {1..60}; do
  if docker exec "$sesame_postgres_container" pg_isready -U sesame_test -d sesame_test >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "$sesame_postgres_container" pg_isready -U sesame_test -d sesame_test >/dev/null

for attempt in {1..60}; do
  if docker exec -e MYSQL_PWD=sesame_test "$sesame_mysql_container" \
    mysql -h 127.0.0.1 -u sesame_test -D sesame_test -e 'SELECT 1' >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec -e MYSQL_PWD=sesame_test "$sesame_mysql_container" \
  mysql -h 127.0.0.1 -u sesame_test -D sesame_test -e 'SELECT 1' >/dev/null

sesame_postgres_address="$(docker port "$sesame_postgres_container" 5432/tcp)"
sesame_mysql_address="$(docker port "$sesame_mysql_container" 3306/tcp)"
sesame_postgres_port="${sesame_postgres_address##*:}"
sesame_mysql_port="${sesame_mysql_address##*:}"

SESAME_TEST_POSTGRES_URL="postgres://sesame_test:sesame_test@127.0.0.1:${sesame_postgres_port}/sesame_test" \
SESAME_TEST_MYSQL_URL="mysql://sesame_test:sesame_test@127.0.0.1:${sesame_mysql_port}/sesame_test" \
  node --import=@poppinss/ts-exec --enable-source-maps bin/test.ts --files=kysely_sql_dialects
