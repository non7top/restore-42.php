COMPOSE := docker compose
# Inside the Docker network the db service is reachable as 'db:3306'
DB_HOST := db
DB_PORT := 3306
DB_USER := testuser
DB_PASS := testpass
DB_NAME := testdb
# Web service exposed on host
WEB_URL := http://127.0.0.1:8080
COOKIE  := /tmp/restore-test-cookies

.PHONY: all lint syntax phpcs test _run-tests clean-hash

all: lint test

# ── Lint ────────────────────────────────────────────────────────────────────

lint: syntax phpcs

syntax:
	@echo "==> PHP syntax check..."
	$(COMPOSE) run --rm -T web php -l /var/www/html/restore-42.php

phpcs:
	@echo "==> phpcs PSR-12 check..."
	$(COMPOSE) run --rm -T web sh -c '\
	  if ! command -v phpcs >/dev/null 2>&1; then \
	    php -r "copy(\"https://squizlabs.github.io/PHP_CodeSniffer/phpcs.phar\",\"/tmp/phpcs.phar\");"; \
	    alias phpcs="php /tmp/phpcs.phar"; \
	    php /tmp/phpcs.phar --standard=PSR12 \
	      --exclude=Generic.Files.LineLength,PSR1.Files.SideEffects \
	      /var/www/html/restore-42.php; \
	  else \
	    phpcs --standard=PSR12 \
	      --exclude=Generic.Files.LineLength,PSR1.Files.SideEffects \
	      /var/www/html/restore-42.php; \
	  fi'

# ── Integration tests ────────────────────────────────────────────────────────

test:
	@echo "==> Starting services..."
	$(COMPOSE) up -d --wait
	@echo "==> Running integration tests..."
	$(MAKE) _run-tests || { $(MAKE) clean-hash; exit 1; }
	$(MAKE) clean-hash
	@echo "==> All tests passed."

_run-tests:
	@echo "--- auth: first login sets password hash ---"
	curl -sf -c $(COOKIE) -b $(COOKIE) -X POST \
	  '$(WEB_URL)/restore-42.php?action=login' \
	  -d 'password=testpass123' | grep -q '"ok":true'
	@echo "--- check_auth returns true ---"
	curl -sf -c $(COOKIE) -b $(COOKIE) \
	  '$(WEB_URL)/restore-42.php?action=check_auth' | grep -q '"auth":true'
	@echo "--- upload SQL file ---"
	printf 'CREATE TABLE smoke (id INT PRIMARY KEY, v VARCHAR(50));\nINSERT INTO smoke VALUES (1,"ok");\n' \
	  > /tmp/smoke.sql
	curl -sf -c $(COOKIE) -b $(COOKIE) -X POST \
	  '$(WEB_URL)/restore-42.php?action=upload' \
	  -F 'file=@/tmp/smoke.sql' | grep -q '"done":true'
	@echo "--- list_files shows upload ---"
	curl -sf -c $(COOKIE) -b $(COOKIE) \
	  '$(WEB_URL)/restore-42.php?action=list_files' | grep -q 'smoke.sql'
	@echo "--- test_db connects to MariaDB ---"
	curl -sf -c $(COOKIE) -b $(COOKIE) -X POST \
	  '$(WEB_URL)/restore-42.php?action=test_db' \
	  -d 'db_host=$(DB_HOST)&db_port=$(DB_PORT)&db_user=$(DB_USER)&db_pass=$(DB_PASS)&db_name=$(DB_NAME)' \
	  | grep -q '"ok":true'
	@echo "--- import SQL ---"
	curl -sf -c $(COOKIE) -b $(COOKIE) -X POST \
	  '$(WEB_URL)/restore-42.php?action=import_sql' \
	  -d 'db_host=$(DB_HOST)&db_port=$(DB_PORT)&db_user=$(DB_USER)&db_pass=$(DB_PASS)&db_name=$(DB_NAME)&create_db=1&sql_file=/var/www/html/.restore/uploads/smoke.sql' \
	  | grep -q '"ok":true'
	@echo "--- HTML page renders ---"
	curl -sf '$(WEB_URL)/restore-42.php' | grep -q 'auth-screen'
	@rm -f $(COOKIE)

# Reset STORED_PASS_HASH to '' after test run so the file stays clean for git.
# Uses sed on the host file (volume-mounted, so changes from inside the
# container are visible here). The comment on the define line is preserved.
clean-hash:
	@sed -i "s/^define('STORED_PASS_HASH', '[^']*');/define('STORED_PASS_HASH', '');/" \
	  restore-42.php
	@echo "==> STORED_PASS_HASH reset to empty."
