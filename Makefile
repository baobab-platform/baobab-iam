# Makefile for baobab-iam local development
.PHONY: dev-up dev-down bootstrap test integration-test role-policy lint clean check-contract-lock

SHARED_CONTRACTS_DIR ?= ../shared
INFRASTRUCTURE_DIR ?= ../infrastructure

dev-up:
	docker-compose up -d

dev-down:
	docker-compose down

bootstrap:
	docker-compose exec -e BOOTSTRAP_WORKLOAD_CLIENT_SECRET=$$BOOTSTRAP_WORKLOAD_CLIENT_SECRET keycloak /opt/keycloak/bootstrap.sh

test:
	@echo "Running health checks..."
	@# Keycloak 26 serves health/metrics on a separate management interface
	@# (port 9000 by default), not the main HTTP port (8080) — see
	@# https://www.keycloak.org/server/management-interface.
	@curl -s http://localhost:9000/health/ready | grep -q "UP" || (echo "Keycloak not ready" && exit 1)
	@echo "All tests passed."

integration-test:
	./tests/integration/run.sh

# EA-01 consumer lock (needs Shared checkout with history).
check-contract-lock:
	@test -d "$(SHARED_CONTRACTS_DIR)" || { echo "error: set SHARED_CONTRACTS_DIR to a baobab-platform/shared checkout" >&2; exit 1; }
	python3 $(SHARED_CONTRACTS_DIR)/scripts/contract_lock.py check \
		--repository-root . \
		--shared-repo $(SHARED_CONTRACTS_DIR) \
		--mode enforce

# Separation-of-duties rules Keycloak cannot enforce (config/governance/role-policy.json).
role-policy:
	./scripts/check-role-policy.sh

lint:
	@echo "Checking YAML files..."
	@yamllint --no-warnings .
	@echo "Checking shell scripts..."
	@shellcheck scripts/*.sh
	@echo "Checking JSON files..."
	@find config -name '*.json' -exec jq empty {} \;

clean:
	docker-compose down -v
