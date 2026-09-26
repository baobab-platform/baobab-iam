# Makefile for baobab-iam local development
.PHONY: dev-up dev-down bootstrap test integration-test role-policy lint clean

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