# Platform L2 — dependency integration

Aligned with [baobab-platform/infrastructure](https://github.com/baobab-platform/infrastructure) integrated testing (Phase C).

## Local provider stack (default)

```bash
cp .env.example .env
make dev-up
make bootstrap
make integration-test
```

Provider runtimes stay in this repository’s Compose. Platform dependencies
(Postgres/RabbitMQ used by other engines) come from infrastructure when needed.

## Contract lock (Phase B / EA-01)

```bash
make check-contract-lock   # SHARED_CONTRACTS_DIR=../shared
```

CI runs `contract_lock.py check --mode enforce` on every PR (full-history Shared checkout).

## Platform L3

Infrastructure owns `make platform-l3`. Optional IAM probe:

```bash
export PLATFORM_IAM_URL=http://127.0.0.1:4444   # example Hydra public URL
cd ../infrastructure && make platform-l3
```

Publishing workload events onto infrastructure RabbitMQ vhost `nabhold` is optional
bus-level L2 and is not required for provider-contract CI.
