# Sourced by the disposable loopback acceptance scripts.
# CI-only network override: provider containers have no external egress.
# The developer-facing docker-compose.ory.yml remains unchanged.
ory_compose=(-f docker-compose.ory.yml -f tests/ory-foundation/compose.isolated.yml)
if [[ "${ORY_HYDRA_AUDIENCE_CANDIDATE:-0}" == 1 ]]; then
  test -f ory-foundation-evidence/hydra-backport-build.json
  test -f ory-foundation-evidence/hydra-candidate-image.txt
  expected_image=$(cat ory-foundation-evidence/hydra-candidate-image.txt)
  actual_image=$(docker image inspect --format '{{.Id}}' baobab-hydra-audience-candidate:ci)
  [[ "$expected_image" == "$actual_image" ]]
  ory_compose+=(-f tests/ory-foundation/hydra-audience/compose.yml)
fi
