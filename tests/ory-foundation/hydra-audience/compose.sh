# Sourced by the disposable loopback acceptance scripts.
ory_compose=(-f docker-compose.ory.yml)
if [[ "${ORY_HYDRA_AUDIENCE_CANDIDATE:-0}" == 1 ]]; then
  test -f ory-foundation-evidence/hydra-backport-build.json
  test -f ory-foundation-evidence/hydra-candidate-image.txt
  expected_image=$(cat ory-foundation-evidence/hydra-candidate-image.txt)
  actual_image=$(docker image inspect --format '{{.Id}}' baobab-hydra-audience-candidate:ci)
  [[ "$expected_image" == "$actual_image" ]]
  ory_compose+=(-f tests/ory-foundation/hydra-audience/compose.yml)
fi
