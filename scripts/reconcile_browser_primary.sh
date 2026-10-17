#!/usr/bin/env bash
# Sourced by bootstrap.sh after authenticated kcadm setup. This is a hierarchy
# repair, not a policy exception: password/SSO identification must finish before
# the existing OTP/passkey assurance conditions can evaluate a known user.
#
# Keycloak 26.7.5 DefaultAuthenticationFlow.fillListsOfExecutions treats
# CONDITIONAL siblings as required and clears ALTERNATIVE siblings immediately.
# Therefore putting assurance conditions beside cookie/idp/forms silently
# prevents those identification alternatives from executing at all.

reconcile_browser_primary() {
  local primary='Baobab - Primary Authentication' root='Baobab browser'
  local flows root_entries primary_id forms_id root_id current legacy attached entries id model
  current=$(kcadm get realms/baobab | jq -er '.browserFlow')
  [ "$current" = "$root" ] || {
    echo 'Browser hierarchy repair refused: a custom browser flow requires review.' >&2; return 1;
  }
  flows=$(kcadm get authentication/flows -r baobab)
  # Keycloak's primitive false/zero defaults may be absent in its JSON.
  # Interpret the representation's typed defaults, not absence as true.
  root_id=$(jq -er --arg alias "$root" '[.[]|select(.alias==$alias and (.builtIn // false)==false)]|select(length==1)|.[0].id' <<< "$flows")
  forms_id=$(jq -er '[.[]|select(.alias=="Baobab forms")]|select(length==1)|.[0].id' <<< "$flows")
  primary_id=$(jq -r --arg alias "$primary" '[.[]|select(.alias==$alias)]|if length==0 then "" elif length==1 and (.[0].builtIn // false)==false and (.[0].topLevel // false)==false then .[0].id else error("invalid primary flow") end' <<< "$flows")
  root_entries=$(kcadm get authentication/flows/Baobab%20browser/executions -r baobab)
  # Refuse unknown active branches instead of silently restructuring an
  # operator-customised realm. Disabled historical entries remain untouched.
  jq -e --arg primary "$primary" 'all(.[]|select((.level // 0)==0);
    if .requirement=="DISABLED" then true
    elif .displayName==$primary then .requirement=="REQUIRED"
    elif .providerId=="auth-cookie" or .providerId=="identity-provider-redirector" or .displayName=="Baobab forms" then .requirement=="ALTERNATIVE"
    elif .displayName=="Baobab - Step-Up" or .displayName=="Baobab - Passkey Step-Up" then .requirement=="CONDITIONAL"
    else false end)' <<< "$root_entries" >/dev/null
  # Both assurance branches must remain present, conditional and ordered.
  jq -e '[.[]|select((.level // 0)==0 and (.displayName=="Baobab - Step-Up" or .displayName=="Baobab - Passkey Step-Up"))] as $s |
    ($s|length)==2 and all($s[];.requirement=="CONDITIONAL" and .priority>5) and
    ([$s[]|select(.displayName=="Baobab - Passkey Step-Up")][0].priority < [$s[]|select(.displayName=="Baobab - Step-Up")][0].priority)' <<< "$root_entries" >/dev/null
  legacy=$(jq -c '[.[]|select((.level // 0)==0 and (.providerId=="auth-cookie" or .providerId=="identity-provider-redirector" or .displayName=="Baobab forms"))]' <<< "$root_entries")
  attached=$(jq -c --arg primary "$primary" '[.[]|select((.level // 0)==0 and .displayName==$primary)]' <<< "$root_entries")
  jq -e 'length<=1' <<< "$attached" >/dev/null
  if [ "$(jq 'length' <<< "$attached")" = 0 ]; then
    # A previously disabled/customised identification branch is operator
    # policy, not our legacy default. Never reactivate it while repairing.
    jq -e 'length==3 and all(.[];.requirement=="ALTERNATIVE")' <<< "$legacy" >/dev/null
  fi
  if [ -z "$primary_id" ]; then
    # Construct an unattached flow first. An interruption here cannot replace
    # or weaken the active browser flow. Retry resumes the same named flow.
    kcadm create authentication/flows -r baobab -s "alias=$primary" \
      -s providerId=basic-flow -s topLevel=false -s builtIn=false \
      -s 'description=Identify the user before evaluating assurance conditions.' >/dev/null
    flows=$(kcadm get authentication/flows -r baobab)
    primary_id=$(jq -er --arg alias "$primary" '[.[]|select(.alias==$alias)]|select(length==1)|.[0].id' <<< "$flows")
  fi
  BROWSER_REPAIR_DIR=$(mktemp -d)
  for id in $(jq -r '.[].id' <<< "$legacy"); do
    # The generic POST /authentication/executions supports an existing
    # flowId. Copy the execution reference, never delete its shared child
    # flow: deleting an old forms execution cascades and would break the new
    # parent as well. Authenticator configuration IDs are preserved exactly.
    model=$(kcadm get "authentication/executions/$id" -r baobab)
    entries=$(kcadm get authentication/flows/Baobab%20-%20Primary%20Authentication/executions -r baobab)
    local match existing
    match=$(jq -r --argjson model "$model" --arg forms "$forms_id" '[.[]|select((.level // 0)==0)|select(
      if $model.authenticatorFlow then .flowId==$forms else .providerId==$model.authenticator end)] |
      if length==0 then "" elif length==1 then .[0].id else error("duplicate primary execution") end' <<< "$entries")
    if [ -n "$match" ]; then
      existing=$(kcadm get "authentication/executions/$match" -r baobab)
      jq -e --argjson original "$model" '.requirement=="ALTERNATIVE" and
        .authenticator==$original.authenticator and .authenticatorFlow==$original.authenticatorFlow and
        .flowId==$original.flowId and .authenticatorConfig==$original.authenticatorConfig and
        .priority==$original.priority' <<< "$existing" >/dev/null
      continue
    fi
    jq --arg parent "$primary_id" 'del(.id)|.parentFlow=$parent|.requirement="ALTERNATIVE"' <<< "$model" > "$BROWSER_REPAIR_DIR/document.json"
    kcadm create authentication/executions -r baobab -f "$BROWSER_REPAIR_DIR/document.json" >/dev/null
  done
  entries=$(kcadm get authentication/flows/Baobab%20-%20Primary%20Authentication/executions -r baobab)
  # Never attach an empty, partial, duplicated or policy-modified primary
  # flow. Fresh imports and interrupted repairs meet the same invariant.
  jq -e --arg forms "$forms_id" '[.[]|select((.level // 0)==0)] as $e |
    ($e|length)==3 and all($e[];.requirement=="ALTERNATIVE") and
    ([$e[]|select(.providerId=="auth-cookie")]|length)==1 and
    ([$e[]|select(.providerId=="identity-provider-redirector")]|length)==1 and
    ([$e[]|select(.flowId==$forms)]|length)==1' <<< "$entries" >/dev/null
  if [ "$(jq 'length' <<< "$attached")" = 0 ]; then
    jq -n --arg parent "$root_id" --arg child "$primary_id" \
      '{parentFlow:$parent,flowId:$child,authenticatorFlow:true,requirement:"REQUIRED",priority:5}' > "$BROWSER_REPAIR_DIR/document.json"
    # This single REST transaction is the security cutover: the fully
    # populated REQUIRED primary precedes both untouched assurance branches.
    kcadm create authentication/executions -r baobab -f "$BROWSER_REPAIR_DIR/document.json" >/dev/null
  else
    jq -e --arg child "$primary_id" '.[0].flowId==$child and .[0].requirement=="REQUIRED" and .[0].priority==5' <<< "$attached" >/dev/null
  fi
  for id in $(jq -r '.[]|select(.requirement!="DISABLED")|.id' <<< "$legacy"); do
    jq --arg id "$id" '.[]|select(.id==$id)|.requirement="DISABLED"' <<< "$legacy" > "$BROWSER_REPAIR_DIR/document.json"
    # Retain old references disabled for audit/recovery. Do not cascade-delete
    # the still-used forms/privileged-MFA graph or weaken a step-up branch.
    kcadm update authentication/flows/Baobab%20browser/executions -r baobab -f "$BROWSER_REPAIR_DIR/document.json" >/dev/null
  done
  rm -rf -- "$BROWSER_REPAIR_DIR"
  unset BROWSER_REPAIR_DIR
  echo 'Browser primary authentication hierarchy verified; MFA and step-up retained.'
}
