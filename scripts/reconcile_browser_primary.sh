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
  root_entries=$(kcadm get authentication/flows/Baobab%20browser/executions -r baobab)
  # GET authentication/flows returns TOP-LEVEL flows only. Child IDs come
  # from recursive execution references, including fresh non-top-level imports.
  forms_id=$(jq -er '[.[]|select(.displayName=="Baobab forms")|.flowId]|unique|select(length==1)|.[0]' <<< "$root_entries")
  attached=$(jq -c --arg primary "$primary" '[.[]|select((.level // 0)==0 and .displayName==$primary)]' <<< "$root_entries")
  jq -e 'length<=1' <<< "$attached" >/dev/null
  if [ "$(jq 'length' <<< "$attached")" = 1 ]; then
    primary_id=$(jq -er '.[0].flowId' <<< "$attached")
  else
    # An off-path repair candidate is deliberately top-level/discoverable
    # until it is attached. No realm/client binding is ever changed to it.
    # Require our reserved description before resuming a prior candidate.
    primary_id=$(jq -r --arg alias "$primary" '[.[]|select(.alias==$alias)]|
      if length==0 then "" elif length==1 and (.[0].builtIn // false)==false and .[0].topLevel==true and
        .[0].description=="Identify the user before evaluating assurance conditions." then .[0].id
      else error("invalid primary repair candidate") end' <<< "$flows")
  fi
  # Refuse unknown active branches instead of silently restructuring an
  # operator-customised realm. Disabled historical entries remain untouched.
  jq -e --arg primary "$primary" 'all(.[]|select((.level // 0)==0);
    if .requirement=="DISABLED" then true
    elif .displayName==$primary then (.requirement=="REQUIRED" or .requirement=="CONDITIONAL")
    elif .providerId=="auth-cookie" or .providerId=="identity-provider-redirector" or .displayName=="Baobab forms" then .requirement=="ALTERNATIVE"
    elif .displayName=="Baobab - Step-Up" or .displayName=="Baobab - Passkey Step-Up" then .requirement=="CONDITIONAL"
    else false end)' <<< "$root_entries" >/dev/null
  # Both assurance branches must remain present, conditional and ordered.
  jq -e '[.[]|select((.level // 0)==0 and (.displayName=="Baobab - Step-Up" or .displayName=="Baobab - Passkey Step-Up"))] as $s |
    ($s|length)==2 and all($s[];.requirement=="CONDITIONAL" and .priority>5) and
    ([$s[]|select(.displayName=="Baobab - Passkey Step-Up")][0].priority < [$s[]|select(.displayName=="Baobab - Step-Up")][0].priority)' <<< "$root_entries" >/dev/null
  legacy=$(jq -c '[.[]|select((.level // 0)==0 and (.providerId=="auth-cookie" or .providerId=="identity-provider-redirector" or .displayName=="Baobab forms"))]' <<< "$root_entries")
  if [ "$(jq 'length' <<< "$attached")" = 0 ]; then
    # A previously disabled/customised identification branch is operator
    # policy, not our legacy default. Never reactivate it while repairing.
    jq -e 'length==3 and all(.[];.requirement=="ALTERNATIVE")' <<< "$legacy" >/dev/null
  fi
  if [ -z "$primary_id" ]; then
    # Construct an unattached flow first. An interruption here cannot replace
    # or weaken the active browser flow. Retry resumes the same named flow.
    kcadm create authentication/flows -r baobab -s "alias=$primary" \
      -s providerId=basic-flow -s topLevel=true -s builtIn=false \
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
  jq -e --arg forms "$forms_id" '[.[]|select((.level // 0)==0 and .providerId!="conditional-level-of-authentication")] as $e |
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
    jq -e --arg child "$primary_id" '.[0].flowId==$child and (.[0].requirement=="REQUIRED" or .[0].requirement=="CONDITIONAL") and .[0].priority==5' <<< "$attached" >/dev/null
  fi
  for id in $(jq -r '.[]|select(.requirement!="DISABLED")|.id' <<< "$legacy"); do
    jq --arg id "$id" '.[]|select(.id==$id)|.requirement="DISABLED"' <<< "$legacy" > "$BROWSER_REPAIR_DIR/document.json"
    # Retain old references disabled for audit/recovery. Do not cascade-delete
    # the still-used forms/privileged-MFA graph or weaken a step-up branch.
    kcadm update authentication/flows/Baobab%20browser/executions -r baobab -f "$BROWSER_REPAIR_DIR/document.json" >/dev/null
  done
  rm -rf -- "$BROWSER_REPAIR_DIR"
  unset BROWSER_REPAIR_DIR
  reconcile_browser_primary_loa
  reconcile_passkey_enrollment_guard
  echo 'Browser primary identity and current-request LoA 1 verified; MFA and step-up retained.'
}

# Keycloak ConditionalLoaAuthenticator returns true for EVERY configured level
# while currentAuthenticationLoa is zero. A plain REQUIRED identity wrapper
# therefore triggers the level-3 WebAuthn branch even on an ordinary login.
# Use the native LoA-1 condition's onParentFlowSuccess callback: only successful
# primary authentication records level 1, before root assurance is evaluated.
# max-age=0 records this request only, never reusable MFA/passkey assurance.
reconcile_browser_primary_loa() {
  local entries predicate primary root model config
  entries=$(kcadm get authentication/flows/Baobab%20-%20Primary%20Authentication/executions -r baobab)
  predicate=$(jq -c '[.[]|select((.level // 0)==0 and .providerId=="conditional-level-of-authentication")]' <<< "$entries")
  jq -e 'length<=1' <<< "$predicate" >/dev/null
  root=$(kcadm get authentication/flows/Baobab%20browser/executions -r baobab)
  primary=$(jq -ce '[.[]|select((.level // 0)==0 and .displayName=="Baobab - Primary Authentication")]|select(length==1)|.[0]' <<< "$root")
  BROWSER_REPAIR_DIR=$(mktemp -d)
  if [ "$(jq 'length' <<< "$predicate")" = 0 ]; then
    # Prepare while still REQUIRED, so an interrupted/unconfigured condition
    # cannot disable primary identification. Fresh imports already have it.
    jq -e '.requirement=="REQUIRED"' <<< "$primary" >/dev/null
    jq -n --arg parent "$(jq -r '.flowId' <<< "$primary")" \
      '{parentFlow:$parent,authenticator:"conditional-level-of-authentication",authenticatorFlow:false,requirement:"REQUIRED",priority:0}' > "$BROWSER_REPAIR_DIR/document.json"
    kcadm create authentication/executions -r baobab -f "$BROWSER_REPAIR_DIR/document.json" >/dev/null
    entries=$(kcadm get authentication/flows/Baobab%20-%20Primary%20Authentication/executions -r baobab)
    predicate=$(jq -ce '[.[]|select((.level // 0)==0 and .providerId=="conditional-level-of-authentication")]|select(length==1)' <<< "$entries")
  fi
  jq -e '.[0].requirement=="REQUIRED" and (.[0].priority // 0)==0' <<< "$predicate" >/dev/null
  # The execution model carries authenticatorConfig, unlike execution-info's
  # authenticationConfig field. Read the actual model to avoid API ambiguity.
  model=$(kcadm get "authentication/executions/$(jq -r '.[0].id' <<< "$predicate")" -r baobab)
  config=$(jq -r '.authenticatorConfig // ""' <<< "$model")
  if [ -z "$config" ]; then
    jq -e '.requirement=="REQUIRED"' <<< "$primary" >/dev/null
    jq -n '{alias:"baobab-primary-loa-silver",config:{"loa-condition-level":"1","loa-max-age":"0"}}' > "$BROWSER_REPAIR_DIR/document.json"
    kcadm create "authentication/executions/$(jq -r '.id' <<< "$model")/config" -r baobab -f "$BROWSER_REPAIR_DIR/document.json" >/dev/null
    model=$(kcadm get "authentication/executions/$(jq -r '.id' <<< "$model")" -r baobab)
    config=$(jq -er '.authenticatorConfig' <<< "$model")
  fi
  # Refuse custom baseline policy, duplicate/extra fields or inflated levels;
  # never overwrite operator assurance policy as part of a login repair.
  config=$(kcadm get "authentication/config/$config" -r baobab)
  jq -e 'del(.id)=={alias:"baobab-primary-loa-silver",config:{"loa-condition-level":"1","loa-max-age":"0"}}' <<< "$config" >/dev/null
  if [ "$(jq -r '.requirement' <<< "$primary")" = REQUIRED ]; then
    jq '.requirement="CONDITIONAL"' <<< "$primary" > "$BROWSER_REPAIR_DIR/document.json"
    # Security cutover is last: a validated LoA-1 predicate and all three
    # identification alternatives exist before enabling conditional semantics.
    kcadm update authentication/flows/Baobab%20browser/executions -r baobab -f "$BROWSER_REPAIR_DIR/document.json" >/dev/null
  fi
  rm -rf -- "$BROWSER_REPAIR_DIR"
  unset BROWSER_REPAIR_DIR
}

# A required passwordless authenticator with no enrolled key throws an internal
# CREDENTIAL_SETUP_REQUIRED error. Do not call that a valid denial or enable
# automatic enrollment and accidentally attest LoA 3. The native configured-user
# predicate skips only that impossible factor branch. ConditionalLoaAuthenticator
# onTopFlowSuccess still denies an essential unmet LoA via acrNotFulfilled/400;
# configured users still execute REQUIRED WebAuthn with unchanged LoA policy.
reconcile_passkey_enrollment_guard() {
  local root branch entries guard model config
  root=$(kcadm get authentication/flows/Baobab%20browser/executions -r baobab)
  branch=$(jq -ce '[.[]|select((.level // 0)==0 and .displayName=="Baobab - Passkey Step-Up")]|select(length==1)|.[0]|select(.requirement=="CONDITIONAL")' <<< "$root")
  entries=$(kcadm get authentication/flows/Baobab%20-%20Passkey%20Step-Up/executions -r baobab)
  jq -e '[.[]|select((.level // 0)==0 and .providerId!="conditional-user-configured")]|sort_by(.priority)|
    length==2 and .[0].providerId=="conditional-level-of-authentication" and .[0].requirement=="REQUIRED" and .[0].priority==10 and
    .[1].providerId=="webauthn-authenticator-passwordless" and .[1].requirement=="REQUIRED" and .[1].priority==20' <<< "$entries" >/dev/null
  model=$(kcadm get "authentication/executions/$(jq -r '.[]|select((.level // 0)==0 and .providerId=="conditional-level-of-authentication")|.id' <<< "$entries")" -r baobab)
  config=$(kcadm get "authentication/config/$(jq -er '.authenticatorConfig' <<< "$model")" -r baobab)
  jq -e 'del(.id)=={alias:"baobab-passkey-step-up-loa-3",config:{"loa-condition-level":"3","loa-max-age":"300"}}' <<< "$config" >/dev/null
  guard=$(jq -c '[.[]|select((.level // 0)==0 and .providerId=="conditional-user-configured")]' <<< "$entries")
  jq -e 'length<=1' <<< "$guard" >/dev/null
  if [ "$(jq 'length' <<< "$guard")" = 0 ]; then
    BROWSER_REPAIR_DIR=$(mktemp -d)
    jq -n --arg parent "$(jq -r '.flowId' <<< "$branch")" \
      '{parentFlow:$parent,authenticator:"conditional-user-configured",authenticatorFlow:false,requirement:"REQUIRED",priority:15}' > "$BROWSER_REPAIR_DIR/document.json"
    kcadm create authentication/executions -r baobab -f "$BROWSER_REPAIR_DIR/document.json" >/dev/null
    rm -rf -- "$BROWSER_REPAIR_DIR"
    unset BROWSER_REPAIR_DIR
  else
    jq -e '.[0].requirement=="REQUIRED" and .[0].priority==15' <<< "$guard" >/dev/null
  fi
}
