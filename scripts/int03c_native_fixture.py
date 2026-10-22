#!/usr/bin/env python3
"""INT-03C only: independently registered native Ory proof-client plan.

Authorisation is the exact *committed* Accepted Shared #366 workload rows,
not a supplied plan or local copy. This prepares no credentials or Principal.
The maintained IAM Ory adapter alone can create disposable clients, with a
supervisor recording intent before the POST and deleting its own clients.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import yaml

SHARED = "74dd98d47e678fc479bb4bfc4138d601fb53319e"
OWNER = "baobab-int03c-issuer-owner"
VERIFIER = "baobab-int03c-issuer-verifier"
EXPECTED = {
    OWNER: {
        "repository":"baobab-platform/infrastructure",
        "owner":"baobab-platform/infrastructure",
        "runtime":"INT-03C supervised disposable issuer proof owner",
        "environment":"development",
        "allowed_audiences":["baobab-control-plane"],
        "allowed_scopes":["context:resolve"],
        "credential_type":"client_credentials",
        "rotation_owner":"baobab-platform/infrastructure",
        "status":"ACTIVE",
    },
    VERIFIER: {
        "repository":"baobab-platform/infrastructure",
        "owner":"baobab-platform/infrastructure",
        "runtime":"INT-03C independent disposable issuer verifier",
        "environment":"development",
        "allowed_audiences":["baobab-control-plane"],
        "allowed_scopes":["context:resolve"],
        "credential_type":"client_credentials",
        "rotation_owner":"baobab-platform/infrastructure",
        "status":"ACTIVE",
    },
}


def committed_registry(checkout):
    checkout=Path(checkout)
    if checkout.is_symlink() or not checkout.is_dir():
        raise ValueError("Shared source checkout missing")
    result=subprocess.run(["git","-C",str(checkout),"rev-parse","HEAD"],
                          capture_output=True,text=True,check=True,timeout=10)
    if result.stdout.strip()!=SHARED:
        raise ValueError("unreviewed Shared commit")
    dirty=subprocess.run(["git","-C",str(checkout),"status","--porcelain",
                          "--untracked-files=all"],capture_output=True,
                         text=True,check=True,timeout=10)
    if dirty.stdout.strip():
        raise ValueError("Shared source is not clean")
    raw=subprocess.run(["git","-C",str(checkout),"show",
                        SHARED+":contracts/identity/v1/workload-registry.yaml"],
                       capture_output=True,text=True,check=True,timeout=10).stdout
    source=yaml.safe_load(raw)
    rows=source["workloads"]
    if any(rows.get(name)!=row for name,row in EXPECTED.items()) or (
        sorted(name for name in rows if name.startswith("baobab-int03c-"))
        != sorted(EXPECTED)):
        raise ValueError("governed identity row or count differs")
    return rows


def make_plan(rows):
    if any(rows.get(k)!=v for k,v in EXPECTED.items()):
        raise ValueError("unapproved source")
    return {
        "schema":"iam.int03c.native-plan.v1",
        "state":"PREPARED_NOT_PROVISIONED",
        "identities_created":False,
        "qualified":False,
        "shared_sha":SHARED,
        "provisioning_specs":[
            {"logical_client_id":name,
             "allowed_scopes":["context:resolve"],
             "audiences":["baobab-control-plane"],
             "auth_method":"client_secret",
             "lifecycle_status":"PROVISIONED",
             "access_token_ttl_seconds":60,
             "require_new":True,
             "metadata":{"environment":"development",
                         "owner":"baobab-platform/infrastructure"}}
            for name in (OWNER,VERIFIER)
        ],
    }


def main(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument("action",choices=("native-plan",))
    p.add_argument("--shared-checkout",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    x=p.parse_args(argv)
    try:
        rows=committed_registry(x.shared_checkout)
        record=make_plan(rows)
        x.output.mkdir(mode=0o700,exist_ok=False)
        target=x.output/"native-plan.json"
        fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,"w") as out:
            json.dump(record,out,sort_keys=True)
            out.write("\n")
        print("INT03C_CANONICAL_PLAN_PREPARED; identities_created=false; qualified=false")
        return 0
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):
        print("INT03C_SHARED_REGISTRY_HOLD",file=sys.stderr)
        return 2


if __name__=="__main__":
    sys.exit(main())
