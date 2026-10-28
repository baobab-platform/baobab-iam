package tokenprofile

import (
    "strings"
    "testing"
)

func tmsHoldFixture() Config {
    return Config{
        SharedCommit:"ab7a473a1f69784f115ad353e36383faf9b95965",
        Environment:"development",
        Workloads:map[string]Workload{
            "synthetic-valid":{
                Environment:"development",CredentialType:"client_credentials",
                Status:"ACTIVE",Audiences:[]string{"baobab-control-plane"},
                Scopes:[]string{"context:resolve"},
            },
        },
    }
}

func TestTMSProfileDeniedBeforeIssuance(t *testing.T){
    tests:=[]struct{name,id,audience,scope string}{
        {"TMS service","baobab-tms","baobab-control-plane","context:validate"},
        {"TMS validator","baobab-dev-tms-validator","baobab-control-plane","context:validate"},
        {"foreign client TMS audience","synthetic-valid","baobab-tms","context:resolve"},
        {"foreign client TMS scope","synthetic-valid","baobab-control-plane","tms:booking:submit"},
    }
    for _,tc:=range tests {
        t.Run(tc.name,func(t *testing.T){
            c:=tmsHoldFixture()
            w:=c.Workloads["synthetic-valid"]
            w.Audiences=[]string{tc.audience}
            w.Scopes=[]string{tc.scope}
            c.Workloads=map[string]Workload{tc.id:w}
            if err:=c.Validate();err==nil||!strings.Contains(err.Error(),"not accepted"){
                t.Fatalf("proposal accepted: %v",err)
            }
            e:=Evidence{
                ClientID:tc.id,Subject:tc.id,Grant:"client_credentials",
                RequestedScopes:[]string{tc.scope},GrantedScopes:[]string{tc.scope},
                GrantedAudiences:[]string{tc.audience},
            }
            if claims,err:=c.Claims(e);err==nil||claims!=nil{
                t.Fatalf("direct Claims bypassed hold: %v / %v",claims,err)
            }
            request:=WorkloadTokenRequest{
                WorkloadID:tc.id,Audience:tc.audience,Scopes:[]string{tc.scope},
            }
            if _,err:=c.AdmitRequest(request,nil,e);err==nil {
                t.Fatal("canonical request admitted unaccepted TMS authority")
            }
        })
    }
}

func TestTMSGrantInjectionDeniedWithoutRegressingCPValidator(t *testing.T){
    c:=tmsHoldFixture()
    if err:=c.Validate();err!=nil{t.Fatalf("unrelated CP workload blocked: %v",err)}
    e:=Evidence{
        ClientID:"synthetic-valid",Subject:"synthetic-valid",Grant:"client_credentials",
        RequestedScopes:[]string{"context:resolve"},GrantedScopes:[]string{"context:resolve"},
        GrantedAudiences:[]string{"baobab-control-plane"},
    }
    if _,err:=c.Claims(e);err!=nil{t.Fatalf("ordinary workload regressed: %v",err)}
    e.GrantedAudiences=[]string{"baobab-tms"}
    if _,err:=c.Claims(e);err==nil{t.Fatal("unauthorized TMS audience was issued")}
    e.GrantedAudiences=[]string{"baobab-control-plane"}
    e.GrantedScopes=[]string{"tms:booking:submit"}
    if _,err:=c.Claims(e);err==nil{t.Fatal("unauthorized TMS scope was issued")}
    w:=c.Workloads["synthetic-valid"]
    w.Scopes=[]string{"context:validate"}
    c.Workloads["synthetic-valid"]=w
    if err:=c.Validate();err!=nil{
        t.Fatalf("existing registered context:validate resource servers must remain possible: %v",err)
    }
}

func TestTMSHumanAudienceCannotBeProjected(t *testing.T){
    c:=tmsHoldFixture()
    w:=c.Workloads["synthetic-valid"]
    w.HumanTokenProfile=&HumanTokenProfile{Audiences:[]string{"baobab-tms"}}
    c.Workloads["synthetic-valid"]=w
    if err:=c.Validate();err==nil{t.Fatal("unaccepted human audience passed")}
}
