# IAM CTS v2.0 pull request audit

**Observed 11 November 2026, Africa/Johannesburg.** The initial GitHub inventory returned 30 open IAM pull requests, all drafts. The two requested baseline PRs had already merged. The inventory records the original candidate heads. A successor head requires a new CI observation.

## Governing baseline

- [IAM #187](https://github.com/baobab-platform/baobab-iam/pull/187) merged as `ee5295671979eafd92790da3888fd9e043b44c65`. Its reviewed-head CI, Ory live and Foundation checks passed. The approved CTS crosswalk validates 44 requirements, 227 legacy sections and 17 gates. The source also switches the SAML dependency and updates the separately built Hydra candidate.
- [IAM #160](https://github.com/baobab-platform/baobab-iam/pull/160) merged as `5fd97af34a20f814b12af00b938baf7a08c3a5bc`. Its reviewed-head CI, Ory live and Foundation passed. Preserve exact Kratos issuer and subject matching and its positive and negative tests.
- Older heads reported the Crewjam SAML advisory and the Hydra `x/net` finding. Reconcile on the merged CTS baseline and verify live federation and the separate Hydra artifact. Scanner exemptions cannot supply acceptance evidence.
- [Trade #189](https://github.com/baobab-platform/baobab-trade/pull/189) remains a DEV-07/11 consumer companion. Its native Order Module, RabbitMQ and ordinary CI passed at the observed head. Foundation failed. The genuine buyer origin and independent same-event ERP proof remain separate.

## Original candidate inventory

| PR and head | CTS sections | Scope | Failed or missing exact-head workflow evidence | Review disposition |
| --- | --- | --- | --- | --- |
| [#149](https://github.com/baobab-platform/baobab-iam/pull/149) `1d6c328a045a` | S04, S09, S16 | N04 registered-resource gate | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42502588198), [CI](https://github.com/baobab-platform/baobab-iam/actions/runs/42502587091) | Capability matrix gate failed. Reconcile publication inventory with #169 and verify the actual CP provider assignment and independent Pulse/Payments originals. Scoped INT-02 passed. |
| [#151](https://github.com/baobab-platform/baobab-iam/pull/151) `53ac08d013b9` | S07, S11 | N06 native assurance | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42503409472), [Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/42503408661), [CI](https://github.com/baobab-platform/baobab-iam/actions/runs/42503408669) | Collides with #174 on assurance types and policy ownership. Keep WebAuthn and current Kratos evidence in one assurance model. CTS and Ory checks failed at the captured head. |
| [#152](https://github.com/baobab-platform/baobab-iam/pull/152) `7ef9f46645dc` | S07, S09, S16 | N07 connected consumers | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42503454671), [CI](https://github.com/baobab-platform/baobab-iam/actions/runs/42503454043), [Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/42503453882) | Keep actual Thamani browser and TMS denial receipts separate from source/profile fixtures. CTS and Ory failed; N06 acceptance is a predecessor. |
| [#153](https://github.com/baobab-platform/baobab-iam/pull/153) `399a505f08ad` | S15, S16 | N08 restore and operational hardening | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/43012472577) | Actual N08 and Ory workflows passed at this head. Carry forward CTS main’s SAML replacement instead of the candidate’s old module. Review after N06/N07 convergence. |
| [#156](https://github.com/baobab-platform/baobab-iam/pull/156) `4b32b9b65a0f` | S10 | Thamani ADR-0011 historical guidance | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42502595948) | Retain the ADR/runbook changes and discard obsolete inherited security changes. #167 remains the stacked ledger update. |
| [#157](https://github.com/baobab-platform/baobab-iam/pull/157) `0dde9bb37573` | S09, S10 | People provider-reader issuance | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42502601570) | Preserve the dev-only ACTIVE, paired scope and exact CP audience check. Provider certification and CP activation stay separate. |
| [#161](https://github.com/baobab-platform/baobab-iam/pull/161) `3c4e16b92855` | S05, S07, S09 | ADR-0005–0007 Hydra adapter | [Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/42833248156), [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42833250681) | Reconciled prior squashes and added exact create-response verification without losing the merged Kratos checks. |
| [#164](https://github.com/baobab-platform/baobab-iam/pull/164) `0e48e5e9b413` | S03, S05 | Delegated subject issuer binding | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42836600057), [Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/42836597027) | Merge after #161. Require CP principal lookup to consume the same original verified issuer/subject. |
| [#165](https://github.com/baobab-platform/baobab-iam/pull/165) `4f63794aa402` | S07, S11 | Workforce current Kratos assurance | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42836607490), [Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/42836606072) | Reconcile with #151 and #174. AAL2 session evidence does not establish CP administrative authority or A3/A4. |
| [#166](https://github.com/baobab-platform/baobab-iam/pull/166) `3b08719269b5` | S07, S10 | Governed buyer consent and token profile | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42836619280), [Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/42836615477) | Reconcile #171’s shared human profile edits and preserve original estate/Trade negatives. |
| [#167](https://github.com/baobab-platform/baobab-iam/pull/167) `9aab4c794e9d` | S10 | Thamani B2C disposition ledger | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42836799026), [Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/42836797020) | Use #156 as the primary ADR/runbook disposition and retain distinct ledger traceability. |
| [#168](https://github.com/baobab-platform/baobab-iam/pull/168) `40f2fc40a7c5` | S10 | Buyer/supplier authority boundary | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42836811775), [CI](https://github.com/baobab-platform/baobab-iam/actions/runs/42836809984), [Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/42836810209) | Preserve refusal tests for separate scopes. Resolve source formatting and inherited provider checks before merge. |
| [#169](https://github.com/baobab-platform/baobab-iam/pull/169) `15beca57c526` | S04, S18 | Catalogue capability support | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42841795872), [CI](https://github.com/baobab-platform/baobab-iam/actions/runs/42841793986), [Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/42841794185) | Keep catalogue metadata and runtime issuer registry pins distinct. Existing CI failed the independent CMS fixture boundary. |
| [#170](https://github.com/baobab-platform/baobab-iam/pull/170) `5e40668e04a8` | S05, S12, S13 | Verified revocation and redaction | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42852035480), [Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/42852031917), [CI](https://github.com/baobab-platform/baobab-iam/actions/runs/42852032237) | Coordinate provider verification with #181 deny-only containment. Runtime journal and CP/engine denial must have their own evidence. |
| [#171](https://github.com/baobab-platform/baobab-iam/pull/171) `0ad29577b4f9` | S11 | Recovery-code AMR boundary | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42853937289), [CI](https://github.com/baobab-platform/baobab-iam/actions/runs/42853935341), [Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/42853935703) | Converge shared human-profile edits with #166 and the #151 assurance path. Recovery evidence cannot grant strong assurance. |
| [#172](https://github.com/baobab-platform/baobab-iam/pull/172) `3a0d9ed2ef25` | S05, S12 | Private identity traits | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42853052201), [Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/42853049418), [CI](https://github.com/baobab-platform/baobab-iam/actions/runs/42853049528) | Overlaps #170 and #171. Preserve contract-compatible nested traits and refuse credential/proofing data across writes. |
| [#173](https://github.com/baobab-platform/baobab-iam/pull/173) `7a8d0a2f11da` | S09 | Native commitment issuance recheck | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42853568006), [CI](https://github.com/baobab-platform/baobab-iam/actions/runs/42853564749), [Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/42853564478) | Decision 9 scope remains unallocated. Reconcile with #185 provisioning and CP #468 without promoting Proposed ADR-IAM-0034. |
| [#174](https://github.com/baobab-platform/baobab-iam/pull/174) `3567e280a710` | S04, S11 | Current Kratos assurance evaluator | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42859041099), [Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/42859038987) | Both #151 and #174 define assurance Level, Operation, Evidence and Policy in the same Go package. Use one model before stacking #177. |
| [#175](https://github.com/baobab-platform/baobab-iam/pull/175) `8b1d7265a983` | S04, S08 | Federation capability dispatch | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42866285822), [CI](https://github.com/baobab-platform/baobab-iam/actions/runs/42866283970), [Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/42866283033) | Depends on catalogue #169 and the CP federation grant. Live enterprise workflow and formatting failed. Keep PARTIAL until originals pass. |
| [#176](https://github.com/baobab-platform/baobab-iam/pull/176) `b5e9c06b90da` | S08, S14 | Privileged Ory transport | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42860523694), [Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/42860520443), [CI](https://github.com/baobab-platform/baobab-iam/actions/runs/42860520426) | Separate admin-client TLS/proxy policy from #186 resource JWKS transport. Preserve exact provider endpoints and live federation evidence. |
| [#177](https://github.com/baobab-platform/baobab-iam/pull/177) `0cf41df405bb` | S04, S11 | Assurance grant separation | No exact-head PR workflows returned | Depends on the common #151/#174 policy and assurance-specific CP evidence. No exact-head PR workflows were returned at audit. |
| [#178](https://github.com/baobab-platform/baobab-iam/pull/178) `430d45f119ce` | S15 | Regional DR promotion preflight | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42860091575), [Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/42860089104) | Hardened issuer, witness and revocation fields. Offline preflight has no promotion authority. Pair with #182 restored-denial evidence. |
| [#179](https://github.com/baobab-platform/baobab-iam/pull/179) `364f211eac32` | S14 | JWKS rotation preflight | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42860204434), [Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/42860199479) | Reject aliased or reused public material. Offline overlap checks complement #151 live Hydra rotation and #186 verifier refresh. |
| [#180](https://github.com/baobab-platform/baobab-iam/pull/180) `4927fd08033f` | S08, S14 | SAML assertion hardening | No exact-head PR workflows returned | Port applicable defence-in-depth to the current replacement dependency. Do not restore the obsolete Crewjam import. Exact-head CI absent. |
| [#181](https://github.com/baobab-platform/baobab-iam/pull/181) `0c1db72ffe9b` | S12, S13 | Incident containment | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42864669529), [Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/42864667868) | Compare #151 security operations and #170 verified disable. Journal source cannot stand in for current native CP/resource denials. |
| [#182](https://github.com/baobab-platform/baobab-iam/pull/182) `ef4b9694e033` | S12, S15 | Privacy tombstones and restore veto | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42864764036), [Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/42864758584) | Integrate with #178 and #153 so restore cannot revive a revoked subject. Preserve independent checkpoint and original CP/native denial. |
| [#183](https://github.com/baobab-platform/baobab-iam/pull/183) `c3bcced6fa19` | S11, S13 | Break-glass lease | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42864852150), [Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/42864849237) | Execution must recheck the lease and distinct approvers. The PostgreSQL store and receipts alone establish no privileged executor. |
| [#184](https://github.com/baobab-platform/baobab-iam/pull/184) `ac385f4072f2` | S14, S15 | Runtime image lock conformance | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42865677380), [Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/42865666943) | Reconciled on CTS main. The check aligns compose with the pinned PG17 job. Live Ory jobs remain the runtime evidence. |
| [#185](https://github.com/baobab-platform/baobab-iam/pull/185) `20f4f1ecf334` | S09 | Hydra provisioning ceiling | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42875471063), [Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/42875468702) | The command claims non-production operation but admits production registry IDs and accepts configurable origins. Resolve profile and environment binding before merge. |
| [#186](https://github.com/baobab-platform/baobab-iam/pull/186) `9470882a0a98` | S09, S14, S18 | Pinned JWKS verifier transport | [Foundation Repository Gates](https://github.com/baobab-platform/baobab-iam/actions/runs/42872307321), [Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/42872305367) | Reconciled on CTS main. TLS regression uses a private CA and actual signed token. Current issuer status and CP authority remain separate. |

## Cross-repository joins

- N04’s [Shared #420](https://github.com/baobab-platform/shared/pull/420) and N07’s [Shared #422](https://github.com/baobab-platform/shared/pull/422) are closed without merge. Resolve the accepted registry allocation through current Shared `main` and each consumer pin. The closure of a proposal cannot establish whether equivalent contracts landed elsewhere.
- N07 still depends on the original [Thamani #44](https://github.com/baobab-platform/thamani/pull/44) and [TMS #28](https://github.com/baobab-platform/baobab-tms/pull/28) receipts. The native booking denial remains required.
- Native commitment provenance depends on the exact Shared workload registry and [CP #468](https://github.com/baobab-platform/baobab-cp/pull/468). The unallocated scope must remain unavailable.
- The DEV-11 connected authority and trace chain is tracked by [Infrastructure #72](https://github.com/baobab-platform/infrastructure/pull/72), [CP #465](https://github.com/baobab-platform/baobab-cp/pull/465) and [ZuriBeans #159](https://github.com/baobab-platform/zuribeans/pull/159). Track original IAM, CP and engine receipts against the same source tuple.

## Integration order

Land independently qualified adapter and preflight work separately. Reconcile the ADR sequence after #161, then the N04 through N08 stack in its existing order. Resolve the shared assurance package before converging #174 and #177. Preserve independent CP grant and native-engine authorization checks. Record exact head, CI, consumer pin, evidence class, unmet original runtime cases and rollback before claiming any gate complete.

## Reconciled candidate heads

| PR | Reconciled head |
| --- | --- |
| #161 | `d798f01afa446baf50834b4d413b0b864b172699` |
| #156 | `1401a579fdfd179064cce60c83d476eedda13e98` |
| #157 | `5d478b4376abe5597217c014aaab8615f9784cd3` |
| #178 | `c079426a109d79d298989edc08cc0469213bbd8a` |
| #179 | `573b638f522d6767e88fa0e26fbdbf3b9758a112` |
| #181 | `9072a72923d9a6f90e7b197eb5c0820f9afbbc18` |
| #182 | `b1776d9f740f651d7accdafc3432ccffe30549ed` |
| #183 | `179ab41caf0a5be2d2ff31f641386e04620577c7` |
| #184 | `774ceee420458ba7996df1da5c3989e3308d7e46` |
| #186 | `569916e6a297101dfa67effe203647e9aad4a0b8` |
| #169 | `bfb9168d833408c43ab330746231f4cbf891c4df` |
| #164 | `fc8f96a2868f36d9e827e21c14598c758dcc9286` |

## Continuation review

At the refreshed inventory there were 22 implementation candidates and this audit PR. Since the original snapshot, #156, #161, #164, #165, #166, #167, #168 and #184 landed on main. Four additional exact-head, green candidates were accepted for their documented source scope.

| PR | Merge commit | CTS disposition |
| --- | --- | --- |
| #157 | `555330b8a44e4f7e88591257fe7876dcd58a9930` | Development People issuer ceiling, paired scopes and exact CP audience. Shared #436 defines the scope. Registration, CP read authority and protected issuance have separate gates. |
| #178 | `89db5908747167502884501b552f9bbb6553cc32` | S15 offline regional recovery preflight. Independent restored-denial readback and regional promotion remain held. |
| #179 | `26ac632c1d8013ae2c93a7fc9b422054207b4727` | S14 offline JWKS rotation preflight. Real Hydra and resource rollover acceptance remains held. |
| #186 | `0a1c3df4b4809a56241965b8929534308771c20b` | S09/S14 pinned TLS transport reaches both signed-token verification and remote key lookup. CP registration and authority remain separate. |

| Candidate | Current disposition |
| --- | --- |
| #149 | Exact-head scoped INT-02 passes. N04 still requires current CP support and binding, original Pulse and Payments source evidence and independent teardown. |
| #151–#153 | N06–N08 require current CTS and maintained SAML convergence. #151 and #174 have overlapping assurance models. Original Thamani and TMS receipts and restored-security negatives remain required. |
| #169 | `a6f9461a00a306e4a62d2e3dd5ba95bf4b02f861` separates the read-only capability catalogue checkout from the runtime/CMS registry checkout. Both pinned Shared revisions, the executable provider census, publication, canonical workload and human contract corpora, and CMS fixture checks passed locally. Exact-head PR CI is required. Provider promotion remains held under CTS2-005. |
| #170–#173 | Exact candidate CI was green at the reviewed heads. #170 documents the ERP issuer/subject mapping deviation and the provider-only nature of revocation. #171 requires connected identity and assurance evidence, with #172 and #173 stacked behind it. Decision 9 remains unallocated. |
| #174, #177 | Converge on one assurance policy, including current Kratos evidence and assurance-specific CP resolution. #177 has a merge conflict and lacks exact-head PR CI. |
| #175 | `b8e7be0033cbecc9851219a654f19ff563fe937f` permits the federation capability in the authenticated CP wire client and aligns the live Keycloak fixture. It also carries the CTS-approved SAML and separately built Hydra dependency pins after the image scan flagged the inherited pin. Federation and Keycloak race suites passed locally. CTS2-019 still requires connected current CP and original estate evidence. |
| #176, #180 | Reconcile the transport and SAML patches onto the corrected federation and maintained SAML lineage. #180 has no exact-head PR CI. |
| #181, #182 | Candidate PostgreSQL 17 suites are green. Current CP/Security and resource-side incident denial, all reactivation paths and independently witnessed restore evidence remain held. |
| #183 | `019ade1510e492bc29f55d5da5346747b3ed8755` rechecks the original approval after alerting and audit, and at each use within the unexpired lease. The administrative race suite passed locally. An independently authenticated live verifier and privileged executor still require acceptance. |
| #185 | The non-production command admits production registry IDs on configurable Hydra origins. CTS2-021 requires a reviewed environment-bound provisioning route, as well as the separate issuance and resource fences. |

For a subsequent acceptance decision, record the reviewed source SHA, required check URLs and any original evidence that the owning CTS workstream requires. Documentation records evidence without allocating scope, granting access or changing protected environments.

### Further continuation changes

| PR | Exact reviewed revision | Verification and remaining evidence |
| --- | --- | --- |
| #170 | Merge `6b0f8048af024c5b61831b58fce20126c2f30210` | Exact-head CI passed. Verified native provider disable and readback, recursive trait validation and redaction merged under S05/S12/S13. ERP's issuer/subject mapping deviation and original CP and engine revocation readbacks remain open. |
| #151 | `1909f7600105633bfa02251b53ad3b8545c554c6` | Integrated the reviewed N04 base and the CTS dependency baseline. CTS crosswalk and targeted assurance, federation, Ory, BFF and security operations race tests passed locally. |
| #152 | `e971d57c914b52fc50b2bf81fcc838afbe897509` | Integrated the revised N06 base and its maintained SAML dependency. CTS, 30 N07 unit tests and targeted race suites passed locally. Original Thamani and TMS receipts are still required. |
| #153 | `a05a3e262b6f7a4eddf5afe42559f8bd4a4be3b0` | Integrated the revised N07 base and its dependency pins while preserving N08 restore and delivery checks. CTS, eight N08 unit tests and targeted race suites passed locally. The new head requires CI and restored non-resurrection evidence. |
| #176 | `480daefa6ba9861cc7300f7c2fe5e8ef19bab9a8` | The privileged transport owns routing and accepts explicit trusted CA roots and stricter TLS settings. The workload tests use TLS HTTP. Six targeted race suites passed locally. |
| #180 | `2a57835decfb4c2aaed31899354a3a670aedd0c5` | Moved the parser guards to the maintained verifier pinned by CTS #187. Federation and Keycloak race suites passed locally. Final connected SAML and CP evidence is outstanding. |
| #177 | Base conflict reproduced | The local guard uses the canonical assurance key. The reviewed CP and IAM runtime composition still needs a distinct, current assurance grant and binding readback. Preserve native-login grant separation. |

The workflow states above describe the evidence available at review. Pending CI
or original qualification keeps the corresponding candidate open.

### Final branch reconciliation for this pass

| PR | Exact candidate | Review disposition |
| --- | --- | --- |
| #158 | `a089d4c91135d044280582a14418c6b7b8ec6ba1` | Reconciled the Dependabot staging workflow pin with CTS main. The Shared workflow delta changes only the pinned `setup-go` action. The IAM staging-tag trigger and permissions were reviewed against main. No protected run or tag was created. |
| #176 | `ff33011223294d2d14e5ba5be446e1d7872a910f` | Integrated the corrected #175 base while retaining the privileged client fixtures. Federation, Keycloak and Ory targeted race tests passed. |
| #177 | `459d6167c355ad992eb64623ac4a805b77291b28` | Resolved the stacked merge conflicts and retained the assurance-specific CP guard. Four targeted race suites passed. Current CP assurance projection and policy convergence with #151 remain required. |
| #180 | `465356e5d438aac30cc14bea7e1ff35de36c6925` | Integrated the corrected assurance and transport base. Federation, Keycloak and Ory race tests passed. |
| #185 | `1553f2c6bf826c12ddbd91ed28599d20fffcd6f0` | The local command now validates offline plans against the exact Shared registry. The production IDs in its profile inventory cannot reach Hydra through this command. Updated the M4 inventory, live evidence checklist and runbook. Go race tests, the documented CLI invocation and the exact Shared snapshot check passed. Live mutation requires an environment-bound lifecycle. |

Live companion readback confirmed that CP #465/#468, Trade #231, Pulse #63,
Thamani #44 and TMS #28 were still open. Shared #420/#422 remained closed
without merge. Preserve the owning original evidence requirements before
closing the corresponding workstreams.

## Continuation checkpoint — 12 November 2026, 01:41 SAST

This addendum is a **new observation**, not a replacement of the historical 11 November inventory. GitHub currently reports **14 open IAM pull requests, all DRAFT**: #149, #151, #152, #153, #174, #175, #176, #177, #180, #181, #182, #183, #185 and this audit #189. Source-only green workflows do not qualify protected identities, ACTIVE provider support, CP grants, or business commitments.

| Candidate | Source/qualification at this checkpoint | Disposition |
| --- | --- | --- |
| #149 N04 | Source and scoped INT-02 workflows green; no complete original registered-provider/CP/native consumer, Pulse+Payments and teardown receipts | DRAFT/HELD; prerequisite for N06 |
| #151 N06 | N04-stacked; current-head Ory and CI failed; no qualified WebAuthn A3/A4/recovery/issuer/native-operation integration | DRAFT/HELD |
| #152 N07 | N06-stacked; CI, Ory and connected candidate failed; no genuine Thamani/TMS/current CP/legal mandate and multi-estate owner originals | DRAFT/HELD |
| #153 N08 | N07-stacked; CI and Ory failed; native PG17 and operation jobs alone do not prove DR and identity replay across providers | DRAFT/HELD |
| #174 assurance | Head `acf79bf3c7f2da1eb67c9f53f491c84c3d8f4354` has six successful component workflows, but high-risk operation proof remains absent | DRAFT/HELD |
| #175 federation | Head `decbc0819d1f03fcfe48eeb28e612eac417d9ab0` has six successful component workflows; real CP federation grant/Keycloak originals and SAML threat review remain held | DRAFT/HELD |
| #176 Ory transport | Head `09216f79adba895549419dc0c04620437b086df4` has six successful workflows and current private-CA TLS fixture; distinct live privileged routing and owner approval not inferred | DRAFT/HELD; parent of #177 |
| #177 assurance CP grant | **Reconciled** latest #176 and its accepted CTS/native TLS fixtures in merge head `ee138f56df3b84a732dd86cd9042cbd515d0d599`. Test fake now demonstrably grants human login while denying `identity.authentication.assurance`. Earlier Go-format and CMS-fixture failures resulted from superseded #176. Fresh exact-head CI initiated. | DRAFT/HELD pending current-head workflows, separate CP assurance binding and native originals |
| #180 SAML parser | **Reconciled** current #177 in head `d4fe537c483c050d983fe330fb73482b4fae8088`, preserving supatype/saml 0.7.0 (never revert to Crewjam), namespace/Subject/NameID guards and panic-to-deny semantics. Earlier upstream native fixture failures were stale-base, not a valid reason to relax provider trust. Fresh exact-head CI initiated. | DRAFT/HELD pending SAML/Keycloak original and final security result |
| #181 incident | New `3040cf601d648446757800c201236d3aa1fef38d`: repeats independent Security/CP authority **immediately before** durable VERIFIED commit, including a replay of a historically verified operation. Added revocation-after-resource-readback negatives; failed final authority persists UNKNOWN. Fresh CI initiated. | DRAFT/HELD pending real CP/resource/original containment receipts |
| #182 privacy | New `e0422ca6506eeda8a28cdc0a9e3b7a36baf6ce33`: journal checkpoint now requires both stable revision and stable independently issued evidence reference. Added same-revision/evidence-substitution negative. Fresh PostgreSQL17/CI initiated. | DRAFT/HELD pending real issuer/CP/privacy independent custody and DR |
| #183 emergency | Head `019ade1510e492bc29f55d5da5346747b3ed8755` has seven green source/runtime workflows, but emergency lease is evidence, not an executed privileged-provider operation; independent approver/executor and audit remains unqualified | DRAFT/HELD |
| #185 workload | Head `3ba29350b7aa4124b2361ceede8a9fc864950f46` has seven green workflows. The previous arbitrary Hydra provisioning path is replaced by plan-only, reviewed manifest and strict scope/audience ceilings. No ACTIVE grant, arbitrary live mutation, or actual token/caller proof follows. | DRAFT/HELD |
| #189 audit record | Documentation-only register and this dated reconciliation; no provider/credential/consumer activation | Reviewable separately once updated-head checks pass |

**Dependency and evidence reconciliation:** Shared #422 (proposed N07 TMS issuer/validator) was CLOSED WITHOUT MERGE; CP #455 adopted only inert Shared #430 source declarations; no ACTIVE subject, CP legal mandate or native TMS booking is implied. Thamani #44 and TMS #28 remain held. Infrastructure #69/#72 are connected qualification harness companions but their source/CI alone is not complete N07/N08 original browser/booking qualification. CP #468 merged, while ADR-IAM-0034's native commitment scope remains unallocated. The supported release distinctions remain ENGINEERING-COMPLETE, STAGING-READY packet and independently approved PRODUCTION-READY; no promotion is granted in this register.

**Merge rule:** for implementation PRs, do not substitute draft source acceptance for original native-authority evidence. Recheck actual immutable source HEAD, required CI and review comments, stack/companion ancestry, independent negative receipts and teardown before marking ready or merging. No CI exception, skip, privileged credential injection or protected-stage action was introduced here.
