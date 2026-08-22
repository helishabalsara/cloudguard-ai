# cloudreach

**Cloud security posture management that answers *is it actually reachable?* — not *does a security group look wrong?***

## The two problems this exists for

### 1. Reachability, not heuristics

Open-source CSPM marks a resource "publicly exposed" based on security group rules alone — a `0.0.0.0/0` inbound rule, or an internet-facing load balancer. That produces a flood of false positives, because a permissive security group on a host with no internet gateway route is not exposed.

Real reachability is a conjunction:

```
security group ∧ NACL ∧ route table ∧ IGW/NAT ∧ LB listener ∧ peering/TGW transitivity
```

Most tools ingest every one of those inputs and then never join them.

### 2. CI/CD OIDC trust — currently unmodelled anywhere

GitHub Actions, GitLab CI and Terraform Cloud assume cloud roles via OIDC federation. Nothing open-source maps those trust edges.

cloudreach parses `AssumeRolePolicyDocument` trust conditions, resolves which repositories, branches and environments can assume which roles, and flags over-broad `sub` claim patterns — the `repo:org/*:*` wildcard that lets **any repository in an organisation assume a production role**.

This is an actively exploited supply-chain path with no open tooling.

## Architecture

| Layer | Purpose |
|---|---|
| **1. Collectors** | Cloud provider APIs → normalised schema |
| **2. Asset graph** | Identities, roles, policies, compute, storage, network paths as a graph |
| **3. Policy engine** | OPA / Rego rules evaluated against the graph |
| **4. Reachability** | Sound internet-exposure paths |
| **5. Remediation** | Emit the Terraform diff, not a paragraph of advice |

## Status

🚧 **In development.** AWS first.

### Available now
- [ ] AWS collectors
- [ ] Asset graph
- [ ] Rego policy engine
- [ ] Reachability analysis
- [ ] OIDC trust mapping
- [ ] Terraform remediation diffs

## Open core

This repository is the open edition: the reachability engine, the OIDC trust mapper, and the CLI — the parts that are technically hard and that nothing else does.

The commercial edition adds multi-cloud breadth, a web UI, multi-tenancy, SSO/RBAC, scheduling, ticketing integrations and a hosted service. Roadmap items are marked as roadmap.

---

**Website:** _(coming soon)_
