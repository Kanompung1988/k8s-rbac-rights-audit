---
name: k8s-rbac-rights-audit
description: Review Kubernetes Role, ClusterRole, RoleBinding and ClusterRoleBinding YAML/JSON manifests offline for wildcard permissions, secret reads, escalation verbs, workload creation, pod exec, cluster-admin grants, risky group or default service-account bindings. Use in least-privilege PR reviews without cluster credentials or kubectl.
license: MIT
compatibility: Python 3.10+ with PyYAML 6.0.2. Local Kubernetes YAML/JSON manifests only; no cluster, network or secrets required.
metadata:
  author: AREAZERO Skill Lab
  version: "1.0.0"
---

# Kubernetes RBAC rights audit

## Trigger / non-trigger
Use before submitting Kubernetes RBAC manifest changes, including GitOps PRs, Helm-rendered YAML and raw `kubectl` manifests. This is **not** an authorization check against a live cluster; aggregation selectors, admission policies, dynamic roles, namespace RBAC and impersonation are not resolved to effective privileges.

## Procedure
1. Provide a **trusted local** YAML/JSON manifest (or a directory of rendered manifests) to `python scripts/audit.py examples/unsafe.yaml --format markdown --fail-on high`.
2. Review `KR001–KR011`, prioritize unrestricted wildcard, privilege-escalation verbs, Secrets read and cluster-admin bindings. See [rules](references/RULES.md) and [official references](references/SOURCES.md).
3. Check the **namespace scope**: a `RoleBinding` referencing a `ClusterRole` grants only namespaced rights; a `ClusterRoleBinding` grants cluster-wide permissions. Findings distinguish this nuance.
4. Confirm resources, verbs, API groups and subjects reflect real application needs. Do not automatically delete role bindings; coordinate with cluster owners and least-privilege tests.
5. Re-run against the final rendered YAML and document file/document/name/field and safe remediation. Explain that safe/unsafe fixture outputs are synthetic.

## Reproduction
`python -m pip install -r requirements.txt` then `python scripts/audit.py examples/safe.yaml --format json --fail-on high` exits **0**; `python scripts/audit.py examples/unsafe.yaml --format json --fail-on none` shows reproducible metadata findings (without cluster credentials). Exit status **2** means findings meet threshold; **1** means parse or input failure; **0** means no blocking finding under this heuristic rule set.

## Constraints
Read-only `yaml.SafeLoader` derivative rejects duplicate keys. Scans up to 200 local manifests, with 1 MB/file, 100 documents/file and no symlink following. It parses the selected local files in memory but **outputs only RBAC metadata**, never Secret values. YAML from untrusted external parties should be pre-vetted or processed in an isolated environment. No Kubernetes APIs, `kubectl`, network or actions on actual RBAC policies. Does not replace `kubectl auth can-i`, admission policy, or independent security review.
