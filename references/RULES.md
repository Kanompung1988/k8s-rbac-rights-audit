# Finding reference — Kubernetes RBAC Rights Audit

| Rule | Severity | Static detection | Response |
|---|---|---|---|
| KR001 | High | Wildcard `verbs: ["*"]` | Replace with necessary verbs |
| KR002 | High | Wildcard `resources` or `apiGroups` | Scope exact API surface |
| KR003 | High | Core-group Secret get/list/watch, including wildcard verbs | Restrict subjects/namespaces; list/watch disclose data |
| KR004 | Critical | `bind`, `escalate`, or `impersonate` verbs | Review potential policy-bypass scope |
| KR005 | Medium | Create workloads such as Pods or Deployments | Review service account, admission, mounted object access |
| KR006 | High | Pod exec/attach via `create` | Restrict interactive access |
| KR007 | Critical for ClusterRoleBinding; High for RoleBinding | Reference `cluster-admin` ClusterRole | Replace with purpose-built permissions; RoleBinding is namespace-scoped |
| KR008 | Critical | Bind to `system:masters` or `system:unauthenticated` | Remove or justify very exceptional scope |
| KR009 | High | ClusterRoleBinding includes default ServiceAccount | Use dedicated account and narrow grant |
| KR010 | Medium | Wildcard non-resource URL | Restrict API path coverage |
| KR011 | Medium | Aggregated ClusterRole selector | Resolve live aggregation before interpreting final rights |

**Limitations:** The tool checks files, not subjects' actual effective rights. It cannot map custom role references, external groups, aggregated roles, defaults added by controllers, admission and tenancy boundaries; severity is a prompt for review, not proof of exploitable permissions. Kubernetes RBAC and cluster policy evolve. This tool reads YAML with safe parsing but no hard sandbox for hostile encodings/alias complexity; review only trusted local PR inputs or use isolation.
