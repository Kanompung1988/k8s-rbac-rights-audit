#!/usr/bin/env python3
"""Read-only Kubernetes RBAC YAML/JSON privilege review. No kubectl or API access."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
import yaml

SEVERITIES = ("low", "medium", "high", "critical")
KINDS = {"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"}

class AuditError(ValueError):
    pass

class StrictLoader(yaml.SafeLoader):
    pass

def unique_mapping(loader, node):
    loader.flatten_mapping(node)
    found = {}
    for key, value in node.value:
        k = loader.construct_object(key, deep=True)
        if not isinstance(k, (str, int, float, bool, tuple)):
            raise AuditError("Complex YAML mapping keys are unsupported")
        if k in found:
            raise AuditError(f"Duplicate YAML key: {k}")
        found[k] = loader.construct_object(value, deep=True)
    return found

StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def file_paths(input_path: Path, max_files=200):
    if input_path.is_symlink() or not input_path.exists():
        raise AuditError("Input missing or symlink (refusing to follow symlink)")
    if input_path.is_dir():
        paths = sorted(p for p in input_path.rglob("*") if p.suffix.lower() in (".yaml", ".yml", ".json") and p.is_file())
        if len(paths) > max_files:
            raise AuditError(f"Too many YAML/JSON files (>{max_files})")
    elif input_path.is_file():
        paths = [input_path]
    else:
        raise AuditError("Input must be a regular file or directory")
    for p in paths:
        if p.is_symlink():
            raise AuditError("Symlinked input manifest rejected")
    return paths


def strings(obj, key):
    vals = obj.get(key, []) if isinstance(obj, dict) else []
    if not isinstance(vals, list) or not all(isinstance(x, str) for x in vals):
        raise AuditError(f"RBAC {key} must be a list of strings")
    return set(vals)


def inspect(path: Path, max_file_bytes=1_000_000, max_docs=100) -> dict:
    if path.stat().st_size > max_file_bytes:
        raise AuditError(f"Manifest exceeds {max_file_bytes} bytes")
    try:
        with path.open(encoding="utf-8") as file:
            content = file.read()
        docs = list(yaml.load_all(content, Loader=StrictLoader))
    except (UnicodeError, OSError, yaml.YAMLError) as exc:
        raise AuditError(f"Cannot parse YAML/JSON manifest {path.name}: {type(exc).__name__}") from exc
    if len(docs) > max_docs:
        raise AuditError(f"Manifest contains too many YAML documents (>{max_docs})")
    findings = []
    resources_seen = 0
    for doc_index, obj in enumerate(docs, 1):
        if obj is None:
            continue
        if not isinstance(obj, dict):
            raise AuditError(f"Document {doc_index} must be a YAML object")
        kind = obj.get("kind")
        if kind not in KINDS:
            continue
        resources_seen += 1
        metadata = obj.get("metadata") or {}
        if not isinstance(metadata, dict):
            raise AuditError("RBAC metadata must be a mapping")
        name = str(metadata.get("name") or "<unnamed>")
        namespace = str(metadata.get("namespace") or "default") if kind in ("Role", "RoleBinding") else "cluster"
        def add(rule, severity, field, msg, guidance):
            findings.append({"rule": rule, "severity": severity, "file": str(path), "document": doc_index,
                             "kind": kind, "name": name, "namespace": namespace, "field": field,
                             "message": msg, "guidance": guidance})
        if kind in ("Role", "ClusterRole"):
            rules = obj.get("rules", [])
            if not isinstance(rules, list):
                raise AuditError("RBAC rules must be an array")
            for idx, rule in enumerate(rules):
                if not isinstance(rule, dict):
                    raise AuditError("RBAC rules entries must be objects")
                verbs = strings(rule, "verbs")
                resources = strings(rule, "resources")
                groups = strings(rule, "apiGroups")
                urls = strings(rule, "nonResourceURLs")
                base = f"rules[{idx}]"
                if "*" in verbs:
                    add("KR001", "high", base+".verbs", "Wildcard verbs grant current and future operations", "Specify exact required verbs")
                if "*" in resources or "*" in groups:
                    add("KR002", "high", base+".resources", "Wildcard resources or API groups expand privilege surface", "Scope exact API groups/resources")
                if "" in groups and "secrets" in resources and verbs.intersection({"get", "list", "watch", "*"}):
                    add("KR003", "high", base, "Can read Kubernetes Secrets, including list/watch", "Limit access and scope to named resources where feasible")
                if verbs.intersection({"bind", "escalate", "impersonate"}):
                    add("KR004", "critical", base+".verbs", "RBAC escalation/impersonation verb is allowed", "Review target resources and justify escalation boundary")
                workloads = {"pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs", "replicasets", "replicationcontrollers"}
                if resources.intersection(workloads) and verbs.intersection({"create", "*"}):
                    add("KR005", "medium", base, "Workload creation can confer indirect namespace access", "Review admission and service account scopes")
                if resources.intersection({"pods/exec", "pods/attach"}) and verbs.intersection({"create", "*"}):
                    add("KR006", "high", base, "Can exec/attach into pods", "Limit to dedicated break-glass roles")
                if "*" in urls:
                    add("KR010", "medium", base+".nonResourceURLs", "Wildcard non-resource URLs", "Use explicit required API paths")
            if kind == "ClusterRole" and obj.get("aggregationRule"):
                add("KR011", "medium", "aggregationRule", "ClusterRole aggregation may change effective permissions", "Resolve selectors in the target cluster")
        else:
            role_ref = obj.get("roleRef") or {}
            if not isinstance(role_ref, dict):
                raise AuditError("roleRef must be a mapping")
            if role_ref.get("kind") == "ClusterRole" and role_ref.get("name") == "cluster-admin":
                sev = "critical" if kind == "ClusterRoleBinding" else "high"
                add("KR007", sev, "roleRef", "Binds subjects to cluster-admin role", "Prefer task-scoped role and least privileges")
            subjects = obj.get("subjects", [])
            if not isinstance(subjects, list):
                raise AuditError("subjects must be a list")
            for i, sub in enumerate(subjects):
                if not isinstance(sub, dict):
                    raise AuditError("subject entry must be an object")
                field = f"subjects[{i}]"
                if sub.get("kind") == "Group" and sub.get("name") in ("system:masters", "system:unauthenticated"):
                    add("KR008", "critical", field, "Binding grants rights to a sensitive Kubernetes group", "Remove or explicitly justify exceptional binding")
                if (kind == "ClusterRoleBinding" and sub.get("kind") == "ServiceAccount"
                        and sub.get("name") == "default"):
                    add("KR009", "high", field, "ClusterRoleBinding includes a default service account", "Use a dedicated least-privileged service account")
    findings.sort(key=lambda f: (-SEVERITIES.index(f["severity"]), f["document"], f["rule"], f["field"]))
    return {"file": str(path), "rbac_resources": resources_seen, "findings": findings}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="Manifest path or directory (no Kubernetes API calls)")
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    parser.add_argument("--fail-on", choices=("none", "low", "medium", "high", "critical"), default="high")
    args = parser.parse_args(argv)
    try:
        reports = [inspect(p) for p in file_paths(args.path)]
    except (AuditError, OSError) as exc:
        print(f"INPUT ERROR: {exc}", file=sys.stderr)
        return 1
    findings = [f for report in reports for f in report["findings"]]
    if args.format == "json":
        print(json.dumps({"tool":"k8s-rbac-rights-audit", "reports":reports, "findings":findings},indent=2))
    else:
        print("# Kubernetes RBAC Rights Audit\n\nStatic manifest heuristics, not cluster-effective authorization.\n")
        for report in reports:
            print(f"## {report['file']} ({report['rbac_resources']} RBAC documents)")
            for f in report["findings"]:
                print(f"- **{f['severity'].upper()} {f['rule']}** {f['kind']} `{f['name']}` {f['field']}: {f['message']}")
            if not report["findings"]: print("- No findings in the supported rule set.")
    if args.fail_on != "none":
        floor = SEVERITIES.index(args.fail_on)
        if any(SEVERITIES.index(f["severity"]) >= floor for f in findings): return 2
    return 0

if __name__ == "__main__": sys.exit(main())
