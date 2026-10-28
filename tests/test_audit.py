from __future__ import annotations
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
import yaml

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("rbacaudit",ROOT/"scripts"/"audit.py")
audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)

class RbacTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
    def make(self, data, fname="rbac.yaml"):
        p=self.root/fname;p.write_text(data if isinstance(data,str) else yaml.safe_dump(data),encoding="utf-8");return p
    def role(self,verbs=None,resources=None,groups=None,kind="Role",extra=None):
        v={"apiVersion":"rbac.authorization.k8s.io/v1","kind":kind,"metadata":{"name":"app","namespace":"team"},
        "rules":[{"apiGroups":groups if groups is not None else [""],"resources":resources if resources is not None else ["pods"],"verbs":verbs if verbs is not None else ["get"]}]}
        if extra:v.update(extra)
        return v
    def binding(self,kind="RoleBinding",role="edit",subs=None):
        return {"apiVersion":"rbac.authorization.k8s.io/v1","kind":kind,"metadata":{"name":"binding","namespace":"team"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":role},"subjects":subs or [{"kind":"User","name":"alice"}]}
    def rules(self,obj):return [x["rule"] for x in audit.inspect(self.make(obj))["findings"]]
    def test_safe_role(self):self.assertEqual(self.rules(self.role()),[])
    def test_wildcard_verbs(self):self.assertIn("KR001",self.rules(self.role(["*"])))
    def test_wildcard_resources(self):self.assertIn("KR002",self.rules(self.role(resources=["*"])))
    def test_wildcard_group(self):self.assertIn("KR002",self.rules(self.role(groups=["*"])))
    def test_secret_get(self):self.assertIn("KR003",self.rules(self.role(["get"],["secrets"])))
    def test_secret_list(self):self.assertIn("KR003",self.rules(self.role(["list"],["secrets"])))
    def test_secret_watch(self):self.assertIn("KR003",self.rules(self.role(["watch"],["secrets"])))
    def test_secret_non_core_api(self):self.assertNotIn("KR003",self.rules(self.role(["get"],["secrets"],["apps"])))
    def test_bind(self):self.assertIn("KR004",self.rules(self.role(["bind"],["clusterroles"],["rbac.authorization.k8s.io"])))
    def test_escalate(self):self.assertIn("KR004",self.rules(self.role(["escalate"],["roles"],["rbac.authorization.k8s.io"])))
    def test_impersonate(self):self.assertIn("KR004",self.rules(self.role(["impersonate"],["users"])))
    def test_workload_create(self):self.assertIn("KR005",self.rules(self.role(["create"],["pods"])))
    def test_no_workload_create(self):self.assertNotIn("KR005",self.rules(self.role(["get"],["pods"])))
    def test_pod_exec(self):self.assertIn("KR006",self.rules(self.role(["create"],["pods/exec"])))
    def test_cluster_admin_cluster_binding(self):
        f=audit.inspect(self.make(self.binding("ClusterRoleBinding","cluster-admin")))["findings"]
        self.assertEqual(next(x["severity"] for x in f if x["rule"]=="KR007"),"critical")
    def test_cluster_admin_namespace_binding(self):
        f=audit.inspect(self.make(self.binding("RoleBinding","cluster-admin")))["findings"]
        self.assertEqual(next(x["severity"] for x in f if x["rule"]=="KR007"),"high")
    def test_default_sa_cluster_binding(self):self.assertIn("KR009",self.rules(self.binding("ClusterRoleBinding","view",[{"kind":"ServiceAccount","name":"default","namespace":"dev"}])))
    def test_default_sa_role_binding_not_flagged(self):self.assertNotIn("KR009",self.rules(self.binding("RoleBinding","view",[{"kind":"ServiceAccount","name":"default"}])))
    def test_system_masters(self):self.assertIn("KR008",self.rules(self.binding(subs=[{"kind":"Group","name":"system:masters"}])))
    def test_unauthenticated(self):self.assertIn("KR008",self.rules(self.binding(subs=[{"kind":"Group","name":"system:unauthenticated"}])))
    def test_nonresource_urls(self):
        d=self.role();d["rules"][0]["nonResourceURLs"]=["*"]
        self.assertIn("KR010",self.rules(d))
    def test_aggregation(self):self.assertIn("KR011",self.rules(self.role(kind="ClusterRole",extra={"aggregationRule":{"clusterRoleSelectors":[{"matchLabels":{"rbac.example.com/aggregate":"yes"}}]}})))
    def test_ignore_non_rbac(self):self.assertEqual(self.rules({"kind":"Secret","metadata":{"name":"private"},"data":{"password":"base64here"}}),[])
    def test_multi_documents(self):
        p=self.make(yaml.safe_dump(self.role())+"---\n"+yaml.safe_dump(self.binding("ClusterRoleBinding","cluster-admin")))
        self.assertEqual(audit.inspect(p)["rbac_resources"],2)
    def test_duplicate_yaml_key(self):
        p=self.make("kind: Role\nkind: ClusterRole\nmetadata: {}\n")
        with self.assertRaises(audit.AuditError):audit.inspect(p)
    def test_malformed_yaml(self):
        p=self.make("kind: Role\nmetadata: [unterminated\n")
        with self.assertRaises(audit.AuditError):audit.inspect(p)
    def test_file_size_cap(self):
        with self.assertRaises(audit.AuditError):audit.inspect(self.make(self.role()),max_file_bytes=4)
    def test_too_many_docs(self):
        p=self.make("---\nkind: Role\n"*5)
        with self.assertRaises(audit.AuditError):audit.inspect(p,max_docs=2)
    def test_symlink_input(self):
        p=self.make(self.role());q=self.root/"link.yaml";q.symlink_to(p)
        with self.assertRaises(audit.AuditError):audit.file_paths(q)
    def test_cli_json(self):
        p=self.make(self.role(["*"],["secrets"]))
        r=subprocess.run([sys.executable,str(ROOT/"scripts"/"audit.py"),str(p),"--format","json"],text=True,capture_output=True)
        self.assertEqual(r.returncode,2)
        self.assertIn("KR003",[x["rule"] for x in json.loads(r.stdout)["findings"]])
    def test_cli_none(self):
        p=self.make(self.role(["*"],["secrets"]))
        r=subprocess.run([sys.executable,str(ROOT/"scripts"/"audit.py"),str(p),"--fail-on","none"],text=True,capture_output=True)
        self.assertEqual(r.returncode,0)
    def test_cli_safe(self):
        p=self.make(self.role())
        r=subprocess.run([sys.executable,str(ROOT/"scripts"/"audit.py"),str(p)],text=True,capture_output=True)
        self.assertEqual(r.returncode,0)
    def test_invalid_rule_types(self):
        p=self.make(self.role(extra={"rules":[{"verbs":"get","resources":["pods"]}]}))
        with self.assertRaises(audit.AuditError):audit.inspect(p)

if __name__=="__main__":unittest.main()
