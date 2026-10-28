# Contributing

Issues and focused Pull Requests with **synthetic reproductions** are welcome. For a new rule, provide its security/compatibility rationale, official primary source, safe/unsafe fixture and regression test. Use a feature branch, keep tooling offline and deterministic, avoid uploading real tokens, proprietary distribution files or customer Kubernetes manifests, and document false positives/negatives. Run `python -m unittest discover -s tests -v` and both documented example commands before requesting review. The maintainer evaluates scope and CI before merging.
