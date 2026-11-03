<div align="center">

```text
 █████╗ ███████╗ ██████╗ ██╗███████╗
██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
███████║█████╗  ██║  ███╗██║███████╗
██╔══██║██╔══╝  ██║   ██║██║╚════██║
██║  ██║███████╗╚██████╔╝██║███████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝
```

### Multi-cloud Security Intelligence & Infrastructure Analysis Platform

**Not another scanner. A system that understands how your cloud connects, and how small misconfigurations chain into big breaches.**

![status](https://img.shields.io/badge/status-early%20development-f43f5e?style=for-the-badge)
![python](https://img.shields.io/badge/python-3.11+-22d3ee?style=for-the-badge&logo=python&logoColor=white)
![clouds](https://img.shields.io/badge/AWS%20·%20Azure%20·%20GCP-a78bfa?style=for-the-badge)
![license](https://img.shields.io/badge/license-see%20LICENSE-34d399?style=for-the-badge)
![tests](https://img.shields.io/github/actions/workflow/status/achh-914/AEGIS/tests.yml?style=for-the-badge&label=tests)

</div>

---

## ⚡ Why AEGIS

Scanners give you a flat list of findings. Attackers don't think in lists, they think in **paths**.

AEGIS models your infrastructure as a **graph** (resources are nodes, trust and reachability are edges), then reasons over it:

| | Capability | Question it answers |
|---|---|---|
| 🧠 | **Understand** | How is everything actually connected? |
| 🎯 | **Attack paths** | Can the internet reach my crown jewels, and how? |
| 💥 | **Blast radius** | If this identity is compromised, what falls? |
| 🔮 | **Simulate** | What happens if I change this rule? |
| 🛠️ | **Remediate** | What is the safest fix? (patch generated, never auto-applied) |
| ✅ | **Verify** | Did the fix close the path without breaking anything? |

---

## 🏗️ Architecture

<p align="center">
  <img src="docs/assets/architecture.svg" alt="AEGIS architecture" width="100%"/>
</p>

---

## 🎯 Example: how small things become a breach

```mermaid
%%{init: {'theme':'dark'}}%%
flowchart LR
    I(["🌐 Internet"]):::bad -->|"SG: 0.0.0.0/0 :22"| E["EC2<br/>web-01"]:::warn
    E -->|"instance profile"| R["IAM Role<br/>app-role"]:::warn
    R -->|"iam:PassRole + ec2:RunInstances"| A["IAM Role<br/>admin-role"]:::bad
    A -->|"s3:*"| S[("🪣 S3<br/>customer-data")]:::crit

    classDef bad fill:#33060f,stroke:#f43f5e,color:#fff,stroke-width:2px
    classDef warn fill:#2e1604,stroke:#fb923c,color:#fff,stroke-width:2px
    classDef crit fill:#4a0519,stroke:#f43f5e,color:#fff,stroke-width:4px
```

Individually each setting looks "medium". Together: **critical**. That is what AEGIS is built to see.

---

## 💻 Terminal preview

```diff
$ aegis scan --provider aws --snapshot ./snapshots/prod.json
+ ✔ Loaded 1,284 resources · 3,911 relationships
+ ✔ Graph built in 0.8s

$ aegis paths --from internet --to s3:customer-data
- ✖ CRITICAL  1 attack path found (4 hops)
-   internet → ec2:web-01 → role:app-role → role:admin-role → s3:customer-data

$ aegis simulate --change "sg-0a1b: remove 0.0.0.0/0 on :22"
! ⚠ Paths closed: 1   Paths opened: 0   Services impacted: 0

$ aegis fix --path 1 --format terraform > fix.tf
+ ✔ Patch generated (not applied)

$ aegis verify --after ./snapshots/prod-after.json
+ ✔ Attack path closed · no regressions
```

> paths, blast and simulate are implemented. fix and verify are on the roadmap, so their output above is the target UX.

---

## 🚀 Quick start

```bash
git clone https://github.com/achh-914/AEGIS.git
cd AEGIS
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# 1. Find attack paths from the internet to a sensitive bucket
aegis paths --snapshot examples/aws_breach_demo.json --to s3:customer-data

# 2. What falls if this role is compromised?
aegis blast --snapshot examples/aws_breach_demo.json --from role:app-role

# 3. What-if: remove SSH exposure, on a copy of the graph
aegis simulate --snapshot examples/aws_breach_demo.json --remove-ingress sg-0a1b:22
```

Run the tests with pytest -q.

---

## 🧱 Design principles

- **Read-only by default.** AEGIS never mutates your cloud. Fixes are generated as patches you review.
- **Offline first.** Works from JSON snapshots, so no credentials are needed to analyze.
- **Graph over lists.** Risk is a property of relationships, not of single resources.
- **Verify, don't assume.** Every fix is re-analyzed and diffed.

## 🗺️ Roadmap

- [x] Graph model + JSON snapshot loader (demo format)
- [x] Attack path engine (first reference path, with tests)
- [x] Blast radius analysis
- [x] Change simulation on graph copies
- [x] CI: tests on Python 3.11 / 3.12 / 3.13
- [ ] Loader for real AWS exports (get-account-authorization-details)
- [x] Automatic scan with rule tags (OPEN-INGRESS, PRIVESC-PASSROLE, OPEN-TRUST, PUBLIC-BUCKET)
- [ ] More rules (cross-account trust, wildcard IAM policies, unencrypted storage)
- [ ] Risk scoring
- [ ] Terraform / CLI remediation generator
- [ ] Verification & before/after diff
- [ ] Azure and GCP adapters
- [ ] REST API + dashboard

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and [SECURITY.md](SECURITY.md).

## 📄 License

See [LICENSE](LICENSE).
