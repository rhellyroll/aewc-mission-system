# AEW&C Ground Mission Station — RHEL 9 Hardening & Automation Lab Series

**Repo:** `rhellyroll/aewc-mission-system`

> Hardened, automated, and compliance-aligned RHEL 9 deployment simulating an **Airborne Early Warning & Control (AEW&C) Ground Mission Station (GMS)** node.
> This lab series demonstrates STIG-informed system hardening, encryption at rest, centralized audit logging, and idempotent configuration enforcement aligned to **NIST SP 800-53 Rev. 5** controls.
> All controls are implemented as production-style, reusable Ansible roles and validated end-to-end with drift detection.

---

## Architecture Overview

| Component    | Hostname      | IP Address      | Role                                    |
| ------------ | ------------- | --------------- | --------------------------------------- |
| Control Node | control-node  | 192.168.10.5    | Ansible automation, Git version control |
| GMS Node     | aewc-gms-01   | 192.168.10.10   | Hardened RHEL 9 mission system          |
| Log Server   | log-server-01 | 192.168.10.20   | Centralized audit log receiver          |
| Network      | Host-only     | 192.168.10.0/24 | Isolated management enclave             |

**Platform:** 3-VM VirtualBox homelab  
**Automation Model:** Idempotent Ansible roles  
**Security Posture:** DISA STIG-aligned baseline with encryption + centralized auditing

---

## Threat Model Assumptions

This system simulates a mission ground station operating within a restricted enclave under the following risk assumptions:

- Insider privilege misuse
- Credential theft and lateral movement
- Exploit attempts against exposed network services
- Physical disk removal or improper system decommission
- Local audit log tampering following compromise
- Configuration drift leading to non-compliance

Security controls were selected to mitigate these operational risks while maintaining mission availability and audit integrity.

---

## Lab Breakdown

---

### A1 — Baseline Hardening

#### What Was Implemented

- SELinux set to **Enforcing** (targeted policy)
- firewalld configured to `internal` zone
- Source restriction limited to `192.168.10.0/24`
- Supplemental nftables `aewc_filter` table with custom input chain
- Hostname configuration via Ansible
- Idempotency validation (`changed=0 failed=0`)

#### firewalld + nftables Integration

RHEL 9 uses nftables as the native backend for firewalld.
The `aewc_filter` table was implemented as a supplemental nftables chain operating alongside firewalld-managed rules — not replacing them.

Validation:

```bash
nft list ruleset
```

Confirmed:

- No duplicate INPUT chains
- No rule ordering conflicts
- No override of firewalld-managed policies

#### STIG Mapping

| STIG ID        | Requirement                            |
| -------------- | -------------------------------------- |
| RHEL-09-431010 | SELinux must be enforcing              |
| RHEL-09-211020 | System must implement a firewall       |
| RHEL-09-211030 | Firewall must restrict inbound traffic |

#### NIST 800-53 Mapping

| Control | Description            |
| ------- | ---------------------- |
| CM-6    | Configuration Settings |
| SI-2    | Flaw Remediation       |

#### Operational Relevance

Mandatory access control and enclave-bound ingress filtering reduce lateral movement risk and limit blast radius in case of subsystem compromise.

---

### A2 — Kernel Hardening

#### What Was Implemented

Persisted via `/etc/sysctl.d/99-aewc-hardening.conf`:

| Parameter                            | Value | Purpose                 |
| ------------------------------------ | ----- | ----------------------- |
| `kernel.randomize_va_space`          | `2`   | Full ASLR               |
| `net.ipv4.ip_forward`                | `0`   | Disable IP forwarding   |
| `fs.suid_dumpable`                   | `0`   | Core dump restriction   |
| `net.ipv4.tcp_syncookies`            | `1`   | SYN flood protection    |
| `net.ipv4.conf.all.accept_redirects` | `0`   | ICMP redirect rejection |
| `net.ipv4.conf.all.rp_filter`        | `1`   | Reverse path filtering  |

Validation:

```bash
sysctl -a | grep <parameter>
```

#### STIG Mapping

| STIG ID        | Requirement                      |
| -------------- | -------------------------------- |
| RHEL-09-213060 | IP forwarding disabled           |
| RHEL-09-213110 | ICMP redirects disabled          |
| RHEL-09-213080 | Reverse path filtering enabled   |

#### NIST 800-53 Mapping

| Control | Description            |
| ------- | ---------------------- |
| CM-6    | Configuration Settings |
| SI-2    | System Hardening       |

#### Operational Relevance

Kernel-level attack surface reduction mitigates exploit reliability, enforces enclave-only routing, and strengthens resilience against network-layer abuse.

---

### A3 — Disk Encryption (Encryption at Rest)

#### What Was Implemented

- LUKS-encrypted secondary volume (`/dev/sdb`)
- Registered in `/etc/crypttab` for boot-time unlock
- XFS filesystem provisioned
- Persistent mount at `/mnt/secure`
- Fully automated via Ansible

#### Passphrase Management

- LUKS passphrase stored as `vault_luks_passphrase`
- Protected via **Ansible Vault** (`group_vars/aewc_gms/vault.yml`)
- No plaintext credentials stored in repository
- Vault password excluded from version control

In a production or classified environment, this would transition to:

- Enterprise secrets manager (HashiCorp Vault / CyberArk)
- TPM-bound key
- Hardware-backed cryptographic module

#### Idempotency Safeguard

`cryptsetup luksFormat` is destructive and non-idempotent.

Resolved by:

- Pre-check using `cryptsetup isLuks`
- Conditional execution only if device not already formatted

#### STIG Mapping

| STIG ID        | Requirement          |
| -------------- | -------------------- |
| RHEL-09-611010 | Encrypt data at rest |

#### NIST 800-53 Mapping

| Control | Description                       |
| ------- | --------------------------------- |
| SC-28   | Protection of Information at Rest |

#### Operational Relevance

Protects mission data against physical compromise and supports controlled decommission procedures aligned with FIPS cryptographic requirements.

---

### A4 — Auditd Remote Logging

#### What Was Implemented

On `aewc-gms-01`:

- Installed `audispd-plugins`
- Configured `audisp-remote` for TCP forwarding to `log-server-01`

On `log-server-01`:

- Configured `tcp_listen_port = 60` in `auditd.conf`

Validated:

```bash
ss -lntp | grep :60
```

Confirmed forwarded logs containing `hostname=aewc-gms-01` in `/var/log/audit/audit.log`.

#### Audit Rules Implemented

Defined in `/etc/audit/rules.d/aewc.rules` and loaded via `augenrules --load`:

```bash
# Privileged execution monitoring
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k privileged

# Identity file modification
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity

# Sudoers modification
-w /etc/sudoers -p wa -k sudoers

# Syscall monitoring
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=unset -k exec
-a always,exit -F arch=b64 -S open,unlink -F auid>=1000 -k file_access

# Login/logout events
-w /var/log/lastlog -p wa -k logins
```

Validation:

```bash
auditctl -l
```

#### Port 60 Justification

Port 60 is the default TCP port used by `audisp-remote` per IANA assignment. Binding to a privileged port (<1024) is expected behavior for auditd on RHEL 9 and aligns with STIG remote audit forwarding guidance.

#### STIG Mapping

| STIG ID        | Requirement                     |
| -------------- | ------------------------------- |
| RHEL-09-653010 | Audit logs must be protected    |
| RHEL-09-653020 | Audit records must be forwarded |

#### NIST 800-53 Mapping

| Control | Description                     |
| ------- | ------------------------------- |
| AU-9    | Protection of Audit Information |

#### Operational Relevance

Enables forensic reconstruction and preserves evidentiary integrity under incident response procedures by preventing local log tampering.

---

### A5 — Final Integration Validation

#### What Was Validated

| Control                | Validation Command                 | Expected Result      |
| ---------------------- | ---------------------------------- | -------------------- |
| SELinux enforcement    | `getenforce`                       | `Enforcing`          |
| ASLR                   | `sysctl kernel.randomize_va_space` | `2`                  |
| Encrypted mount        | `mount \| grep /mnt/secure`        | Present              |
| Firewall source        | `firewall-cmd --list-all`          | `192.168.10.0/24`    |
| Audit listener         | `ss -lntp \| grep :60`             | Port 60 bound        |
| Audit rules loaded     | `auditctl -l`                      | Rules present        |
| Idempotency            | Second playbook run                | `changed=0 failed=0` |

#### Development Issues Resolved

**LUKS idempotency** — `cryptsetup luksFormat` is destructive on re-run. Resolved by gating execution behind a `cryptsetup isLuks` pre-check.

**RHEL 9 audit plugin path** — `audisp-remote` plugin config path changed from the deprecated `/etc/audisp/plugins.d/` to `/etc/audit/plugins.d/` in RHEL 9. Template target corrected accordingly.

**nftables rule ordering** — Supplemental `aewc_filter` chain validated against full `nft list ruleset` output to confirm no conflict with firewalld-managed rules.

#### OpenSCAP / SCAP Scanning

Automated SCAP evaluation via OpenSCAP was not performed in this lab iteration. Manual validation of individual STIG controls was conducted via Ansible ad-hoc commands and system-level inspection as documented above. SCAP benchmark integration is identified as the next planned iteration using:

```bash
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig \
  --results scan-results.xml \
  --report scan-report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-xccdf.xml
```

#### STIG Mapping

Configuration enforcement across multiple STIG categories — see per-lab mappings above.

#### NIST 800-53 Mapping

| Control | Description            |
| ------- | ---------------------- |
| CM-6    | Configuration Settings |

#### Operational Relevance

Demonstrates repeatable, drift-resistant deployment suitable for controlled defense environments where configuration deviation may constitute a security incident.

---

## Ansible Role Structure

```
aewc-mission-system/
├── inventory/
│   └── hosts.ini
├── playbooks/
│   └── site.yml
├── roles/
│   ├── baseline_hardening/
│   │   ├── tasks/
│   │   ├── handlers/
│   │   ├── templates/
│   │   └── defaults/
│   ├── kernel_hardening/
│   ├── disk_encryption/
│   ├── audit_remote/
│   └── integration_validation/
├── group_vars/
│   └── aewc_gms/
│       ├── vars.yml
│       └── vault.yml        # Encrypted via Ansible Vault — no plaintext secrets
└── .github/
    └── workflows/
        └── ansible-lint.yml
```

All roles are:

- Idempotent
- Variable-driven
- Vault-integrated
- Linted via CI on push

---

## How to Run

### 1. Clone Repository

```bash
git clone https://github.com/rhellyroll/aewc-mission-system.git
cd aewc-mission-system
```

### 2. Configure Inventory

Edit `inventory/hosts.ini` with correct IP mappings for all three hosts.

### 3. Create Vault File

```bash
ansible-vault create group_vars/aewc_gms/vault.yml
```

Add:

```yaml
vault_luks_passphrase: <your-passphrase>
```

### 4. Execute Deployment

```bash
ansible-playbook -i inventory/hosts.ini playbooks/site.yml --ask-vault-pass
```

### 5. Validate Idempotency

Run the playbook a second time — expect:

```
changed=0
failed=0
```

---

## Security Controls Summary

| Lab | Capability               | NIST 800-53 | DISA STIG IDs                                   |
| --- | ------------------------ | ----------- | ----------------------------------------------- |
| A1  | SELinux + Firewall       | CM-6, SI-2  | RHEL-09-431010, RHEL-09-211020, RHEL-09-211030  |
| A2  | Kernel Hardening         | CM-6, SI-2  | RHEL-09-213060, RHEL-09-213110, RHEL-09-213080  |
| A3  | Encryption at Rest       | SC-28       | RHEL-09-611010                                  |
| A4  | Remote Audit Logging     | AU-9        | RHEL-09-653010, RHEL-09-653020                  |
| A5  | Configuration Validation | CM-6        | Multi-category enforcement                      |

---

## Compliance Alignment

| Control                                           | Status |
| ------------------------------------------------- | :----: |
| Mandatory Access Controls (SELinux Enforcing)     | ✅     |
| Network Boundary Protection (firewalld + nftables)| ✅     |
| Encryption at Rest (LUKS + Ansible Vault)         | ✅     |
| Centralized Audit Logging (audisp-remote)         | ✅     |
| STIG-Aligned Audit Rules                          | ✅     |
| Idempotent Configuration Enforcement              | ✅     |
| No Plaintext Secrets in Repository                | ✅     |

---

## Project Positioning

This project simulates a hardened AEW&C mission ground system deployed inside a segmented enclave with centralized audit logging and automated compliance enforcement.

It demonstrates the ability to:

- Engineer secure-by-default RHEL 9 systems aligned to DISA STIG
- Translate compliance frameworks into executable infrastructure automation
- Implement encryption and audit controls without exposing secrets
- Diagnose and resolve configuration failures during implementation
- Enforce configuration state consistently across distributed systems

---

**Author:** Caleb Sims  
Defense-Oriented Linux Automation | RHEL 9 | Ansible | DISA STIG | NIST 800-53  
Interim Secret Clearance
