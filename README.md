# Secure VPC with Bastion Host on AWS

> **Stack:** AWS · Terraform · Python · GitHub Actions  
> **Level:** Beginner  
> **Series:** AWS Networking Portfolio — Project 1/5  
> **Deploy time:** ~5 minutes with `terraform apply`

Secure AWS VPC with hardened bastion host, private subnet isolation, and least-privilege security groups — built with Terraform and validated by an automated pytest suite that catches misconfigurations in CI.

---

## The real problem

A startup deployed EC2 instances directly in a public subnet with port 22 (SSH) open to `0.0.0.0/0`. Four hours after deploy, automated bots detected the IP and launched a brute-force attack. The instance was compromised, AWS credentials were extracted via the metadata endpoint, and the attacker spun up additional resources — resulting in an unexpected bill.

**Estimated incident impact:**
- Financial cost: $12,000 in attacker-created resources within 48h
- Downtime: 6 hours of investigation and remediation
- Regulatory risk: potential data breach notification

**Why does this happen?** The standard tutorial teaches how to create the infrastructure — but not how to secure it.

---

## The solution

A two-tier architecture with a **bastion host** as the single SSH entry point, workload instances fully isolated in a private subnet, and all traffic audited by VPC Flow Logs.

```
Internet
    │
    ▼
[Internet Gateway]
    │
    ▼
┌─────────────────────────────────────────────┐
│  VPC 10.0.0.0/16                            │
│                                             │
│  ┌──────────────────┐                       │
│  │  Public Subnet   │                       │
│  │  10.0.0.0/24     │                       │
│  │                  │                       │
│  │  ┌────────────┐  │                       │
│  │  │  Bastion   │  │ ← SSH from your       │
│  │  │  Host      │  │   IP only (/32 CIDR)  │
│  │  │  (EIP)     │  │                       │
│  │  └─────┬──────┘  │                       │
│  └────────┼─────────┘                       │
│           │ SSH via SG reference            │
│  ┌────────┼─────────┐                       │
│  │  Private Subnet  │                       │
│  │  10.0.10.0/24    │                       │
│  │                  │                       │
│  │  ┌────────────┐  │                       │
│  │  │  App EC2   │  │ ← No public IP        │
│  │  │  (private) │  │   No internet route   │
│  │  └────────────┘  │                       │
│  └──────────────────┘                       │
│                                             │
│  [VPC Flow Logs → CloudWatch]               │
└─────────────────────────────────────────────┘
```

---

## What goes beyond the tutorial?

| NextWork Tutorial | This implementation |
|---|---|
| Manual setup in the console | 100% Terraform — reproducible in minutes |
| No tests | pytest suite that validates network rules |
| No auditing | VPC Flow Logs + CloudWatch integrated |
| SSH open for convenience | SSH restricted to admin IP via `/32` |
| No OS hardening | Fail2ban, auditd, secure SSHd config |
| No CI/CD | GitHub Actions with tfsec + checkov |
| No cost analysis | Infracost integrated in the pipeline |

---

## Measurable impact

| Metric | Without protection | With this solution |
|---|---|---|
| SSH attack surface | Entire internet (~4B IPs) | 1 specific IP |
| Time to brute-force compromise | ~4 hours (observed) | Practically infeasible |
| Traffic auditability | None | 100% (Flow Logs) |
| Environment reproducibility | Manual (hours) | `terraform apply` (5 min) |
| Config drift detection | None | Automated daily CI |

---

## How to reproduce

### Prerequisites

```bash
# AWS CLI configured
aws configure

# Terraform installed
terraform -version  # >= 1.5.0

# Python for the tests
python -m pip install pytest boto3 pytest-html
```

### Deploy

```bash
# 1. Clone the repository
git clone https://github.com/your-username/devsecops-portfolio
cd aws-secure-vpc-bastion/terraform

# 2. Configure variables
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values

# 3. Initialize and apply
terraform init
terraform plan   # Review what will be created
terraform apply

# 4. Note the important outputs
terraform output ssh_command_bastion
terraform output ssh_command_private
```

### Connect via SSH

```bash
# To the bastion
ssh -i keys/devsecops-p1-lab-bastion.pem ec2-user@<bastion-ip>

# To the private instance (ProxyJump via bastion)
ssh -i keys/devsecops-p1-lab-bastion.pem \
    -J ec2-user@<bastion-ip> \
    ec2-user@<private-ip>
```

---

## Automated security tests

```bash
# Export variables from the created environment
export VPC_ID=$(terraform -chdir=terraform output -raw vpc_id)
export BASTION_SG_ID=$(terraform -chdir=terraform output -raw security_groups | jq -r '.bastion')
export PRIVATE_SG_ID=$(terraform -chdir=terraform output -raw security_groups | jq -r '.private_instances')

# Run the tests
cd ..
pytest tests/ -v --html=reports/security-report.html

# Report generated at: reports/security-report.html
```

**What the tests validate:**
- ✅ Port 22 NOT open to `0.0.0.0/0` on the bastion
- ✅ Private instances accept SSH only from the bastion SG
- ✅ No security group has an allow-all rule
- ✅ VPC Flow Logs enabled and capturing ALL traffic
- ✅ Private subnets without auto-assignment of public IPs
- ✅ Required tags present on all resources

---

## Cost analysis

```bash
# Cost estimate with Infracost
infracost breakdown --path terraform/
```

**Estimated cost (us-east-1):**

| Resource | Cost/month |
|---|---|
| 2x EC2 t3.micro | ~$15.00 |
| 1x Elastic IP | $0 (associated) |
| CloudWatch Logs (30 days) | ~$2.00 |
| **Total** | **~$17/month** |

> **ROI:** The incident described above ($12,000) would fund ~58 years of this secure infrastructure.

---

## CIS AWS Benchmark checklist

- [x] VPC Flow Logs enabled (CIS 3.9)
- [x] No security group with SSH open to `0.0.0.0/0` (CIS 5.2)
- [x] IMDSv2 required on all instances (CIS 5.6)
- [x] Encrypted EBS volumes (CIS 2.2.1)
- [x] Root login disabled via SSH
- [x] Password-based SSH disabled
- [x] Authentication logs in CloudWatch

---

## Lessons learned

Things that **are not in the tutorial** but discovered during implementation:

1. **`map_public_ip_on_launch = false`** must be explicit even on public subnets — public IPs should be assigned only to what needs it (the bastion via EIP), not automatically.

2. **SG-to-SG references > CIDRs** — in the bastion egress, referencing the private instances security group is safer than using the private subnet CIDR. If the CIDR changes, the rule doesn't break — and you don't expose more than necessary.

3. **IMDSv2 is critical** — the classic SSRF attack in cloud abuses the `169.254.169.254` metadata endpoint. Enforcing IMDSv2 (`http_tokens = "required"`) eliminates this entire attack class.

4. **Fail2ban keeps audit logs clean** — without it, brute-force attacks flood `/var/log/secure`, making it hard to spot legitimate activity among the noise.

5. **Terraform auto-detected my IP** — using `data "http"` to fetch the external IP, the security group gets configured with the correct IP automatically, no hardcoding needed in tfvars.

---

## 🔗 Next steps (what I would do in production)

- [ ] Replace SSH with **AWS Systems Manager Session Manager** (eliminates port 22 entirely)
- [ ] Add **AWS CloudTrail** for API call auditing
- [ ] Implement **AWS Config** with a custom rule to detect configuration drift
- [ ] Add a **NAT Gateway** for controlled outbound updates from private instances
- [ ] Configure **CloudWatch Alarms** for failed login attempts

---

## 🔗 Resources

- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS VPC Security Best Practices](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-best-practices.html)
- [Base tutorial: NextWork — Build a VPC](https://learn.nextwork.org/projects/aws-networks-vpc)

---
