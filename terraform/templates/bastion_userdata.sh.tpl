#!/bin/bash
###############################################################
# Bastion Host — Hardening Script (User Data)
# Runs on first instance boot
###############################################################

set -euo pipefail
exec > >(tee /var/log/user-data.log | logger -t user-data) 2>&1

echo "=== Starting bastion host hardening ==="
echo "Project: ${project_name} | Environment: ${environment}"

###############################################################
# 1. UPDATE THE SYSTEM
###############################################################
echo "[1/7] Updating system packages..."
dnf update -y --security

###############################################################
# 2. INSTALL AUDITING TOOLS
###############################################################
echo "[2/7] Installing security tools..."
dnf install -y \
  auditd \
  fail2ban \
  aide \
  amazon-cloudwatch-agent \
  jq \
  nmap \
  --skip-broken || true

###############################################################
# 3. SSH HARDENING
###############################################################
echo "[3/7] Applying secure SSH configuration..."

cat > /etc/ssh/sshd_config.d/99-hardening.conf << 'EOF'
# SSH Hardening — CIS Benchmark Level 1
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
Banner /etc/ssh/banner.txt
AllowUsers ec2-user
EOF

# Legal warning banner (security best practice)
cat > /etc/ssh/banner.txt << 'EOF'
*************************************************************
*        RESTRICTED ACCESS — MONITORED SYSTEM              *
*                                                           *
* This system is for authorized personnel only.            *
* All access is logged and monitored.                      *
* Unauthorized access is a criminal offense.               *
*************************************************************
EOF

systemctl restart sshd

###############################################################
# 4. CONFIGURE AUDITD
###############################################################
echo "[4/7] Configuring system auditing..."

cat > /etc/audit/rules.d/99-bastion.rules << 'EOF'
# Monitor SSH login attempts
-w /var/log/secure -p wa -k auth_log
-w /etc/ssh/sshd_config -p wa -k ssh_config

# Monitor sudo usage
-w /etc/sudoers -p wa -k sudoers
-w /var/log/sudo.log -p wa -k sudo_log

# Monitor user and group changes
-w /etc/passwd -p wa -k user_modification
-w /etc/group -p wa -k group_modification
-w /etc/shadow -p wa -k shadow_modification

# Monitor suspicious command execution
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands
EOF

systemctl enable auditd
systemctl start auditd

###############################################################
# 5. CONFIGURE FAIL2BAN
###############################################################
echo "[5/7] Configuring fail2ban..."

cat > /etc/fail2ban/jail.d/sshd.conf << 'EOF'
[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/secure
maxretry = 3
bantime  = 3600
findtime = 600
EOF

systemctl enable fail2ban
systemctl start fail2ban

###############################################################
# 6. CONFIGURE CLOUDWATCH AGENT
###############################################################
echo "[6/7] Configuring CloudWatch Agent..."

cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'EOF'
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/secure",
            "log_group_name": "/ec2/bastion/auth",
            "log_stream_name": "{instance_id}",
            "retention_in_days": 30
          },
          {
            "file_path": "/var/log/user-data.log",
            "log_group_name": "/ec2/bastion/userdata",
            "log_stream_name": "{instance_id}",
            "retention_in_days": 7
          }
        ]
      }
    }
  },
  "metrics": {
    "metrics_collected": {
      "cpu": { "measurement": ["cpu_usage_idle", "cpu_usage_user"], "metrics_collection_interval": 60 },
      "mem": { "measurement": ["mem_used_percent"], "metrics_collection_interval": 60 },
      "disk": { "measurement": ["disk_used_percent"], "metrics_collection_interval": 300 }
    }
  }
}
EOF

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config \
  -m ec2 \
  -s \
  -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json

###############################################################
# 7. DISABLE UNNECESSARY SERVICES
###############################################################
echo "[7/7] Disabling unused services..."

for service in postfix avahi-daemon cups bluetooth; do
  systemctl disable "$service" 2>/dev/null || true
  systemctl stop "$service" 2>/dev/null || true
done

echo "=== Hardening completed successfully! ==="
echo "Bastion host ready for secure use."
