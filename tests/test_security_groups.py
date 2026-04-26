"""
Automated Network Security Tests 
=============================================
QA background applied to infrastructure:
Validates that security groups and the network topology
are configured exactly as they should be.

If anyone accidentally modifies a rule, these tests will fail.

Usage:
    pip install pytest boto3 pytest-html
    pytest tests/ -v --html=reports/security-report.html

Requirements:
    - AWS credentials configured (aws configure or env vars)
    - VPC_ID environment variable set to the created VPC ID
    - BASTION_SG_ID and PRIVATE_SG_ID environment variables set
"""

import os
import boto3
import pytest

# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture(scope="session")
def ec2_client():
    return boto3.client("ec2", region_name=os.environ.get("AWS_REGION", "us-east-1"))

@pytest.fixture(scope="session")
def vpc_id():
    vpc_id = os.environ.get("VPC_ID")
    if not vpc_id:
        pytest.skip("VPC_ID not set. Export it: export VPC_ID=vpc-xxxxxxxx")
    return vpc_id

@pytest.fixture(scope="session")
def bastion_sg_id():
    sg_id = os.environ.get("BASTION_SG_ID")
    if not sg_id:
        pytest.skip("BASTION_SG_ID not set.")
    return sg_id

@pytest.fixture(scope="session")
def private_sg_id():
    sg_id = os.environ.get("PRIVATE_SG_ID")
    if not sg_id:
        pytest.skip("PRIVATE_SG_ID not set.")
    return sg_id

@pytest.fixture(scope="session")
def vpc_info(ec2_client, vpc_id):
    response = ec2_client.describe_vpcs(VpcIds=[vpc_id])
    return response["Vpcs"][0]

@pytest.fixture(scope="session")
def bastion_sg(ec2_client, bastion_sg_id):
    response = ec2_client.describe_security_groups(GroupIds=[bastion_sg_id])
    return response["SecurityGroups"][0]

@pytest.fixture(scope="session")
def private_sg(ec2_client, private_sg_id):
    response = ec2_client.describe_security_groups(GroupIds=[private_sg_id])
    return response["SecurityGroups"][0]

# ── Helpers ───────────────────────────────────────────────

def get_ingress_rules(sg: dict) -> list:
    return sg.get("IpPermissions", [])

def get_egress_rules(sg: dict) -> list:
    return sg.get("IpPermissionsEgress", [])

def rule_allows_port_from_cidr(rules: list, port: int, cidr: str) -> bool:
    for rule in rules:
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)
        if from_port <= port <= to_port:
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == cidr:
                    return True
    return False

def rule_allows_port_from_sg(rules: list, port: int, source_sg_id: str) -> bool:
    for rule in rules:
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)
        if from_port <= port <= to_port:
            for sg_pair in rule.get("UserIdGroupPairs", []):
                if sg_pair.get("GroupId") == source_sg_id:
                    return True
    return False

def rule_allows_all_traffic(rules: list) -> bool:
    """Checks for a protocol -1 rule (all traffic) — should always return False."""
    for rule in rules:
        if rule.get("IpProtocol") == "-1":
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    return True
    return False

# ── VPC Tests ─────────────────────────────────────────────

class TestVPCConfiguration:
    """Validates basic VPC configuration."""

    def test_vpc_exists(self, vpc_info):
        """VPC must exist and be in available state."""
        assert vpc_info["State"] == "available", "VPC is not in 'available' state"

    def test_vpc_has_correct_cidr(self, vpc_info):
        """VPC must use the planned CIDR block."""
        expected_cidr = os.environ.get("EXPECTED_VPC_CIDR", "10.0.0.0/16")
        assert vpc_info["CidrBlock"] == expected_cidr, \
            f"Expected CIDR: {expected_cidr}, found: {vpc_info['CidrBlock']}"

    def test_vpc_dns_enabled(self, vpc_info):
        """DNS support must be enabled on the VPC."""
        assert vpc_info.get("EnableDnsSupport") != False, \
            "DNS Support must be enabled on the VPC"

    def test_vpc_has_required_tags(self, vpc_info):
        """VPC must have project and environment tags."""
        tags = {t["Key"]: t["Value"] for t in vpc_info.get("Tags", [])}
        assert "Project" in tags, "Tag 'Project' missing on VPC"
        assert "Environment" in tags, "Tag 'Environment' missing on VPC"
        assert "ManagedBy" in tags, "Tag 'ManagedBy' missing — must be 'terraform'"
        assert tags["ManagedBy"] == "terraform", \
            "Tag ManagedBy must be 'terraform' — infrastructure must be managed via IaC"

# ── Subnet Tests ──────────────────────────────────────────

class TestSubnetConfiguration:
    """Validates public and private subnet isolation."""

    @pytest.fixture
    def subnets(self, ec2_client, vpc_id):
        response = ec2_client.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )
        return response["Subnets"]

    def test_has_public_and_private_subnets(self, subnets):
        """Both public and private tier subnets must exist."""
        tiers = set()
        for subnet in subnets:
            tags = {t["Key"]: t["Value"] for t in subnet.get("Tags", [])}
            tiers.add(tags.get("Tier", "unknown"))
        assert "public" in tiers, "No public subnet found"
        assert "private" in tiers, "No private subnet found"

    def test_private_subnets_no_public_ip(self, subnets):
        """Private subnets must NOT auto-assign public IPs."""
        for subnet in subnets:
            tags = {t["Key"]: t["Value"] for t in subnet.get("Tags", [])}
            if tags.get("Tier") == "private":
                assert not subnet["MapPublicIpOnLaunch"], \
                    f"Private subnet {subnet['SubnetId']} is configured to auto-assign public IPs!"

    def test_public_subnets_no_auto_public_ip(self, subnets):
        """Public subnets must also NOT auto-assign public IPs (explicit assignment only)."""
        for subnet in subnets:
            tags = {t["Key"]: t["Value"] for t in subnet.get("Tags", [])}
            if tags.get("Tier") == "public":
                assert not subnet["MapPublicIpOnLaunch"], \
                    f"Subnet {subnet['SubnetId']}: MapPublicIpOnLaunch must be false — " \
                    "public IPs must be assigned explicitly"

# ── Bastion Security Group Tests ──────────────────────────

class TestBastionSecurityGroup:
    """
    Validates that the bastion host is correctly configured:
    - SSH accepted ONLY from authorized IPs
    - No unnecessary ports open
    - No 'allow all' rule (0.0.0.0/0 for all traffic)
    """

    def test_bastion_has_no_allow_all_ingress(self, bastion_sg):
        """CRITICAL: Bastion must not have a rule allowing all inbound traffic."""
        assert not rule_allows_all_traffic(get_ingress_rules(bastion_sg)), \
            "CRITICAL FAILURE: Bastion has an ingress rule allowing ALL traffic!"

    def test_bastion_ssh_not_open_to_world(self, bastion_sg):
        """CRITICAL: Bastion SSH must NOT be open to 0.0.0.0/0."""
        ssh_open_to_world = rule_allows_port_from_cidr(
            get_ingress_rules(bastion_sg), port=22, cidr="0.0.0.0/0"
        )
        assert not ssh_open_to_world, \
            "CRITICAL FAILURE: Port 22 is open to 0.0.0.0/0! " \
            "This violates the least-privilege principle."

    def test_bastion_no_rdp_open(self, bastion_sg):
        """RDP port (3389) must not be open to the internet."""
        rdp_open = rule_allows_port_from_cidr(
            get_ingress_rules(bastion_sg), port=3389, cidr="0.0.0.0/0"
        )
        assert not rdp_open, "RDP port (3389) is open to the internet!"

    def test_bastion_has_description_on_rules(self, bastion_sg):
        """All rules must have a description (documentation is security)."""
        for rule in get_ingress_rules(bastion_sg):
            for ip_range in rule.get("IpRanges", []):
                desc = ip_range.get("Description", "").strip()
                assert desc, \
                    f"Ingress rule without description on bastion SG. " \
                    f"Port: {rule.get('FromPort')} — CIDR: {ip_range.get('CidrIp')}. " \
                    "All rules must have a description."

# ── Private Instances Security Group Tests ────────────────

class TestPrivateInstancesSecurityGroup:
    """
    Validates isolation of private instances:
    - Must only accept SSH from the bastion
    - Must not have direct SSH access from the internet
    """

    def test_private_no_direct_ssh_from_internet(self, private_sg):
        """CRITICAL: Private instances must not accept SSH from the internet."""
        ssh_from_internet = rule_allows_port_from_cidr(
            get_ingress_rules(private_sg), port=22, cidr="0.0.0.0/0"
        )
        assert not ssh_from_internet, \
            "CRITICAL FAILURE: Private instances accept SSH directly from the internet!"

    def test_private_accepts_ssh_from_bastion(self, private_sg, bastion_sg_id):
        """Private instances MUST accept SSH from the bastion SG."""
        ssh_from_bastion = rule_allows_port_from_sg(
            get_ingress_rules(private_sg), port=22, source_sg_id=bastion_sg_id
        )
        assert ssh_from_bastion, \
            "Private instances are not accepting SSH from the bastion! " \
            "Check the ingress rule referencing the bastion SG."

    def test_private_no_allow_all_ingress(self, private_sg):
        """CRITICAL: Private instances must not have an allow-all rule."""
        assert not rule_allows_all_traffic(get_ingress_rules(private_sg)), \
            "CRITICAL FAILURE: Private security group has an allow-all rule!"

# ── Flow Logs Tests ───────────────────────────────────────

class TestFlowLogs:
    """Verifies VPC Flow Logs are enabled (CIS AWS Benchmark requirement)."""

    @pytest.fixture
    def flow_logs(self, ec2_client, vpc_id):
        response = ec2_client.describe_flow_logs(
            Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
        )
        return response["FlowLogs"]

    def test_flow_logs_enabled(self, flow_logs):
        """VPC Flow Logs must be enabled."""
        assert len(flow_logs) > 0, \
            "VPC Flow Logs are not enabled! " \
            "This violates the CIS AWS Benchmark and hinders incident auditing."

    def test_flow_logs_capture_all_traffic(self, flow_logs):
        """Flow Logs must capture ALL traffic (ACCEPT + REJECT)."""
        for fl in flow_logs:
            assert fl["TrafficType"] == "ALL", \
                f"Flow Log {fl['FlowLogId']} only captures '{fl['TrafficType']}'. " \
                "Must be 'ALL' for complete auditing."

    def test_flow_logs_active(self, flow_logs):
        """Flow Logs must be in ACTIVE state."""
        for fl in flow_logs:
            assert fl["FlowLogStatus"] == "ACTIVE", \
                f"Flow Log {fl['FlowLogId']} is not ACTIVE: {fl['FlowLogStatus']}"
