import boto3
import json
import csv
from datetime import datetime, timezone
from botocore.exceptions import ClientError, BotoCoreError


# ============================================================
# AWS CLOUD SECURITY SCANNER
# Read-only AWS security assessment tool
# ============================================================

RISK_POINTS = {
    "CRITICAL": 20,
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2
}

# Project-defined threshold for old active access keys.
ACCESS_KEY_MAX_AGE_DAYS = 90

findings = []


# ============================================================
# GENERAL HELPERS
# ============================================================

def add_finding(service, resource, issue, severity, recommendation):
    findings.append({
        "service": service,
        "resource": resource,
        "issue": issue,
        "severity": severity,
        "risk": RISK_POINTS[severity],
        "recommendation": recommendation
    })


def print_header():
    print("\n" + "=" * 50)
    print("          AWS CLOUD SECURITY SCANNER")
    print("=" * 50)


def print_section(title):
    print("\n" + "-" * 50)
    print(title)
    print("-" * 50)


def handle_error(service, error):
    if isinstance(error, ClientError):
        error_data = error.response.get("Error", {})
        code = error_data.get("Code", "Unknown")
        message = error_data.get("Message", "Unknown error")

        print(f"⚠ {service}: {code} - {message}")

    else:
        print(f"⚠ {service}: {error}")


def get_paginated_items(client, operation, result_key, **kwargs):
    """
    Retrieve all items from a paginated AWS API operation.
    """

    try:
        paginator = client.get_paginator(operation)

        items = []

        for page in paginator.paginate(**kwargs):
            items.extend(page.get(result_key, []))

        return items

    except Exception as error:
        handle_error(operation, error)
        return []


def mask_access_key(key_id):
    """
    Display only part of an AWS access key ID.
    """

    if not key_id:
        return "Unknown"

    if len(key_id) <= 8:
        return key_id

    return f"{key_id[:4]}{'x' * 10}{key_id[-2:]}"


# ============================================================
# S3 HELPERS
# ============================================================

def get_bucket_region(s3_client, bucket_name):
    """
    Find the actual AWS region of an S3 bucket.
    """

    try:
        response = s3_client.get_bucket_location(
            Bucket=bucket_name
        )

        location = response.get("LocationConstraint")

        # S3 returns None for us-east-1.
        if location is None:
            return "us-east-1"

        # Older S3 location value.
        if location == "EU":
            return "eu-west-1"

        return location

    except Exception as error:
        handle_error(
            f"S3 region ({bucket_name})",
            error
        )

        return None


def get_bucket_client(session, s3_client, bucket_name):
    """
    Create an S3 client for the bucket's actual region.
    """

    bucket_region = get_bucket_region(
        s3_client,
        bucket_name
    )

    if not bucket_region:
        return None, None

    try:
        regional_client = session.client(
            "s3",
            region_name=bucket_region
        )

        return regional_client, bucket_region

    except Exception as error:
        handle_error(
            f"S3 client ({bucket_name})",
            error
        )

        return None, None


# ============================================================
# S3 SECURITY ASSESSMENT
# ============================================================

def scan_s3(session, s3_client, buckets):

    print_section("S3 SECURITY ASSESSMENT")

    print(
        f"S3 Buckets Found: {len(buckets)}"
    )

    if not buckets:
        print("No S3 buckets found.")
        return

    for bucket in buckets:

        bucket_name = bucket.get(
            "Name",
            "Unknown"
        )

        print(f"\nBucket: {bucket_name}")

        regional_s3, bucket_region = get_bucket_client(
            session,
            s3_client,
            bucket_name
        )

        if not regional_s3:
            continue

        print(
            f"Region: {bucket_region}"
        )

        check_s3_public_access(
            regional_s3,
            bucket_name
        )

        check_s3_acl(
            regional_s3,
            bucket_name
        )

        check_s3_policy(
            regional_s3,
            bucket_name
        )

        check_s3_encryption(
            regional_s3,
            bucket_name
        )

        check_s3_versioning(
            regional_s3,
            bucket_name
        )


# ============================================================
# S3 - BLOCK PUBLIC ACCESS
# ============================================================

def check_s3_public_access(
    s3_client,
    bucket_name
):

    try:

        response = s3_client.get_public_access_block(
            Bucket=bucket_name
        )

        config = response.get(
            "PublicAccessBlockConfiguration",
            {}
        )

        settings = [
            config.get("BlockPublicAcls", False),
            config.get("IgnorePublicAcls", False),
            config.get("BlockPublicPolicy", False),
            config.get("RestrictPublicBuckets", False)
        ]

        if all(settings):

            print(
                "✓ Block Public Access: Enabled"
            )

        else:

            add_finding(
                "S3",
                bucket_name,
                "S3 Block Public Access is not fully enabled",
                "HIGH",
                "Enable all S3 Block Public Access settings"
            )

    except ClientError as error:

        code = error.response.get(
            "Error",
            {}
        ).get(
            "Code",
            ""
        )

        if code in {
            "NoSuchPublicAccessBlockConfiguration",
            "NoSuchPublicAccessBlock"
        }:

            add_finding(
                "S3",
                bucket_name,
                "S3 Block Public Access configuration is not enabled",
                "HIGH",
                "Enable all S3 Block Public Access settings"
            )

        elif code == "AccessDenied":

            print(
                "⚠ Block Public Access: Access denied while checking"
            )

        else:

            handle_error(
                f"S3 Public Access ({bucket_name})",
                error
            )

    except Exception as error:

        handle_error(
            f"S3 Public Access ({bucket_name})",
            error
        )


# ============================================================
# S3 - ACL
# ============================================================

def check_s3_acl(
    s3_client,
    bucket_name
):

    try:

        response = s3_client.get_bucket_acl(
            Bucket=bucket_name
        )

        public_acl = False
        authenticated_acl = False

        for grant in response.get(
            "Grants",
            []
        ):

            grantee = grant.get(
                "Grantee",
                {}
            )

            uri = grantee.get(
                "URI",
                ""
            )

            if "AllUsers" in uri:

                public_acl = True

            elif "AuthenticatedUsers" in uri:

                authenticated_acl = True

        if public_acl:

            add_finding(
                "S3",
                bucket_name,
                "S3 bucket ACL allows public access",
                "HIGH",
                "Remove public AllUsers permissions from the bucket ACL"
            )

        elif authenticated_acl:

            add_finding(
                "S3",
                bucket_name,
                "S3 bucket ACL grants access to all authenticated AWS users",
                "MEDIUM",
                "Remove unnecessary AuthenticatedUsers ACL permissions"
            )

        else:

            print(
                "✓ Bucket ACL: No broad public ACL found"
            )

    except Exception as error:

        handle_error(
            f"S3 ACL ({bucket_name})",
            error
        )


# ============================================================
# S3 - BUCKET POLICY
# ============================================================

def check_s3_policy(
    s3_client,
    bucket_name
):

    try:

        response = s3_client.get_bucket_policy(
            Bucket=bucket_name
        )

        policy_string = response.get(
            "Policy"
        )

        if not policy_string:

            print(
                "✓ Bucket Policy: No bucket policy configured"
            )

            return

        policy = json.loads(
            policy_string
        )

        statements = policy.get(
            "Statement",
            []
        )

        if isinstance(
            statements,
            dict
        ):

            statements = [
                statements
            ]

        public_policy = False

        for statement in statements:

            if statement.get(
                "Effect"
            ) != "Allow":

                continue

            principal = statement.get(
                "Principal"
            )

            # Principal = "*"
            if principal == "*":

                public_policy = True
                break

            # Principal = {"AWS": "*"}
            if isinstance(
                principal,
                dict
            ):

                aws_principal = principal.get(
                    "AWS"
                )

                if aws_principal == "*":

                    public_policy = True
                    break

                if (
                    isinstance(
                        aws_principal,
                        list
                    )
                    and "*" in aws_principal
                ):

                    public_policy = True
                    break

        if public_policy:

            add_finding(
                "S3",
                bucket_name,
                "S3 bucket policy allows public access",
                "HIGH",
                "Remove public Allow statements from the bucket policy"
            )

        else:

            print(
                "✓ Bucket Policy: No public Allow statement detected"
            )

    except ClientError as error:

        code = error.response.get(
            "Error",
            {}
        ).get(
            "Code",
            ""
        )

        if code == "NoSuchBucketPolicy":

            print(
                "✓ Bucket Policy: No bucket policy configured"
            )

        elif code == "AccessDenied":

            print(
                "⚠ Bucket Policy: Access denied while checking"
            )

        else:

            handle_error(
                f"S3 Policy ({bucket_name})",
                error
            )

    except json.JSONDecodeError:

        print(
            "⚠ Bucket Policy: Unable to parse policy document"
        )

    except Exception as error:

        handle_error(
            f"S3 Policy ({bucket_name})",
            error
        )


# ============================================================
# S3 - ENCRYPTION
# ============================================================

def check_s3_encryption(
    s3_client,
    bucket_name
):

    try:

        response = s3_client.get_bucket_encryption(
            Bucket=bucket_name
        )

        rules = response.get(
            "ServerSideEncryptionConfiguration",
            {}
        ).get(
            "Rules",
            []
        )

        if rules:

            print(
                "✓ Default Encryption: Enabled"
            )

        else:

            add_finding(
                "S3",
                bucket_name,
                "Default S3 bucket encryption is not configured",
                "MEDIUM",
                "Enable default server-side encryption for the bucket"
            )

    except ClientError as error:

        code = error.response.get(
            "Error",
            {}
        ).get(
            "Code",
            ""
        )

        if code == (
            "ServerSideEncryptionConfigurationNotFoundError"
        ):

            add_finding(
                "S3",
                bucket_name,
                "Default S3 bucket encryption is not configured",
                "MEDIUM",
                "Enable default server-side encryption for the bucket"
            )

        elif code == "AccessDenied":

            print(
                "⚠ Default Encryption: Access denied while checking"
            )

        else:

            handle_error(
                f"S3 Encryption ({bucket_name})",
                error
            )

    except Exception as error:

        handle_error(
            f"S3 Encryption ({bucket_name})",
            error
        )


# ============================================================
# S3 - VERSIONING
# ============================================================

def check_s3_versioning(
    s3_client,
    bucket_name
):

    try:

        response = s3_client.get_bucket_versioning(
            Bucket=bucket_name
        )

        status = response.get(
            "Status"
        )

        if status == "Enabled":

            print(
                "✓ Versioning: Enabled"
            )

        else:

            add_finding(
                "S3",
                bucket_name,
                "S3 bucket versioning is not enabled",
                "LOW",
                "Enable S3 versioning to protect against accidental deletion or overwrite"
            )

    except Exception as error:

        handle_error(
            f"S3 Versioning ({bucket_name})",
            error
        )


# ============================================================
# IAM SECURITY ASSESSMENT
# ============================================================

def scan_iam(
    iam_client,
    users
):

    print_section(
        "IAM SECURITY ASSESSMENT"
    )

    print(
        f"IAM Users Found: {len(users)}"
    )

    if not users:

        print(
            "No IAM users found."
        )

        return

    for user in users:

        username = user.get(
            "UserName",
            "Unknown"
        )

        print(
            f"\nUser: {username}"
        )

        check_iam_mfa(
            iam_client,
            username
        )

        check_iam_access_keys(
            iam_client,
            username
        )


# ============================================================
# IAM - MFA
# ============================================================

def check_iam_mfa(
    iam_client,
    username
):

    try:

        mfa_devices = get_paginated_items(
            iam_client,
            "list_mfa_devices",
            "MFADevices",
            UserName=username
        )

        if mfa_devices:

            print(
                "✓ MFA: Enabled"
            )

        else:

            add_finding(
                "IAM",
                username,
                "MFA is not enabled for the IAM user",
                "HIGH",
                "Enable MFA for the IAM user"
            )

    except Exception as error:

        handle_error(
            f"IAM MFA ({username})",
            error
        )


# ============================================================
# IAM - ACCESS KEYS
# ============================================================

def check_iam_access_keys(
    iam_client,
    username
):

    try:

        keys = get_paginated_items(
            iam_client,
            "list_access_keys",
            "AccessKeyMetadata",
            UserName=username
        )

        if not keys:

            print(
                "✓ Access Keys: None"
            )

            return

        # An access key existing is NOT automatically a finding.
        print(
            f"✓ Access Keys: {len(keys)}"
        )

        now = datetime.now(
            timezone.utc
        )

        for key in keys:

            key_id = key.get(
                "AccessKeyId",
                ""
            )

            status = key.get(
                "Status",
                "Unknown"
            )

            created = key.get(
                "CreateDate"
            )

            print(
                f"   Key: {mask_access_key(key_id)}"
                f" | Status: {status}"
            )

            # Only active keys are checked for age.
            if status != "Active":
                continue

            if not created:
                continue

            age_days = (
                now - created
            ).days

            if age_days > ACCESS_KEY_MAX_AGE_DAYS:

                add_finding(
                    "IAM",
                    username,
                    f"Active access key is older than "
                    f"{ACCESS_KEY_MAX_AGE_DAYS} days "
                    f"({age_days} days old)",
                    "MEDIUM",
                    "Rotate old access keys and remove unused credentials"
                )

    except Exception as error:

        handle_error(
            f"IAM Access Keys ({username})",
            error
        )


# ============================================================
# EC2 & SECURITY GROUP ASSESSMENT
# ============================================================

def scan_ec2(
    ec2_client,
    instances,
    security_groups
):

    print_section(
        "EC2 & SECURITY GROUP ASSESSMENT"
    )

    print(
        f"EC2 Instances Found: {len(instances)}"
    )

    if instances:

        for instance in instances:

            instance_id = instance.get(
                "InstanceId",
                "Unknown"
            )

            state = instance.get(
                "State",
                {}
            ).get(
                "Name",
                "Unknown"
            )

            public_ip = instance.get(
                "PublicIpAddress"
            )

            print(
                f"Instance: {instance_id}"
                f" | State: {state}"
            )

            if public_ip:

                print(
                    f"   Public IP: {public_ip}"
                )

    else:

        print(
            "No EC2 instances found."
        )

    print(
        f"\nSecurity Groups Found: "
        f"{len(security_groups)}"
    )

    if not security_groups:

        print(
            "No security groups found."
        )

        return

    for security_group in security_groups:

        group_id = security_group.get(
            "GroupId",
            "Unknown"
        )

        group_name = security_group.get(
            "GroupName",
            "Unknown"
        )

        print(
            f"\nSecurity Group: {group_name}"
        )

        print(
            f"Group ID: {group_id}"
        )

        permissions = security_group.get(
            "IpPermissions",
            []
        )

        for permission in permissions:

            protocol = permission.get(
                "IpProtocol",
                ""
            )

            from_port = permission.get(
                "FromPort"
            )

            to_port = permission.get(
                "ToPort"
            )

            # ------------------------------------------------
            # IPv4
            # ------------------------------------------------

            for ip_range in permission.get(
                "IpRanges",
                []
            ):

                cidr = ip_range.get(
                    "CidrIp",
                    ""
                )

                if cidr != "0.0.0.0/0":
                    continue

                evaluate_security_group_rule(
                    group_id,
                    protocol,
                    from_port,
                    to_port,
                    "IPv4",
                    cidr
                )

            # ------------------------------------------------
            # IPv6
            # ------------------------------------------------

            for ipv6_range in permission.get(
                "Ipv6Ranges",
                []
            ):

                cidr = ipv6_range.get(
                    "CidrIpv6",
                    ""
                )

                if cidr != "::/0":
                    continue

                evaluate_security_group_rule(
                    group_id,
                    protocol,
                    from_port,
                    to_port,
                    "IPv6",
                    cidr
                )


# ============================================================
# SECURITY GROUP RULE EVALUATION
# ============================================================

def evaluate_security_group_rule(
    group_id,
    protocol,
    from_port,
    to_port,
    ip_version,
    cidr
):

    # --------------------------------------------------------
    # ALL TRAFFIC
    # --------------------------------------------------------

    if protocol == "-1":

        add_finding(
            "Security Group",
            group_id,
            f"Unrestricted {ip_version} inbound access "
            f"allows all traffic from {cidr}",
            "CRITICAL",
            "Restrict inbound traffic to trusted IP addresses "
            "and required ports"
        )

        return

    # --------------------------------------------------------
    # SSH
    # --------------------------------------------------------

    is_ssh = False
    if from_port is not None and to_port is not None:
        is_ssh = (from_port <= 22 <= to_port)
    elif from_port == 22 or to_port == 22:
        is_ssh = True

    if is_ssh:

        add_finding(
            "Security Group",
            group_id,
            f"SSH port 22 is exposed to {cidr}",
            "HIGH",
            "Restrict SSH access to trusted IP addresses "
            "or VPN ranges"
        )

        return

    # --------------------------------------------------------
    # RDP
    # --------------------------------------------------------

    is_rdp = False
    if from_port is not None and to_port is not None:
        is_rdp = (from_port <= 3389 <= to_port)
    elif from_port == 3389 or to_port == 3389:
        is_rdp = True

    if is_rdp:

        add_finding(
            "Security Group",
            group_id,
            f"RDP port 3389 is exposed to {cidr}",
            "HIGH",
            "Restrict RDP access to trusted IP addresses "
            "or VPN ranges"
        )

        return

    # --------------------------------------------------------
    # OTHER PORTS
    # --------------------------------------------------------

    if from_port is None or to_port is None:

        port_description = "unknown port"

    elif from_port == to_port:

        port_description = str(from_port)

    else:

        port_description = (
            f"{from_port}-{to_port}"
        )

    add_finding(
        "Security Group",
        group_id,
        f"Inbound port {port_description} "
        f"is exposed to {cidr}",
        "MEDIUM",
        "Restrict public inbound access to only required "
        "ports and trusted IP addresses"
    )


# ============================================================
# CLOUDTRAIL SECURITY ASSESSMENT
# ============================================================

def scan_cloudtrail(
    cloudtrail_client
):

    print_section(
        "CLOUDTRAIL SECURITY ASSESSMENT"
    )

    try:

        response = cloudtrail_client.describe_trails(
            includeShadowTrails=False
        )

        trails = response.get(
            "trailList",
            []
        )

        if not trails:

            add_finding(
                "CloudTrail",
                "AWS Account",
                "CloudTrail trail is not configured",
                "HIGH",
                "Create and enable a CloudTrail trail "
                "for AWS activity logging"
            )

            return

        print(
            f"CloudTrail Trails Found: {len(trails)}"
        )

        for trail in trails:

            trail_name = trail.get(
                "Name",
                "Unknown"
            )

            print(
                f"\nTrail: {trail_name}"
            )

            # ------------------------------------------------
            # MULTI-REGION
            # ------------------------------------------------

            if trail.get(
                "IsMultiRegionTrail",
                False
            ):

                print(
                    "✓ Multi-region: Enabled"
                )

            else:

                add_finding(
                    "CloudTrail",
                    trail_name,
                    "CloudTrail trail is not configured "
                    "as multi-region",
                    "MEDIUM",
                    "Configure the CloudTrail trail "
                    "as a multi-region trail"
                )

            # ------------------------------------------------
            # LOGGING
            # ------------------------------------------------

            try:

                status = (
                    cloudtrail_client
                    .get_trail_status(
                        Name=trail_name
                    )
                )

                if status.get(
                    "IsLogging",
                    False
                ):

                    print(
                        "✓ Logging: Enabled"
                    )

                else:

                    add_finding(
                        "CloudTrail",
                        trail_name,
                        "CloudTrail trail is configured "
                        "but logging is disabled",
                        "HIGH",
                        "Start CloudTrail logging for "
                        "continuous AWS activity monitoring"
                    )

            except Exception as error:

                handle_error(
                    f"CloudTrail status ({trail_name})",
                    error
                )

    except Exception as error:

        handle_error(
            "CloudTrail",
            error
        )


# ============================================================
# RESOURCE DISCOVERY
# ============================================================

def discover_resources(
    session
):

    print_section(
        "RESOURCE DISCOVERY"
    )

    resources = {
        "buckets": [],
        "users": [],
        "instances": [],
        "security_groups": []
    }

    # ========================================================
    # S3
    # ========================================================

    try:

        s3_client = session.client(
            "s3"
        )

        response = s3_client.list_buckets()

        resources["buckets"] = response.get(
            "Buckets",
            []
        )

    except Exception as error:

        handle_error(
            "S3 resource discovery",
            error
        )

    # ========================================================
    # IAM
    # ========================================================

    try:

        iam_client = session.client(
            "iam"
        )

        resources["users"] = get_paginated_items(
            iam_client,
            "list_users",
            "Users"
        )

    except Exception as error:

        handle_error(
            "IAM resource discovery",
            error
        )

    # ========================================================
    # EC2
    # ========================================================

    try:

        ec2_client = session.client(
            "ec2"
        )

        reservations = get_paginated_items(
            ec2_client,
            "describe_instances",
            "Reservations"
        )

        for reservation in reservations:

            resources["instances"].extend(
                reservation.get(
                    "Instances",
                    []
                )
            )

        resources["security_groups"] = (
            get_paginated_items(
                ec2_client,
                "describe_security_groups",
                "SecurityGroups"
            )
        )

    except Exception as error:

        handle_error(
            "EC2 resource discovery",
            error
        )

    # ========================================================
    # DISPLAY DISCOVERY
    # ========================================================

    print(
        f"✓ S3 Buckets: "
        f"{len(resources['buckets'])}"
    )

    print(
        f"✓ IAM Users: "
        f"{len(resources['users'])}"
    )

    print(
        f"✓ EC2 Instances: "
        f"{len(resources['instances'])}"
    )

    print(
        f"✓ Security Groups: "
        f"{len(resources['security_groups'])}"
    )

    print(
        "\n✓ Resources discovered"
    )

    return resources


# ============================================================
# RUN SECURITY ASSESSMENT
# ============================================================

def run_security_assessment(
    session,
    resources
):

    print_section(
        "SECURITY ASSESSMENT"
    )

    print(
        "Starting security assessment...\n"
    )

    s3_client = session.client(
        "s3"
    )

    iam_client = session.client(
        "iam"
    )

    ec2_client = session.client(
        "ec2"
    )

    cloudtrail_client = session.client(
        "cloudtrail"
    )

    # S3
    scan_s3(
        session,
        s3_client,
        resources["buckets"]
    )

    # IAM
    scan_iam(
        iam_client,
        resources["users"]
    )

    # EC2 / Security Groups
    scan_ec2(
        ec2_client,
        resources["instances"],
        resources["security_groups"]
    )

    # CloudTrail
    scan_cloudtrail(
        cloudtrail_client
    )


# ============================================================
# RISK CALCULATION
# ============================================================

def calculate_risk():

    critical = sum(
        1
        for finding in findings
        if finding["severity"] == "CRITICAL"
    )

    high = sum(
        1
        for finding in findings
        if finding["severity"] == "HIGH"
    )

    medium = sum(
        1
        for finding in findings
        if finding["severity"] == "MEDIUM"
    )

    low = sum(
        1
        for finding in findings
        if finding["severity"] == "LOW"
    )

    total_risk = sum(
        finding["risk"]
        for finding in findings
    )

    security_score = max(
        0,
        100 - total_risk
    )

    return (
        critical,
        high,
        medium,
        low,
        total_risk,
        security_score
    )


def get_score_status(
    score
):

    if score >= 90:
        return "GOOD"

    elif score >= 70:
        return "MODERATE"

    elif score >= 40:
        return "NEEDS ATTENTION"

    else:
        return "HIGH RISK"


# ============================================================
# DISPLAY RESULTS
# ============================================================

def display_results():

    (
        critical,
        high,
        medium,
        low,
        total_risk,
        security_score
    ) = calculate_risk()

    print("\n")
    print("=" * 50)
    print("             SECURITY ASSESSMENT")
    print("=" * 50)

    print("\nFindings Summary")
    print("-" * 50)

    print(
        f"CRITICAL : {critical}"
    )

    print(
        f"HIGH     : {high}"
    )

    print(
        f"MEDIUM   : {medium}"
    )

    print(
        f"LOW      : {low}"
    )

    print(
        f"\nTotal Findings : {len(findings)}"
    )

    print(
        f"Total Risk     : {total_risk}"
    )

    print(
        f"Security Score : {security_score}/100"
    )

    print(
        f"Assessment     : "
        f"{get_score_status(security_score)}"
    )

    # ========================================================
    # SECURITY FINDINGS
    # ========================================================

    if findings:

        print("\n")
        print("=" * 50)
        print("              SECURITY FINDINGS")
        print("=" * 50)

        for index, finding in enumerate(
            findings,
            start=1
        ):

            print("\n" + "-" * 50)

            print(
                f"Finding #{index}"
            )

            print(
                f"Service        : "
                f"{finding['service']}"
            )

            print(
                f"Resource       : "
                f"{finding['resource']}"
            )

            print(
                f"Issue          : "
                f"{finding['issue']}"
            )

            print(
                f"Severity       : "
                f"{finding['severity']}"
            )

            print(
                f"Risk           : "
                f"{finding['risk']}"
            )

            print(
                f"Recommendation: "
                f"{finding['recommendation']}"
            )

    else:

        print("\n")
        print("=" * 50)
        print("          NO SECURITY FINDINGS")
        print("=" * 50)

        print(
            "\n✓ No configured security issues were detected."
        )

    # ========================================================
    # SCAN COMPLETE
    # ========================================================

    print("\n")
    print("=" * 50)
    print("               SCAN COMPLETE")
    print("=" * 50)

    print(
        "\n✓ Assessment completed using "
        "read-only AWS APIs."
    )


# ============================================================
# EXPORT HELPERS
# ============================================================

def export_to_json(scan_results, filepath="report.json"):
    """
    Save scan assessment results to a JSON file.
    """
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(scan_results, f, indent=2, default=str)
    return filepath


def export_to_csv(findings_list, filepath="report.csv"):
    """
    Save findings list to a CSV file.
    """
    fieldnames = ["service", "resource", "severity", "risk", "issue", "recommendation"]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in findings_list:
            writer.writerow({
                "service": item.get("service", ""),
                "resource": item.get("resource", ""),
                "severity": item.get("severity", ""),
                "risk": item.get("risk", 0),
                "issue": item.get("issue", ""),
                "recommendation": item.get("recommendation", "")
            })
    return filepath


def run_scan(region="ap-south-1", session=None):
    """
    Execute full security assessment and return a structured dictionary.
    Used by CLI and Web UI interfaces.
    """
    findings.clear()

    if session is None:
        session = boto3.Session(region_name=region)

    credentials = session.get_credentials()
    if credentials is None:
        raise RuntimeError("AWS credentials were not detected. Please configure using 'aws configure'.")

    sts_client = session.client("sts")
    identity = sts_client.get_caller_identity()
    account_id = identity.get("Account", "Unknown")

    resources = discover_resources(session)
    run_security_assessment(session, resources)

    critical, high, medium, low, total_risk, security_score = calculate_risk()

    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "account_id": account_id,
        "region": region,
        "security_score": security_score,
        "assessment_status": get_score_status(security_score),
        "total_risk": total_risk,
        "summary": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "total": len(findings)
        },
        "resource_counts": {
            "buckets": len(resources["buckets"]),
            "users": len(resources["users"]),
            "instances": len(resources["instances"]),
            "security_groups": len(resources["security_groups"])
        },
        "findings": list(findings)
    }

    return results


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    findings.clear()

    print_header()

    # ========================================================
    # REGION
    # ========================================================

    region = input(
        "\nEnter AWS Region:\n> "
    ).strip()

    if not region:

        print(
            "\n⚠ AWS Region cannot be empty."
        )

        return

    try:

        # ====================================================
        # CREATE AWS SESSION
        # ====================================================

        session = boto3.Session(
            region_name=region
        )

        credentials = session.get_credentials()

        if credentials is None:

            print(
                "\n✗ AWS credentials were not detected."
            )

            print(
                "\nConfigure AWS credentials using:"
            )

            print(
                "aws configure"
            )

            return

        print(
            "\n✓ Credentials detected"
        )

        # ====================================================
        # AUTHENTICATE
        # ====================================================

        sts_client = session.client(
            "sts"
        )

        identity = sts_client.get_caller_identity()

        account_id = identity.get(
            "Account",
            "Unknown"
        )

        print(
            "✓ Connected to AWS"
        )

        print(
            "✓ Account identified"
        )

        print(
            f"  Account ID: {account_id}"
        )

        # ====================================================
        # RESOURCE DISCOVERY
        # ====================================================

        resources = discover_resources(
            session
        )

        # ====================================================
        # SECURITY ASSESSMENT
        # ====================================================

        run_security_assessment(
            session,
            resources
        )

        # ====================================================
        # DISPLAY RESULTS
        # ====================================================

        display_results()

        # ====================================================
        # EXPORT REPORTS
        # ====================================================

        critical, high, medium, low, total_risk, security_score = calculate_risk()
        results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "account_id": account_id,
            "region": region,
            "security_score": security_score,
            "assessment_status": get_score_status(security_score),
            "total_risk": total_risk,
            "summary": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "total": len(findings)
            },
            "resource_counts": {
                "buckets": len(resources["buckets"]),
                "users": len(resources["users"]),
                "instances": len(resources["instances"]),
                "security_groups": len(resources["security_groups"])
            },
            "findings": list(findings)
        }

        export_to_json(results, "report.json")
        export_to_csv(findings, "report.csv")

        print("\n✓ Reports generated:")
        print("  • report.json")
        print("  • report.csv")

    except ClientError as error:

        handle_error(
            "AWS",
            error
        )

    except BotoCoreError as error:

        handle_error(
            "AWS",
            error
        )

    except KeyboardInterrupt:

        print(
            "\n\n⚠ Scan cancelled by user."
        )

    except Exception as error:

        print(
            f"\n✗ Unexpected error: {error}"
        )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()