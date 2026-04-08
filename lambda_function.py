import boto3
import os
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def get_next_rule_number(ec2, nacl_id, egress):
    """
    Dynamically find the lowest available rule number (in steps of 10)
    for the given NACL and traffic direction, below the AWS default rule (32767).
    """
    response = ec2.describe_network_acls(NetworkAclIds=[nacl_id])
    entries = response['NetworkAcls'][0]['Entries']
    used_numbers = {
        e['RuleNumber']
        for e in entries
        if e['Egress'] == egress and e['RuleNumber'] < 32767
    }
    candidate = 10
    while candidate in used_numbers:
        candidate += 10
    return candidate, entries


def is_ip_already_blocked(entries, attacker_cidr, egress):
    """
    Check whether a deny rule for this exact CIDR already exists
    in the given direction, making this invocation idempotent.
    """
    return any(
        e.get('CidrBlock') == attacker_cidr
        and e.get('RuleAction') == 'deny'
        and e['Egress'] == egress
        for e in entries
    )


def check_rule_limit(entries, egress, max_deny_rules=15):
    """
    Warn if we are approaching the AWS NACL rule limit (default 20 per direction).
    Returns True if there is still room to add a rule.
    """
    deny_count = sum(
        1 for e in entries
        if e.get('RuleAction') == 'deny'
        and e['Egress'] == egress
        and e['RuleNumber'] < 32767
    )
    logger.info(f"Current deny rule count ({'outbound' if egress else 'inbound'}): {deny_count}")
    if deny_count >= max_deny_rules:
        logger.warning(
            f"NACL deny rule limit reached ({'outbound' if egress else 'inbound'}). "
            "Manual cleanup or quota increase required."
        )
        return False
    return True


def notify_sns(attacker_ip, nacl_id, context, status):
    """
    Publish a notification to SNS so the security team is aware of the block.
    Requires the ALERT_TOPIC_ARN environment variable to be set.
    Fails gracefully if not configured.
    """
    topic_arn = os.environ.get('ALERT_TOPIC_ARN')
    if not topic_arn:
        logger.info("ALERT_TOPIC_ARN not set — skipping SNS notification.")
        return
    try:
        sns = boto3.client('sns')
        sns.publish(
            TopicArn=topic_arn,
            Subject=f"GuardDuty Auto-Block [{status.upper()}]",
            Message=(
                f"Status     : {status}\n"
                f"Blocked IP : {attacker_ip}\n"
                f"NACL ID    : {nacl_id}\n"
                f"Function   : {context.invoked_function_arn}\n"
                f"Request ID : {context.aws_request_id}"
            )
        )
        logger.info("SNS notification sent successfully.")
    except Exception as e:
        logger.warning(f"SNS notification failed (non-fatal): {e}")


def lambda_handler(event, context):
    logger.info(f"Received event from EventBridge: {json.dumps(event)}")

    # -------------------------------------------------------------------------
    # 1. Extract the attacker's IP from the GuardDuty finding
    #    Handles both IPv4 and IPv6 findings.
    # -------------------------------------------------------------------------
    try:
        remote_ip_details = (
            event['detail']['service']['action']
            ['networkConnectionAction']['remoteIpDetails']
        )
        # Prefer IPv4; fall back to IPv6
        attacker_ip = remote_ip_details.get('ipAddressV4') or remote_ip_details.get('ipAddressV6')
        if not attacker_ip:
            raise ValueError("Neither ipAddressV4 nor ipAddressV6 found in remoteIpDetails.")
        logger.info(f"Target locked. Malicious IP identified: {attacker_ip}")
    except (KeyError, ValueError) as e:
        logger.error(f"Could not extract IP from event payload: {e}")
        return {"status": "error", "message": "Failed to parse attacker IP."}

    attacker_cidr = f"{attacker_ip}/32" if ':' not in attacker_ip else f"{attacker_ip}/128"

    # -------------------------------------------------------------------------
    # 2. Validate environment configuration
    # -------------------------------------------------------------------------
    ec2 = boto3.client('ec2')
    nacl_id = os.environ.get('TARGET_NACL_ID')
    if not nacl_id:
        logger.error("TARGET_NACL_ID environment variable is missing!")
        return {"status": "error", "message": "Configuration error: TARGET_NACL_ID not set."}

    # -------------------------------------------------------------------------
    # 3. Block inbound traffic
    # -------------------------------------------------------------------------
    inbound_blocked = False
    try:
        inbound_rule_number, inbound_entries = get_next_rule_number(ec2, nacl_id, egress=False)

        if is_ip_already_blocked(inbound_entries, attacker_cidr, egress=False):
            logger.info(f"Inbound rule for {attacker_cidr} already exists. Skipping.")
            inbound_blocked = True  # Treat as success — the desired state is already achieved
        elif not check_rule_limit(inbound_entries, egress=False):
            logger.error("Cannot add inbound deny rule: rule limit reached.")
            notify_sns(attacker_ip, nacl_id, context, status="error-limit-inbound")
            return {"status": "error", "message": "NACL inbound rule limit reached."}
        else:
            ec2.create_network_acl_entry(
                NetworkAclId=nacl_id,
                RuleNumber=inbound_rule_number,
                Protocol='-1',       # All protocols (TCP, UDP, ICMP, etc.)
                RuleAction='deny',
                Egress=False,        # Inbound
                CidrBlock=attacker_cidr
            )
            inbound_blocked = True
            logger.info(
                f"SUCCESS: Inbound traffic from {attacker_cidr} blocked "
                f"on NACL {nacl_id} at rule #{inbound_rule_number}."
            )
    except Exception as e:
        logger.error(f"Failed to create inbound NACL rule: {e}")
        notify_sns(attacker_ip, nacl_id, context, status="error-inbound")
        return {"status": "error", "inbound_blocked": False, "message": str(e)}

    # -------------------------------------------------------------------------
    # 4. Block outbound traffic
    #    Re-fetch entries so the outbound query reflects the current NACL state.
    # -------------------------------------------------------------------------
    outbound_blocked = False
    try:
        outbound_rule_number, outbound_entries = get_next_rule_number(ec2, nacl_id, egress=True)

        if is_ip_already_blocked(outbound_entries, attacker_cidr, egress=True):
            logger.info(f"Outbound rule for {attacker_cidr} already exists. Skipping.")
            outbound_blocked = True
        elif not check_rule_limit(outbound_entries, egress=True):
            logger.error("Cannot add outbound deny rule: rule limit reached.")
            notify_sns(attacker_ip, nacl_id, context, status="partial-limit-outbound")
            return {
                "status": "partial",
                "inbound_blocked": inbound_blocked,
                "outbound_blocked": False,
                "message": "NACL outbound rule limit reached.",
                "blocked_ip": attacker_ip
            }
        else:
            ec2.create_network_acl_entry(
                NetworkAclId=nacl_id,
                RuleNumber=outbound_rule_number,
                Protocol='-1',
                RuleAction='deny',
                Egress=True,         # Outbound
                CidrBlock=attacker_cidr
            )
            outbound_blocked = True
            logger.info(
                f"SUCCESS: Outbound traffic to {attacker_cidr} blocked "
                f"on NACL {nacl_id} at rule #{outbound_rule_number}."
            )
    except Exception as e:
        logger.error(f"Failed to create outbound NACL rule: {e}")
        notify_sns(attacker_ip, nacl_id, context, status="partial-error-outbound")
        return {
            "status": "partial",
            "inbound_blocked": inbound_blocked,
            "outbound_blocked": False,
            "message": str(e),
            "blocked_ip": attacker_ip
        }

    # -------------------------------------------------------------------------
    # 5. All done — notify and return
    # -------------------------------------------------------------------------
    notify_sns(attacker_ip, nacl_id, context, status="success")
    return {
        "status": "success",
        "blocked_ip": attacker_ip,
        "inbound_blocked": inbound_blocked,
        "outbound_blocked": outbound_blocked
    }