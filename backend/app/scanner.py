from app.aws import get_iam_client

def list_iam_users():
    iam = get_iam_client()

    response = iam.list_users()

    users = []

    for user in response["Users"]:
        users.append({
            "username": user["UserName"],
            "created": str(user["CreateDate"])
        })

    return users

def scan_mfa():
    iam = get_iam_client()

    response = iam.list_users()

    findings=[]
    for user in response["Users"]:

        mfa = iam.list_mfa_devices(UserName = user["UserName"])

        if mfa["MFADevices"]:
            findings.append({
            "username": user["UserName"] ,
            "mfa_enabled": True,
            "risk": "LOW",
            "recommendation": "No action required."
            })
        else:
            findings.append({
            "username": user["UserName"],
            "mfa_enabled": False,
            "risk": "HIGH",
            "finding": "MFA is disabled.",
            "recommendation": "Enable Multi-Factor Authentication (MFA)."
            })
            
    return findings

def scan_admin_access():
    iam = get_iam_client()

    response = iam.list_users()

    users = []
    for iam_user in response["Users"]:
        admin_found = False

        scan_policy = iam.list_attached_user_policies(UserName=iam_user["UserName"])

        for policy in scan_policy["AttachedPolicies"]:
            if policy["PolicyName"] == "AdministratorAccess":
                admin_found = True
                break  

        if admin_found:
            users.append({
                "username": iam_user["UserName"],
                "risk": "CRITICAL",
                "finding": "AdministratorAccess attached",
                "recommendation": "Remove AdministratorAccess unless absolutely required."
            })
        else:
            users.append({
                "username": iam_user["UserName"],
                "risk": "LOW",
                "finding": "AdministratorAccess not attached",
                "recommendation": "No action required."
            })

    return users

from datetime import datetime, timezone


def scan_inactive_access_keys():
    iam = get_iam_client()
    response = iam.list_users()

    findings = []
    now = datetime.now(timezone.utc)

    for iam_user in response["Users"]:
        access_keys = iam.list_access_keys(UserName=iam_user["UserName"])

        for key in access_keys["AccessKeyMetadata"]:
                if key["Status"] != "Active":
                    continue
                last_used = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                access_key_info = last_used.get("AccessKeyLastUsed")
                last_used_date = access_key_info.get("LastUsedDate") if access_key_info else None
                masked_key = f"****{key['AccessKeyId'][-4:]}"
                if last_used_date is None:
                    findings.append({
                        "username": iam_user["UserName"],
                        "access_key_id": masked_key,
                        "risk": "HIGH",
                        "finding": "Access key has never been used.",
                        "recommendation": "Delete unused access keys to reduce attack surface."
                    })
                    continue

                days_since_last_used = (now - last_used_date).days

                if days_since_last_used > 90:
                    findings.append({
                        "username": iam_user["UserName"],
                        "access_key_id": masked_key,
                        "risk": "HIGH",
                        "finding": f"Access key has not been used for {days_since_last_used} days.",
                        "recommendation": "Rotate or delete access keys that have not been used for over 90 days."
                    })

    return findings
