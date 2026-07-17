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

        scan_policy = iam.list_attached_user_policies(
            UserName=iam_user["UserName"]
        )

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