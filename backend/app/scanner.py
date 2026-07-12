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