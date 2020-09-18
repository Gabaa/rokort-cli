import base64
import getpass
import sys

import requests

requests.packages.urllib3.disable_warnings()

# https://rowlog.com/docs
# https://rowlog.com/docs/authentication

BASE_URL = 'https://rokort.dk/api'
CLUB_ID = 58


def get_b64_auth_string():
    # Get from args if possible, otherwise prompt user
    if len(sys.argv) > 2:
        username = sys.argv[1]
        password = sys.argv[2]
    elif len(sys.argv) > 1:
        username = sys.argv[1]
        password = getpass.getpass("Password: ")
    else:
        username = input("Username: ")
        password = getpass.getpass("Password: ")

    auth = f'{username}:{password}'
    auth_bytes = auth.encode('ascii')
    b64_bytes = base64.b64encode(auth_bytes)
    return b64_bytes.decode('ascii')


def get_members(club_id: int):
    # Get username and password
    b64 = get_b64_auth_string()

    url = BASE_URL + '/members'
    headers = {
        'Authorization': 'Basic ' + b64,
        'X-ClubId': str(club_id)
    }

    try:
        x = requests.get(
            url,
            headers=headers,
            verify=False
        )
        return x.json()
    except requests.exceptions.SSLError as e:
        print(e)


def get_clubs():
    # Get username and password
    b64 = get_b64_auth_string()

    url = BASE_URL + '/clubs'
    headers = {
        'Authorization': 'Basic ' + b64,
        # 'Content-Type': 'application/json; charset=utf8',
        # 'X-ClubId': '103',
    }

    try:
        x = requests.get(
            url,
            headers=headers,
            verify=False
        )
        print('Successful GET request')
        print(x.json())
    except requests.exceptions.SSLError as e:
        print(e)


def main():
    print(get_members(CLUB_ID))


if __name__ == "__main__":
    main()
