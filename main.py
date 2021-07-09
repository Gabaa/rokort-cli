import base64
import getpass
import json
import sys

import requests

requests.packages.urllib3.disable_warnings()

# https://rowlog.com/docs
# https://rowlog.com/docs/authentication

BASE_URL = 'https://rokort.dk/api'
CLUB_ID = 58


def get_auth_string():
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


def get(url: str, auth_string: str, club_id: int):
    headers = {
        'Authorization': 'Basic ' + auth_string,
        'X-ClubId': str(club_id)
    }

    try:
        x = requests.get(
            url,
            headers=headers,
            verify=False,
        )
        return x
    except requests.exceptions.SSLError as e:
        print(e)


def get_members(auth_string: str):
    response = get(BASE_URL + '/members', auth_string, CLUB_ID)
    if response is None:
        print('GET members failed')
    return response.json()


def get_me(auth_string: str):
    response = get(BASE_URL + "/members/me", auth_string, CLUB_ID)
    if response is None:
        print('GET me failed')
    return response.json()


def main():
    auth_string = get_auth_string()
    me = get_me(auth_string)
    print(json.dumps(me, indent=4))


if __name__ == "__main__":
    main()
