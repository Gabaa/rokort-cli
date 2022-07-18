import base64
import getpass
import json
import os
from pathlib import Path

import fire
import requests

import rokortapi


# https://rowlog.com/docs
# https://rowlog.com/docs/authentication
# CLUB_ID = 58

AUTH_PATH = Path("auth.ini")


def require_login(f, *args, **kwargs):
    """Decorator that ensures that the user is logged in."""
    if AUTH_PATH.exists():
        return f(*args, **kwargs)
    else:
        return "Not logged in."


class RokortEntrypoint:
    def __init__(self):
        self._auth_token = None
        self._club_id = None

        if not AUTH_PATH.exists():
            return

        with open(AUTH_PATH, "r") as f:
            lines = f.readlines()

        for line in lines:
            parts = [x.strip() for x in line.split("=")]
            if parts[0] == "auth_token":
                self._auth_token = parts[1]
            if parts[0] == "club_id":
                self._club_id = parts[1]

    def test(self):
        response = requests.get("https://rokort.dk/api")
        print(response.content)

    def login(self, username: str = None, password: str = None, club_id: int = None):
        if AUTH_PATH.exists():
            return "Already logged in."

        if username is None:
            username = input("Username: ")
        if password is None:
            password = getpass.getpass("Password: ")
        if club_id is None:
            club_id = int(input("Club ID: "))

        auth = f"{username}:{password}"
        auth_bytes = auth.encode("ascii")
        b64_bytes = base64.b64encode(auth_bytes)
        token = b64_bytes.decode("ascii")

        with open(AUTH_PATH, "w") as f:
            print(f"auth_token = {token}", file=f)
            print(f"club_id = {club_id}", file=f)

    def logout(self):
        if not AUTH_PATH.exists():
            return "Not logged in."

        resp = input("Are you sure? [y/N] ")

        if len(resp) == 0 or resp.lower() == "n":
            pass
        elif resp.lower() == "y":
            os.remove(AUTH_PATH)
            return "Logged out successfully."
        else:
            return "Could not recognize response."

    def clubs(self):
        pass

    def me(self):
        club = rokortapi.Club(self._auth_token, self._club_id)
        return club.me()

    def members(self):
        response = get(rokortapi.BASE_URL + "/members", self._auth_token, self._club_id)
        if response is None:
            print("GET members failed")
        return response.json()

    def _secret(self):
        print("secret")


if __name__ == "__main__":
    fire.Fire(RokortEntrypoint)
