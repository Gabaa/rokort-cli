import typing

import requests

BASE_URL = "https://rokort.dk/api"


class User:
    pass

    @classmethod
    def from_json(cls, json: dict):
        print(type(json))
        pass


class Club:
    def __init__(self, auth_token: str, club_id: int):
        self.auth_token = auth_token
        self.club_id = club_id

    def get(self, url: str) -> requests.Response:
        headers = {
            "Authorization": f"Basic {self.auth_token}",
            "X-ClubId": str(self.club_id),
        }

        if not url.startswith("/"):
            url = f"/{url}"

        return requests.get(BASE_URL + url, headers=headers)

    def post(self, url: str) -> typing.Any:
        return None

    def me(self) -> User:
        response = self.get("/api/members/me")
        if response is None:
            print("Get request failed: /api/members/me")
        print(response.content)
        return User.from_json(response.json())

    def members(self):
        pass
