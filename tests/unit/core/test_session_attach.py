import unittest

from src.core.models import Request
from src.core.session import Session


class SessionAttachTests(unittest.TestCase):
    def test_attach_respects_case_insensitive_auth_header(self) -> None:
        session = Session(auth_token="session-token")
        request = Request(
            method="GET",
            url="https://example.com",
            headers={"authorization": "Bearer request-token"},
        )

        attached = session.attach(request)

        self.assertEqual(attached.headers["authorization"], "Bearer request-token")
        self.assertNotIn("Authorization", attached.headers)

    def test_attach_merges_cookie_keys_without_duplicates(self) -> None:
        session = Session(cookies={"sessionid": "abc", "lang": "en"})
        request = Request(
            method="GET", url="https://example.com", headers={"Cookie": "sessionid=req; theme=dark"}
        )

        attached = session.attach(request)

        self.assertEqual(attached.headers["Cookie"], "lang=en; sessionid=req; theme=dark")


if __name__ == "__main__":
    unittest.main()
