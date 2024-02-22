"""
A mitmproxy script that blocks and removes well known Matrix server
information.

There are two ways a Matrix server can trigger the client to reconfigure the
homeserver URL:

    1. By responding to a `./well-known/matrix/client` request with a new
    homeserver URL.

    2. By including a new homeserver URL inside the `/login` response.

To run execute it with mitmproxy:

    >>> mitmproxy -s well-known-block.py`

"""
import json

from mitmproxy import http


def request(flow):
    if flow.request.path == "/.well-known/matrix/client":
        headers = http.Headers()
        headers.add("Content-Type", "application/json")

        flow.response = http.Response.make(
            status_code=200,  # (optional) status code
            content=json.dumps(
                {
                    "m.homeserver": {"base_url": "https://localhost:8010/"},
                    "org.matrix.msc2965.authentication": {
                        "issuer": "https://localhost:8010",
                        "account": "https://localhost:8010/account",
                    },
                    "org.matrix.msc3575.proxy": {"url": "https://localhost:8010"},
                }
            ),
            headers=headers,
        )


# def request(flow):
#     if flow.request.path == "/.well-known/matrix/client":
#         headers = http.Headers()
#         headers.add("Content-Type", "application/json")
#
#         flow.response = http.HTTPResponse.make(
#             status_code=404,  # (optional) status code
#             content=b"Not found",  # (optional) content
#             headers=headers,
#         )


def response(flow: http.HTTPFlow):
    if flow.request.path == "/_matrix/client/r0/login":
        if flow.response.status_code == 200:
            body = json.loads(flow.response.content)
            body.pop("well_known", None)
            flow.response.text = json.dumps(body)
