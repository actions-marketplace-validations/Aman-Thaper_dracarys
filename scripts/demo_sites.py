"""Serve the built-in testbed applications on loopback ports for a live demo.

    python scripts/demo_sites.py

Three deliberately different targets come up at once so you can point the scanner
at each in turn and watch the findings change:

    :8901  DevBlog   HTML app   — error-based SQLi, reflected XSS, open redirect,
                                  path traversal, server-side template injection,
                                  exposed .env leaking an AWS key, missing headers
    :8902  NotesAPI  JSON API   — boolean-based SQLi, leaked JWT, exposed OpenAPI
                                  schema, IDOR (needs two identities), CORS that
                                  reflects any origin with credentials
    :8903  Fort      hardened   — the control. Should report nothing at all.

All three are loopback, so no authorization flag is needed. The data is synthetic
and the apps live inside this package; nothing external is ever contacted.
"""
from __future__ import annotations

import asyncio

import uvicorn

from dracarys.scanner.testbed import build_api_app, build_blog_app, build_safe_app

SITES = [
    (8901, "DevBlog", "HTML app", build_blog_app),
    (8902, "NotesAPI", "JSON API", build_api_app),
    (8903, "Fort", "hardened control", build_safe_app),
]

BANNER = """
  DRACARYS demo targets are up.

    http://127.0.0.1:8901   DevBlog    HTML app          expect: SQLi, XSS, open redirect, .env leak
    http://127.0.0.1:8902   NotesAPI   JSON API          expect: boolean SQLi, JWT leak, exposed schema
    http://127.0.0.1:8903   Fort       hardened control  expect: nothing

  Scan one:
    dracarys scan http://127.0.0.1:8901

  Show IDOR (two identities, attacker first):
    dracarys scan http://127.0.0.1:8902 \\
      --auth 'Authorization: Bearer tok-user1' \\
      --second-auth 'Authorization: Bearer tok-user2' \\
      --protected-url http://127.0.0.1:8902/api/v2/notes/1001

  Ctrl-C to stop.
"""


async def main() -> None:
    servers = [
        uvicorn.Server(
            uvicorn.Config(factory(), host="127.0.0.1", port=port, log_level="error")
        )
        for port, _name, _kind, factory in SITES
    ]
    print(BANNER)
    await asyncio.gather(*(server.serve() for server in servers))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n  demo targets stopped.")
