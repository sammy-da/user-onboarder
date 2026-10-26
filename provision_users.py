#!/usr/bin/env python3
"""
Idempotently create Canton 3.x users and grant them rights on a participant.

Input is a HOCON file shaped like Canton's declarative user config (see users.conf).
Talks to the participant's JSON Ledger API (/v2/users, /v2/users/{id}/rights).

Behaviour per user (safe to re-run):
  * user missing        -> POST /v2/users
  * user exists         -> PATCH /v2/users/{id} if primary-party / is-deactivated differ
  * rights              -> POST /v2/users/{id}/rights for the ones the user doesn't have yet
Rights are additive: nothing is ever revoked.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from pyhocon import ConfigFactory

LOG = logging.getLogger("provision_users")

PAGE_SIZE = 10_000


class ApiError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"HTTP {status}: {body}")
        self.status = status
        self.body = body


class MissingPartiesError(Exception):
    pass


@dataclass
class UserSpec:
    user: str
    primary_party: str = ""
    is_deactivated: bool = False
    identity_provider_id: str = ""
    act_as: list[str] = field(default_factory=list)
    read_as: list[str] = field(default_factory=list)
    read_as_any_party: bool = False
    participant_admin: bool = False
    identity_provider_admin: bool = False


def load_specs(path: str) -> list[UserSpec]:
    conf = ConfigFactory.parse_file(path)
    specs = []
    for u in conf.get("users", []):
        r = u.get("rights", {})
        specs.append(
            UserSpec(
                user=u["user"],
                primary_party=u.get("primary-party", ""),
                is_deactivated=u.get("is-deactivated", False),
                identity_provider_id=u.get("identity-provider-id", ""),
                act_as=list(r.get("act-as", [])),
                read_as=list(r.get("read-as", [])),
                read_as_any_party=r.get("read-as-any-party", False),
                participant_admin=r.get("participant-admin", False),
                identity_provider_admin=r.get("identity-provider-admin", False),
            )
        )
    return specs


def _truncate(body: bytes | str, limit: int = 500) -> str:
    text = body.decode(errors="replace") if isinstance(body, bytes) else body
    return text if len(text) <= limit else f"{text[:limit]}... ({len(text)} chars)"


class Client:
    def __init__(self, base_url: str, token: str | None, timeout: float = 30):
        self.base_url = base_url.rstrip("/")
        # tolerate trailing newlines / a pasted "Bearer " prefix, which break the header
        token = (token or "").strip()
        self.token = token.removeprefix("Bearer ").strip() or None
        self.timeout = timeout

    def request(self, method: str, path: str, body=None, query=None):
        url = f"{self.base_url}{path}"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        LOG.debug("-> %s %s%s", method, url, f" body={data.decode()}" if data else "")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                LOG.debug("<- %s %s", resp.status, _truncate(raw))
                return json.loads(raw or b"{}")
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            LOG.debug("<- %s %s", e.code, _truncate(body))
            raise ApiError(e.code, body) from None


# A right is a hashable (kind, party) tuple so we can diff sets.
def wanted_rights(spec: UserSpec) -> set[tuple[str, str]]:
    rights = {("CanActAs", p) for p in spec.act_as} | {("CanReadAs", p) for p in spec.read_as}
    for flag, kind in (
        (spec.read_as_any_party, "CanReadAsAnyParty"),
        (spec.participant_admin, "ParticipantAdmin"),
        (spec.identity_provider_admin, "IdentityProviderAdmin"),
    ):
        if flag:
            rights.add((kind, ""))
    return rights


def to_json(right: tuple[str, str]) -> dict:
    kind, party = right
    return {"kind": {kind: {"value": {"party": party} if party else {}}}}


def from_json(r: dict) -> tuple[str, str]:
    ((kind, body),) = r["kind"].items()
    return (kind, (body.get("value") or {}).get("party", ""))


def is_not_found(e: ApiError) -> bool:
    return e.status == 404 or "USER_NOT_FOUND" in e.body


def list_parties(c: Client, idp: str) -> set[str]:
    parties: set[str] = set()
    token = ""
    while True:
        query = {"pageSize": PAGE_SIZE}
        if idp:
            query["identity-provider-id"] = idp
        if token:
            query["pageToken"] = token
        resp = c.request("GET", "/v2/parties", query=query)
        parties.update(p["party"] for p in resp.get("partyDetails", []))
        token = resp.get("nextPageToken", "")
        if not token:
            return parties


def check_parties(spec: UserSpec, known_parties: set[str]) -> None:
    referenced = {spec.primary_party, *spec.act_as, *spec.read_as} - {""}
    missing = sorted(referenced - known_parties)
    if missing:
        raise MissingPartiesError(f"parties do not exist on the participant: {missing}")


def provision(c: Client, spec: UserSpec, dry_run: bool) -> None:
    idp = spec.identity_provider_id
    idp_query = {"identity-provider-id": idp} if idp else None
    user_path = f"/v2/users/{urllib.parse.quote(spec.user, safe='')}"

    try:
        existing = c.request("GET", user_path, query=idp_query)["user"]
    except ApiError as e:
        if not is_not_found(e):
            raise
        existing = None

    desired = {
        "id": spec.user,
        "primaryParty": spec.primary_party,
        "isDeactivated": spec.is_deactivated,
        "identityProviderId": idp,
    }

    if existing is None:
        LOG.info("%s: creating user", spec.user)
        if not dry_run:
            c.request("POST", "/v2/users", {"user": desired})
        have: set[tuple[str, str]] = set()
    else:
        paths = []
        if existing.get("primaryParty", "") != spec.primary_party:
            paths.append("primary_party")
        if existing.get("isDeactivated", False) != spec.is_deactivated:
            paths.append("is_deactivated")
        if paths:
            LOG.info("%s: updating %s", spec.user, ", ".join(paths))
            if not dry_run:
                c.request(
                    "PATCH",
                    user_path,
                    {"user": desired, "updateMask": {"paths": paths}},
                )
        else:
            LOG.info("%s: user up to date", spec.user)
        have = {
            from_json(r)
            for r in c.request("GET", f"{user_path}/rights", query=idp_query).get("rights", [])
        }

    missing = sorted(wanted_rights(spec) - have)
    if not missing:
        LOG.info("%s: rights up to date", spec.user)
        return
    LOG.info("%s: granting %s", spec.user, missing)
    if not dry_run:
        c.request(
            "POST",
            f"{user_path}/rights",
            {
                "userId": spec.user,
                "identityProviderId": idp,
                "rights": [to_json(r) for r in missing],
            },
        )


def list_users(c: Client, idp: str) -> list[dict]:
    users: list[dict] = []
    token = ""
    while True:
        query = {"pageSize": PAGE_SIZE}
        if idp:
            query["identity-provider-id"] = idp
        if token:
            query["pageToken"] = token
        resp = c.request("GET", "/v2/users", query=query)
        users.extend(resp.get("users", []))
        token = resp.get("nextPageToken", "")
        if not token:
            return users


Snapshot = dict[tuple[str, str], tuple[dict, list[tuple[str, str]]]]  # (idp, user id) -> (user, rights)


def take_snapshot(c: Client, idps: set[str]) -> Snapshot:
    """Fetch every user on the participant (not just the ones in the input) with their rights."""
    # The default identity provider is always listed; add any others named in the input.
    users: dict[tuple[str, str], dict] = {}
    for idp in sorted({"", *idps}):
        for u in list_users(c, idp):
            users[(u.get("identityProviderId", ""), u["id"])] = u

    snap: Snapshot = {}
    for (idp, uid), u in sorted(users.items()):
        query = {"identity-provider-id": idp} if idp else None
        rights = sorted(
            from_json(r)
            for r in c.request(
                "GET", f"/v2/users/{urllib.parse.quote(uid, safe='')}/rights", query=query
            ).get("rights", [])
        )
        snap[(idp, uid)] = (u, rights)
    return snap


def party_formatter(snaps: list[Snapshot], full_party_ids: bool):
    """Parties are shown as their hint (the part before "::") unless full_party_ids is set.
    A hint shared by several different parties is always shown in full, to stay unambiguous."""
    parties = set()
    for snap in snaps:
        for u, rights in snap.values():
            parties.add(u.get("primaryParty", ""))
            parties.update(p for _, p in rights)
    hint_owners: dict[str, set[str]] = {}
    for p in parties - {""}:
        hint_owners.setdefault(p.split("::", 1)[0], set()).add(p)

    def show(p: str) -> str:
        if full_party_ids:
            return p
        hint = p.split("::", 1)[0]
        return hint if len(hint_owners[hint]) == 1 else p

    return show


def user_label(idp: str, uid: str) -> str:
    return f"{uid} [idp={idp}]" if idp else uid


def user_lines(entry, show) -> set[str]:
    u, rights = entry
    lines = {f"right: {k}({show(p)})" if p else f"right: {k}" for k, p in rights}
    if u.get("primaryParty"):
        lines.add(f"primary-party: {show(u['primaryParty'])}")
    if u.get("isDeactivated"):
        lines.add("DEACTIVATED")
    return lines


def print_summary(snap: Snapshot, full_party_ids: bool = False) -> None:
    show = party_formatter([snap], full_party_ids)
    print(f"\n=== {len(snap)} users on participant ===")
    for (idp, uid), entry in snap.items():
        print(user_label(idp, uid))
        for line in sorted(user_lines(entry, show)):
            print(f"  {line}")


def print_diff(before: Snapshot, after: Snapshot, full_party_ids: bool = False) -> None:
    """Print a colored (when stdout is a terminal) diff of the participant's users and rights."""
    use_color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    red, green, reset = ("\033[31m", "\033[32m", "\033[0m") if use_color else ("", "", "")
    show = party_formatter([before, after], full_party_ids)

    print("\n=== changes ===")
    changed = False
    for key in sorted(before.keys() | after.keys()):
        old = user_lines(before[key], show) if key in before else set()
        new = user_lines(after[key], show) if key in after else set()
        if key in before and key in after and old == new:
            continue
        changed = True
        label = user_label(*key)
        if key not in before:
            print(f"{green}+ {label} (new user){reset}")
        elif key not in after:
            print(f"{red}- {label} (user gone){reset}")
        else:
            print(f"  {label}")
        for line in sorted(old - new):
            print(f"{red}-   {line}{reset}")
        for line in sorted(new - old):
            print(f"{green}+   {line}{reset}")
    if not changed:
        print("(no changes)")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("config", help="HOCON file with a `users = [...]` list")
    ap.add_argument(
        "--host",
        default="localhost:7575/api/json-api",
        help="participant JSON Ledger API as host:port[/base-path] (default: %(default)s)",
    )
    ap.add_argument(
        "--token",
        default=os.environ.get("LEDGER_TOKEN"),
        help="bearer JWT, if the JSON API requires auth (default: $LEDGER_TOKEN)",
    )
    ap.add_argument(
        "--check-parties",
        action="store_true",
        help="skip (and fail) any user referencing a party that doesn't exist; never creates parties",
    )
    ap.add_argument(
        "--show-full-party-ids",
        action="store_true",
        help="in the final output, show fully qualified party ids (hint::fingerprint)\n"
        "instead of just the hint",
    )
    ap.add_argument(
        "-v", "--verbose", action="store_true", help="log every API call (the token is never logged)"
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="only log what would change; ends with a full listing of users instead of a diff",
    )
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(message)s")
    specs = load_specs(args.config)
    client = Client(f"http://{args.host}", args.token)

    known_parties: set[str] = set()
    if args.check_parties:
        # Listing parties is expensive, so it happens exactly once for the whole run.
        LOG.info("listing all parties on the participant for --check-parties; this can be slow")
        known_parties = list_parties(client, "")
        LOG.info("found %d parties", len(known_parties))

    idps = {sp.identity_provider_id for sp in specs}
    before: Snapshot | None = None
    if not args.dry_run:
        # Remember the participant's state so the final output can be a diff.
        LOG.info("snapshotting all users and rights before making changes")
        try:
            before = take_snapshot(client, idps)
        except ApiError as e:
            LOG.warning("could not snapshot users, so no diff will be shown: %s", e)

    failures = 0
    for spec in specs:
        try:
            if args.check_parties:
                check_parties(spec, known_parties)
            provision(client, spec, args.dry_run)
        except MissingPartiesError as e:
            LOG.error("%s: skipped: %s", spec.user, e)
            failures += 1
        except ApiError as e:
            LOG.error("%s: %s", spec.user, e)
            failures += 1

    try:
        after = take_snapshot(client, idps)
        if before is None:
            print_summary(after, args.show_full_party_ids)
        else:
            print_diff(before, after, args.show_full_party_ids)
    except ApiError as e:
        LOG.error("could not list users: %s", e)
        failures += 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
