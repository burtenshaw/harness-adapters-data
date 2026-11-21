"""Extract and independently replay data-only OpenFGA conformance questions."""

from collections import defaultdict
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
from urllib.request import urlopen

REPO = "openfga/openfga"
REV = "d67ba7b1d2eaf945cffab3a9129ca1a4c7ad5251"
PATH = "assets/tests/consolidated_1_1_tests.yaml"
FILE_SHA = "b07532f165b4863457e0d7554df90fa5564e855f28e5f2bf87ab3bb1a1d05d98"
PARSED_SHA = "57ed91f7a7c7ec6ccc1d5fe41b6201935a2c09f11aa1409fd53c0032cabb3864"
BLOB = "a9bdebec3ff59b4dd8c8acc9c598790dc65cf2b5"
LICENSE_SHA = "1c46d7b2bed94d457d745f28cabeb31f8d6c81dd9035bc5d24039989ee1e1bff"
INTRO = (
    "Perform a static OpenFGA 1.1 authorization review. Only the listed relationships "
    "exist. The current model controls which tuples can be used; stored tuples of a "
    "disallowed type have no effect. A tuple is written [object, relation, subject]. "
    "A subject ending in #relation includes the members of that related object. "
    "A typed wildcard includes any concrete subject of its type. 'A from B' follows B "
    "to related objects and checks A on those objects. 'but not' is set difference. "
    "Evaluate access under the model below."
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def compact(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def fixture_bytes(cache):
    cached = Path(cache) / "openfga" / "consolidated_1_1_tests.yaml"
    if cached.is_file():
        data = cached.read_bytes()
    else:
        with urlopen(f"https://raw.githubusercontent.com/{REPO}/{REV}/{PATH}", timeout=60) as source:
            data = source.read()
    if digest(data) != FILE_SHA:
        raise ValueError("OpenFGA conformance fixture SHA-256 mismatch")
    if not cached.exists():
        cached.parent.mkdir(parents=True, exist_ok=True)
        cached.write_bytes(data)
    return data


def load_suite(cache):
    data = fixture_bytes(cache)
    parsed = Path(cache) / "openfga" / "consolidated_1_1_tests.json"
    if parsed.is_file():
        encoded = parsed.read_bytes()
    else:
        import yaml

        encoded = compact(yaml.safe_load(data)).encode()
    if digest(encoded) != PARSED_SHA:
        raise ValueError("OpenFGA canonical JSON fixture SHA-256 mismatch")
    if not parsed.is_file():
        parsed.write_bytes(encoded)
    return json.loads(encoded)


@lru_cache(maxsize=None)
def expression(text):
    """Parse the supported direct, computed, tuple-to-userset and set-operation grammar."""
    text = text.strip()
    depth = 0
    for index, char in enumerate(text):
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif char == " " and depth == 0:
            for operator in (" or ", " and ", " but not "):
                if text.startswith(operator, index):
                    return (
                        operator.strip(),
                        expression(text[:index]),
                        expression(text[index + len(operator):]),
                    )
    if depth:
        raise ValueError(f"Unbalanced relation expression {text!r}")
    if text.startswith("(") and text.endswith(")"):
        return expression(text[1:-1])
    if text.startswith("[") and text.endswith("]"):
        return "direct", tuple(t.strip() for t in text[1:-1].split(","))
    pair = re.fullmatch(r"(\w+) from (\w+)", text)
    if pair:
        return "from", *pair.groups()
    if re.fullmatch(r"\w+", text):
        return "relation", text
    raise ValueError(f"Unsupported OpenFGA expression {text!r}")


def relations(model):
    lookup = {}
    current = None
    for line in (l.strip() for l in model.splitlines()):
        if line.startswith("type "):
            current = line.split()[1]
        elif line.startswith("define "):
            name, body = line[7:].split(":", 1)
            lookup[current, name] = expression(body)
        elif line not in {"model", "schema 1.1", "relations", ""}:
            raise ValueError(f"Unsupported OpenFGA declaration {line!r}")
    return lookup


def tuple_key(t):
    return t["object"], t["relation"], t["user"]


def kind(subject):
    base, _, userset = subject.partition("#")
    typ, _, key = base.partition(":")
    if userset:
        return typ + "#" + userset
    return typ + ":*" if key == "*" else typ


class Evaluator:
    """Evaluate the policy independently of the declared upstream assertion answer."""

    def __init__(self, model, tuples):
        self.rules = relations(model)
        self.entries = defaultdict(set)
        self.objects = set()
        for obj, rel, user in tuples:
            self.entries[obj, rel].add(user)
            self.objects.add(obj)
            self.objects.add(user.partition("#")[0])

    def check(self, obj, rel, user, visited=frozenset()):
        subject = obj, rel, user
        if subject in visited:
            return None  # An unresolved cycle cannot establish either side of an exclusion.
        node = self.rules.get((obj.split(":")[0], rel))
        if node is None:
            return False
        return self.evaluate(node, obj, rel, user, visited | {subject})

    def evaluate(self, node, obj, rel, user, visited):
        op = node[0]
        if op == "direct":
            unresolved = False
            for member in self.entries[obj, rel]:
                if kind(member) not in node[1]:
                    continue
                if member == user:
                    return True
                if member.endswith(":*") and "#" not in user and kind(user) == member[:-2]:
                    return True
                if "#" in member:
                    target, indirect = member.split("#", 1)
                    result = self.check(target, indirect, user, visited)
                    if result is True:
                        return True
                    unresolved |= result is None
            return None if unresolved else False
        if op == "relation":
            return self.check(obj, node[1], user, visited)
        if op == "from":
            parent_rel = self.rules.get((obj.split(":")[0], node[2]))
            if parent_rel is None or parent_rel[0] != "direct":
                return False
            unresolved = False
            for parent in self.entries[obj, node[2]]:
                if kind(parent) in parent_rel[1]:
                    result = self.check(parent, node[1], user, visited)
                    if result is True:
                        return True
                    unresolved |= result is None
            return None if unresolved else False
        left = self.evaluate(node[1], obj, rel, user, visited)
        right = self.evaluate(node[2], obj, rel, user, visited)
        if op == "or":
            if True in (left, right):
                return True
            return None if None in (left, right) else False
        if op == "but not":
            right = None if right is None else not right
        if op in {"and", "but not"}:
            if False in (left, right):
                return False
            return None if None in (left, right) else True
        raise ValueError(op)

    def list_objects(self, typ, rel, user):
        return sorted(
            obj for obj in self.objects
            if obj.startswith(typ + ":") and not obj.endswith(":*") and self.check(obj, rel, user)
        )


def neutral_ids(values):
    by_type = defaultdict(set)
    for value in values:
        typ, key = value.partition("#")[0].split(":", 1)
        if key != "*":
            by_type[typ].add(key)
    mapping = {
        (typ, key): f"{typ}:{index + 1}"
        for typ, keys in by_type.items() for index, key in enumerate(sorted(keys))
    }

    def rename(value):
        base, sep, relation = value.partition("#")
        typ, key = base.split(":", 1)
        return (base if key == "*" else mapping[typ, key]) + sep + relation
    return rename


def build(cache):
    if digest(Path(__file__).with_name("access-review-LICENSE.txt").read_bytes()) != LICENSE_SHA:
        raise ValueError("OpenFGA license notice mismatch")
    suite = load_suite(cache)
    seen = set()
    for case in suite["tests"]:
        stored = set()
        for stage_idx, stage in enumerate(case["stages"]):
            stored.update(tuple_key(t) for t in stage.get("tuples", []))
            model = "\n".join(s.rstrip() for s in stage["model"].strip().splitlines()
                              if not s.lstrip().startswith("#"))
            checks = [(i, t) for i, t in enumerate(stage.get("checkAssertions", []))
                      if type(t.get("expectation")) is bool]
            lists = [(i, t) for i, t in enumerate(stage.get("listObjectsAssertions", []))
                     if "expectation" in t]
            values = {v for obj, _, sub in stored for v in (obj, sub)}
            for _, assertion in checks:
                values.update((assertion["tuple"]["object"], assertion["tuple"]["user"]))
            for _, assertion in lists:
                values.add(assertion["request"]["user"])
                for t in assertion.get("contextualTuples", []):
                    values.update((t["object"], t["user"]))
            rename = neutral_ids(values)
            tuples = sorted((rename(o), r, rename(u)) for o, r, u in stored)
            model_and_tuples = model + "\n\nStored relationships:\n" + compact(tuples)
            group = "openfga-" + digest(model_and_tuples.encode())[:20]
            common = dict(
                source_repo=REPO, source_revision=REV, source_path=PATH, source_blob=BLOB,
                source_sha256=FILE_SHA, source_license="Apache-2.0", group_id=group,
                source_scenario=case["name"], source_stage=stage_idx,
                validation={"method": "upstream assertion versus independent OpenFGA DSL interpreter",
                            "source_sha256": FILE_SHA},
            )
            engine = Evaluator(model, tuples)
            all_checks = []
            for i, a in checks:
                t = a["tuple"]
                triplet = rename(t["object"]), t["relation"], rename(t["user"])
                result = engine.check(*triplet) is True
                if result != a["expectation"]:
                    raise ValueError(f"OpenFGA Check mismatch {case['name']}/{stage_idx}/{i}")
                if not any(x[1] == triplet for x in all_checks):
                    all_checks.append((i, triplet, result))
            for chunk_start in range(0, len(all_checks), 8):
                chunk = all_checks[chunk_start:chunk_start + 8]
                body = model_and_tuples + "\n\nAccess checks in order:\n" + compact([v for _, v, _ in chunk])
                prompt = (INTRO + '\nReturn exactly one JSON object {"decisions":[...]} listing a '
                          'JSON boolean for each check in the given order.\n\n' + body)
                if prompt in seen:
                    continue
                seen.add(prompt)
                ids = ",".join(str(i) for i, _, _ in chunk)
                sid = f"{case['name']}/{stage_idx}/check/{ids}"
                yield dict(common, family="openfga-check", source_id=sid, native_case_id=sid,
                           prompt=prompt, answer={"decisions": [ans for _, _, ans in chunk]})
            for i, a in lists:
                request = a["request"]
                ctx = sorted({(rename(t["object"]), t["relation"], rename(t["user"]))
                              for t in a.get("contextualTuples", [])})
                decision = Evaluator(model, tuples + ctx) if ctx else engine
                actual = decision.list_objects(request["type"], request["relation"], rename(request["user"]))
                expected = sorted(rename(s) for s in a["expectation"] or [])
                if actual != expected:
                    raise ValueError(f"OpenFGA ListObjects mismatch {case['name']}/{stage_idx}/{i}")
                body = model_and_tuples
                if ctx:
                    body += "\nAdditional relationships valid only for this query:\n" + compact(ctx)
                query = dict(request, user=rename(request["user"]))
                body += "\n\nListObjects request:\n" + compact(query)
                prompt = (INTRO + '\nReturn exactly one JSON object {"objects":[...]} with all '
                          'authorized object IDs of the requested type, lexicographically sorted. '
                          'Use an empty list if none qualify.\n\n' + body)
                if prompt in seen:
                    continue
                seen.add(prompt)
                sid = f"{case['name']}/{stage_idx}/listObjects/{i}"
                yield dict(common, family="openfga-list-objects", source_id=sid, native_case_id=sid,
                           prompt=prompt, answer={"objects": actual})
