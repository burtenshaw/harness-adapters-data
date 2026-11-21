"""Build static access reviews from the Cedar project's pinned differential corpus."""

from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile
from tempfile import NamedTemporaryFile
from urllib.request import urlopen


REPO = "cedar-policy/cedar-integration-tests"
REV = "aff4b8b99acb71aa5b288fa236295cccbb40d541"
ARCHIVE = "corpus-tests.tar.gz"
ARCHIVE_SHA = "49e40ba6da05cc622a04c2ff0ef858f6bc01e67f2b999002a3d8694af7abb9d9"
ENGINE = "@cedar-policy/cedar-wasm@4.15.0"
ENGINE_FILE = "cedar-policy-cedar-wasm-4.15.0.tgz"
ENGINE_SHA = "9642279ed09d959c34592d859c1373ad98e9fe7e3b34b772e991173fa604882c"
FIELDS = ("principal", "action", "resource", "context")
MAX_CHARS = 6000
MAX_PANELS = 1000
POLICY_IDS = ("policy0", "policy1")
INTRO = """Review these authorization requests using Cedar semantics. Evaluate each independently against the same policies and entity snapshot. A matching forbid overrides all permits. With no matching permit the decision is deny. A policy whose evaluation errors is skipped. For an allow list all matching permits as determining; for an explicit deny list all matching forbids; for default deny use an empty list. Include all policy IDs that errored separately. The entity "in" operation includes the entity itself and transitive parents. No authorization schema is applied.
Return one JSON object with key "results". Its value is an array in request order. Each entry has "request" (the displayed ID), "decision" ("allow" or "deny"), "determining" (array of IDs), and "errors" (array of IDs). Sort each ID array lexicographically."""
# Token identities retain equality patterns but erase arbitrary spelling, literals and namespaces.
TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|::|&&|\|\||!=|==|<=|>=|[a-zA-Z_]\w*|\d+|[^\s]')
KEYWORDS = set("""permit forbid principal action resource context when unless in is has like if then else true false contains containsAll containsAny isIpv4 isIpv6 isLoopback isMulticast isInRange lessThan lessThanOrEqual greaterThan greaterThanOrEqual ip decimal datetime duration getTag hasTag toDate toTime offset durationSince toMilliseconds toSeconds toMinutes toHours toDays""".split())
NODE = r"""
const engine = require(process.argv[1]);
const readline = require('node:readline');
function evaluate(call) {
  const r = engine.isAuthorized({...call.request, policies: {staticPolicies: call.policies}, entities: call.entities});
  if (r.type !== 'success') return null;
  return {decision:r.response.decision, determining:r.response.diagnostics.reason.sort(),
          errors:r.response.diagnostics.errors.map(e=>e.policyId).sort()};
}
readline.createInterface({input:process.stdin}).on('line', line => {
  const calls = JSON.parse(line);
  process.stdout.write(JSON.stringify(calls.map(evaluate)) + '\n');
});
"""


def compact(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def sha(value):
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def obtain(path, url, expected):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        with urlopen(url, timeout=60) as source, NamedTemporaryFile(dir=path.parent, delete=False) as tmp:
            data = source.read()
            if sha(data) != expected:
                raise ValueError(f"Invalid upstream digest for {path.name}")
            tmp.write(data)
        Path(tmp.name).replace(path)
    if sha(path.read_bytes()) != expected:
        raise ValueError(f"Invalid cached digest for {path.name}")
    return path


def normalized(policy):
    table = {}
    parts = []
    for token in TOKEN.findall(policy):
        if token in KEYWORDS or (len(token) <= 2 and not token[0].isalnum() and token[0] not in '\"_'):
            parts.append(token)
        else:
            key = "string" if token[0] == '"' else "num" if token.isdigit() else "id"
            names = table.setdefault(key, {})
            parts.append(names.setdefault(token, f"{key}{len(names)}"))
    return " ".join(parts)


def displayable(value):
    """Limit source-fuzzer artifacts, escapes, oversized literals and unsafe JS integers."""
    if isinstance(value, dict):
        return all(displayable(k) and displayable(v) for k, v in value.items())
    if isinstance(value, list):
        return all(map(displayable, value))
    if isinstance(value, str):
        return len(value) <= 160 and value.isascii() and all(32 <= ord(c) <= 126 for c in value)
    return isinstance(value, bool) or (isinstance(value, int) and abs(value) <= 2**53 - 1)


@dataclass
class Fixture:
    key: str
    policy: str
    shape: str
    entities: list
    requests: list
    hashes: dict


def fixtures(archive):
    with tarfile.open(archive) as tar:
        files = {m.name: tar.extractfile(m).read() for m in tar if m.isfile()}
    for name in sorted(files):
        match = re.fullmatch(r"corpus-tests/([0-9a-f]{40})\.json", name)
        if not match:
            continue
        spec = json.loads(files[name])
        original = files[spec["policies"]].decode()
        # Standalone policy annotations are metadata and do not affect authorization.
        policy = "\n".join(x for x in original.splitlines() if not x.startswith("@")).strip()
        if (len(policy) > 1200 or not policy.isascii() or "\\" in policy
                or re.search(r"(.)\1{19}", policy) or not re.search(r"^(permit|forbid)\(", policy)):
            continue
        entities = json.loads(files[spec["entities"]])
        if len(compact(entities)) > 3000 or not displayable(entities):
            continue
        seen = set()
        requests = []
        for i, row in enumerate(spec["requests"]):
            q = {k: row[k] for k in FIELDS}
            encoded = compact(q)
            if not displayable(q) or len(encoded) > 950 or encoded in seen:
                continue
            seen.add(encoded)
            expected = dict(decision=row["decision"], determining=sorted(row["reason"]), errors=sorted(row["errors"]))
            requests.append((str(i), q, expected))
        if not requests:
            continue
        hashes = {Path(p).name: sha(files[p]) for p in (name, spec["policies"], spec["entities"])}
        yield Fixture(match[1], policy, normalized(policy), entities, requests, hashes)


@contextmanager
def engine(cache):
    pkg = obtain(cache / "engine" / ENGINE_FILE,
                 f"https://registry.npmjs.org/@cedar-policy/cedar-wasm/-/{ENGINE_FILE}", ENGINE_SHA)
    with tarfile.open(pkg) as tar:
        for name in ("cedar_wasm.js", "cedar_wasm_bg.wasm"):
            data = tar.extractfile("package/nodejs/" + name).read()
            path = pkg.parent / name
            if not path.exists() or path.read_bytes() != data:
                with NamedTemporaryFile(dir=path.parent, delete=False) as tmp:
                    tmp.write(data)
                Path(tmp.name).replace(path)
    with subprocess.Popen(["node", "-e", NODE, str((pkg.parent / "cedar_wasm.js").resolve())],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as proc:
        def evaluate(calls):
            if not calls:
                return []
            proc.stdin.write(compact(calls) + "\n")
            proc.stdin.flush()
            line = proc.stdout.readline()
            if not line:
                raise RuntimeError("Cedar evaluator terminated")
            results = json.loads(line)
            if len(results) != len(calls):
                raise RuntimeError("Incomplete Cedar evaluator response")
            return results
        try:
            yield evaluate
        finally:
            proc.stdin.close()


def call(policies, entities, request):
    return dict(policies=policies, entities=entities, request=request)


def ordered_candidates(items, salt):
    return sorted(items, key=lambda x: sha(salt + compact(x)))


def choose(rows):
    """Select up to four requests with different verdicts; order prompts independently."""
    unique = {}
    for row in rows:
        unique.setdefault(compact(row[1]), row)
    ordered = ordered_candidates(list(unique.values()), "panel-order-v1")
    selected = []
    signatures = set()
    for row in ordered:
        signature = compact(row[2])
        if signature not in signatures and len(selected) < 4:
            signatures.add(signature)
            selected.append(row)
    for row in ordered:
        if row not in selected and len(selected) < 4:
            selected.append(row)
    if len(selected) < 3 or {r[2]["decision"] for r in selected} != {"allow", "deny"}:
        return []
    # Final presentation ordering uses only public input, never labels or source ordinals.
    return sorted(selected, key=lambda r: sha("presentation-v1" + compact(r[1])))


def task(fixtures_, entities, rows, derivation, validation):
    policies = {pid: f.policy for pid, f in zip(POLICY_IDS, fixtures_)}
    requests = [{"request": f"R{i}", **q} for i, (_, q, _) in enumerate(rows, 1)]
    answer = {"results": [{"request": f"R{i}", **gold} for i, (_, _, gold) in enumerate(rows, 1)]}
    prompt = ("\n\n".join([INTRO, *(f"{pid}\n{policy}" for pid, policy in policies.items()),
                           "Entities\n" + compact(entities),
                           "Requests\n" + "\n".join(compact(q) for q in requests)]))
    if len(prompt) > MAX_CHARS:
        return None
    keys = [f.key for f in fixtures_]
    structure = sha("\n".join(f.shape for f in fixtures_))
    return dict(family="cedar_authorization", source_id=REPO, source_revision=REV,
                source_path=ARCHIVE, native_case_id="/".join(keys), prompt=prompt, answer=answer,
                source_sha256=ARCHIVE_SHA, source_license="Apache-2.0", source_group=keys,
                source_paths=[f"corpus-tests/{key}.json" for key in keys],
                member_sha256={k:v for f in fixtures_ for k,v in f.hashes.items()},
                policy_sha256=[sha(f.policy) for f in fixtures_], structural_key=structure,
                derivation=derivation, request_origins=[r[0] for r in rows],
                validation={"engine":ENGINE, "engine_sha256":ENGINE_SHA, "method":validation})


def validated(fixtures_, evaluate):
    """Reconcile each original request used as evidence with upstream fixture gold."""
    for offset in range(0, len(fixtures_), 40):
        batch = fixtures_[offset:offset + 40]
        calls = [call({"policy0":f.policy}, f.entities, q) for f in batch for _, q, _ in f.requests]
        results = iter(evaluate(calls))
        for f in batch:
            f.requests = [(i, q, g) for i,q,g in f.requests if next(results) == g]
            if f.requests:
                yield f


def merge_entities(left, right):
    out = {}
    for e in left + right:
        key = compact(e["uid"])
        if key in out and out[key] != e:
            return None
        out[key] = e
    return [out[k] for k in sorted(out)]


def combined_gold(left, right):
    """Cedar's combination rule implemented outside the WASM engine."""
    if left is None or right is None:
        return None
    reason = right["determining"] or left["determining"]
    return {"decision":"deny" if right["determining"] else left["decision"],
            "determining":reason, "errors":sorted(left["errors"] + right["errors"])}


def paired(left, right, evaluate):
    entities = merge_entities(left.entities, right.entities)
    if entities is None or len(compact(entities)) > 3200:
        return None
    policies = {"policy0":left.policy, "policy1":right.policy}
    candidates = {}
    for f in (left, right):
        for i,q,_ in f.requests:
            candidates.setdefault(compact(q), (f"{f.key}/request/{i}", q))
    # Complete the two single-field swaps for each authorization dimension. Each
    # source tuple remains auditable by its fixture and zero-based request index.
    l = next(r for r in left.requests if r[2]["determining"])
    r = next(r for r in right.requests if r[2]["determining"])
    for source, a, other, b in ((left,l,right,r), (right,r,left,l)):
        for field in FIELDS:
            q = dict(a[1])
            q[field] = b[1][field]
            key = compact(q)
            if len(key) <= 950:
                candidates.setdefault(key, (f"{source.key}/request/{a[0]}+{other.key}/request/{b[0]}:{field}",q))
    if len(candidates) < 3:
        return None
    qs = list(candidates.values())
    policy_checks = [{"policy0":left.policy}, {"policy1":right.policy}, policies]
    responses = evaluate([call(p, entities, q) for _,q in qs for p in policy_checks])
    rows = []
    for i,(origin,q) in enumerate(qs):
        permit, forbid, together = responses[i*3:i*3+3]
        if together is not None and together == combined_gold(permit, forbid):
            rows.append((origin, q, together))
    panel = choose(rows)
    if not panel or {p for _,_,g in panel for p in g["determining"]} != set(policies):
        return None
    return task([left,right], entities, panel, "composed_source_policies",
                "upstream individual request gold; whole-set WASM vs independently combined isolated WASM decisions")


def build(cache):
    root = Path(cache) / "cedar"
    archive = obtain(root / ARCHIVE, f"https://raw.githubusercontent.com/{REPO}/{REV}/{ARCHIVE}", ARCHIVE_SHA)
    known = set()
    with engine(root) as evaluate:
        sources = list(validated(list(fixtures(archive)), evaluate))
        for f in sources:
            rows = choose([(f"{f.key}/request/{i}",q,g) for i,q,g in f.requests])
            if rows:
                item = task([f], f.entities, rows, "native",
                            "upstream request decisions, determining policy IDs and evaluation errors vs WASM replay")
                if item and item["structural_key"] not in known:
                    known.add(item["structural_key"])
                    yield item
        bins = {"permit": {}, "forbid": {}}
        for f in sorted(sources, key=lambda f:(len(compact(f.entities)) + len(f.policy), f.key)):
            if any(g["determining"] for _,_,g in f.requests):
                effect = "permit" if f.policy.startswith("permit") else "forbid"
                bins[effect].setdefault(f.shape, f)
        allows, denies = [sorted(rows.values(), key=lambda f:sha(f.key)) for rows in bins.values()]
        uses = Counter()
        for shift in range(len(denies)):
            for i,left in enumerate(allows):
                right = denies[(i + shift) % len(denies)]
                if max(uses[left.key], uses[right.key]) >= 12:
                    continue
                item = paired(left, right, evaluate)
                if item and item["structural_key"] not in known:
                    known.add(item["structural_key"])
                    uses.update((left.key, right.key))
                    yield item
                    if len(known) >= MAX_PANELS:
                        return
