#!/usr/bin/env python3
"""Tag-local Debian raw candidates; original creator remains the authenticator.

Import is inert. Supplier data verification never extracts or compiles a sysroot.
READY is input provenance, not a product/native/SDK acceptance receipt.
"""
import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import zipfile

ROOT = Path(__file__).absolute().parents[2]
REPO, RID = "polaris-arch/sing-box-polaris", 1421657509
MANIFEST, READY, USE = "candidate-manifest.json", "debian-material-ready.json", "debian-material-use.json"
RAW_NAME, READY_NAME = "debian-candidate-raw", "debian-material-ready"
SCOPE, VERIFICATION = "debian-raw", "original-gpgv-packages-deb-v1"
SUPPLIER_NAME, SUPPLIER_KEY = "Supply verified Debian raw inputs", "debian_materials"
OBJECT_LIMIT, UNION_LIMIT, JSON_LIMIT, COUNT_LIMIT = 64 * 1024**2, 1024**3, 1024**2, 512
ZIP_LIMIT, PROFILE_SECONDS, PREPARE_SECONDS, TRANSFER_SECONDS = 1024**3 + 2 * 1024**2, 1200, 2400, 600
INPUTS = ("scripts/ci/cronet_material_supply.py", "scripts/ci/cronet_material_bootstrap.py",
          "release/ci/cronet-material-profiles.json", "release/ci/cronet-material-inputs.json",
          ".github/patches/cronet-sysroot-transport.patch", ".github/CRONET_GO_VERSION")
CONTEXT_KEYS = {"repository", "repositoryID", "sourceCommit", "sourceTree", "tag", "tagObject",
                "workflow", "runID", "runAttempt", "role"}
PROFILE_KEYS = {"id", "keyringSHA256", "selectedDebs", "urls", "verified"}
BINDING_KEYS = {"schema", "scope", "context", "planSHA256", "requiredProfiles", "manifestSHA256",
                "rawArtifact", "readyArtifact", "supplierJob", "verification"}


def require(condition, message):
    if not condition:
        raise ValueError("Debian material admission: " + message)


def encode_json(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                       allow_nan=False) + "\n").encode()


def decode_json(raw):
    require(isinstance(raw, (str, bytes, bytearray)) and len(raw) <= JSON_LIMIT, "JSON byte bound")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: require(False, "non-finite JSON"))


def exact(value, keys, message):
    require(type(value) is dict and set(value) == set(keys), message)


def integer(value, maximum=None, positive=False):
    require(type(value) is int and (value > 0 if positive else value >= 0)
            and (maximum is None or value <= maximum), "integer/counter")


def sha(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None, "SHA256")
    return value


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def equal(left, right):
    return encode_json(left) == encode_json(right)


def read_regular(path, limit=JSON_LIMIT):
    path = Path(path).absolute()
    check_directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_nlink == 1 and info.st_size <= limit, "regular owned single-link bounded file")
        raw = stream.read(limit + 1)
        require(len(raw) <= limit, "actual file bytes")
        return raw


def check_directory(path, private=False):
    path = Path(path).absolute()
    for ancestor in (path, *path.parents):
        info = ancestor.lstat()
        require(stat.S_ISDIR(info.st_mode), "no symlink/non-directory ancestor")
    info = path.lstat()
    require(info.st_uid == os.geteuid(), "directory owner")
    if private:
        require(info.st_mode & 0o077 == 0, "private directory permissions")
    return info


def new_directory(path):
    path = Path(path).absolute()
    check_directory(path.parent)
    path.mkdir(mode=0o700)
    check_directory(path, private=True)
    return path


def write_new(path, raw):
    path = Path(path)
    check_directory(path.parent, private=True)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def replace_json(path, value):
    raw = encode_json(value)
    require(len(raw) <= JSON_LIMIT, "serialized JSON bound")
    path = Path(path)
    check_directory(path.parent, private=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".debian-data-", delete=False) as stream:
            temporary = Path(stream.name)
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        before = path.lstat() if path.exists() or path.is_symlink() else None
        require(before is None or (stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                                   and before.st_nlink == 1), "JSON destination")
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def load_profile_plan(root=ROOT):
    plan = decode_json(read_regular(Path(root) / INPUTS[2]))
    exact(plan, {"schema", "scope", "host", "pins", "limits", "roles", "profiles",
                 "metadata", "callers", "mappings", "eligibleArtifacts"}, "profile plan schema")
    require(plan["schema"] == "polaris-debian-material-profile-plan-v1" and plan["scope"] == SCOPE,
            "profile plan kind")
    require(plan["limits"] == {"objectBytes": OBJECT_LIMIT, "profileBytes": UNION_LIMIT,
                              "unionRawBytes": UNION_LIMIT, "objectCount": COUNT_LIMIT,
                              "manifestBytes": JSON_LIMIT, "readyBytes": JSON_LIMIT,
                              "outerZipBytes": ZIP_LIMIT}, "source-owned limits")
    require(plan["host"] == {"system": "Linux", "machine": "x86_64"}, "source-owned host")
    return plan


def profile_plan_sha256(root=ROOT):
    # There is no self-referential constant: every caller hashes its own trusted
    # checkout, including this controller and the complete static profile plan.
    try:
        measured = {name: digest(read_regular(Path(root) / name, JSON_LIMIT)) for name in INPUTS}
    except OSError as error:
        raise ValueError("Debian material admission: unavailable trusted source input") from error
    return digest(encode_json(measured))


def expected_use(role, artifact_name):
    require(type(role) is str and type(artifact_name) is str, "eligible artifact identity")
    value = load_profile_plan()["eligibleArtifacts"].get(role, {}).get(artifact_name)
    return json.loads(encode_json(value)) if value is not None else None


def validate_context(context):
    exact(context, CONTEXT_KEYS, "context fields")
    for key in ("repositoryID", "runID", "runAttempt"):
        integer(context[key], positive=True)
    require(context["repository"] == REPO and context["repositoryID"] == RID, "repository")
    for key in ("sourceCommit", "sourceTree", "tagObject"):
        require(type(context[key]) is str and re.fullmatch(r"[0-9a-f]{40}", context[key]) is not None,
                "source/tag object")
    require(type(context["tag"]) is str and re.fullmatch(r"v[0-9A-Za-z][0-9A-Za-z._-]{0,199}",
                                                       context["tag"]) is not None, "tag")
    plan = load_profile_plan()
    require(type(context["role"]) is str and context["role"] in plan["roles"]
            and type(context["workflow"]) is str
            and context["workflow"] == plan["roles"][context["role"]]["workflow"], "role/workflow")
    return plan


def required_profiles(context, plan=None):
    plan = plan or validate_context(context)
    return plan["roles"][context["role"]]["profiles"]


def artifact_ref(item):
    require(type(item) is dict, "artifact ref")
    if "size_in_bytes" in item:
        item = {"id": item.get("id"), "name": item.get("name"),
                "digest": item.get("digest"), "size": item.get("size_in_bytes")}
    exact(item, {"id", "name", "digest", "size"}, "artifact ref fields")
    integer(item["id"], positive=True)
    integer(item["size"], ZIP_LIMIT, positive=True)
    require(type(item["name"]) is str and item["name"] in (RAW_NAME, READY_NAME)
            and type(item["digest"]) is str
            and re.fullmatch(r"sha256:[0-9a-f]{64}", item["digest"]) is not None, "artifact ref values")
    return dict(item)


def profile_urls(plan, profile_id):
    profile = next(p for p in plan["profiles"] if p["id"] == profile_id)
    by_id = {item["id"]: item["logicalURL"] for item in plan["metadata"]}
    return {by_id[key] for key in profile["metadataObjectRefs"]}


def allowed_url(url, profile_id, plan):
    require(type(url) is str and len(url) <= 2048, "logical URL type/size")
    profile = next(p for p in plan["profiles"] if p["id"] == profile_id)
    if url in profile_urls(plan, profile_id):
        return
    prefix = profile["archivePrefix"] + "pool/"
    # This fixed ports index mixes Architecture:all pool/ with loong64 pool-loong64/.
    if (profile_id == "sid-loong64" and profile["creatorArchitecture"] == "loong64"
            and profile["archivePrefix"] == "https://snapshot.debian.org/archive/debian-ports/20250625T074124Z/"
            and url.startswith(profile["archivePrefix"] + "pool-loong64/")):
        prefix = profile["archivePrefix"] + "pool-loong64/"
    require(url.startswith(prefix), "logical URL/profile archive")
    relative = url[len(prefix):]
    require(re.fullmatch(r"[A-Za-z0-9._+~:%/-]+\.deb", relative) is not None
            and all(part not in ("", ".", "..") for part in relative.split("/"))
            and re.search(r"(?i)%2f|%5c|%2e", relative) is None, "logical deb URL spelling")


def validate_profile(record, profile_id, plan):
    exact(record, PROFILE_KEYS, "profile receipt fields")
    require(record["id"] == profile_id and record["verified"] is True, "profile original verification")
    sha(record["keyringSHA256"])
    require(type(record["selectedDebs"]) is dict and bool(record["selectedDebs"]) and len(record["selectedDebs"]) <= COUNT_LIMIT,
            "selected deb dictionary")
    for url, expected in record["selectedDebs"].items():
        allowed_url(url, profile_id, plan)
        require(url.endswith(".deb"), "selected deb URL")
        sha(expected)
    require(type(record["urls"]) is list and all(type(url) is str for url in record["urls"])
            and record["urls"] == sorted(set(record["urls"]))
            and all(type(url) is str for url in record["urls"])
            and set(record["urls"]) == profile_urls(plan, profile_id) | set(record["selectedDebs"]),
            "original full metadata/deb URL coverage")


def validate_manifest(manifest, *, context, measurements):
    plan = validate_context(context)
    exact(manifest, {"schema", "scope", "context", "planSHA256", "requiredProfiles", "state",
                     "objects", "profiles", "seed"}, "candidate manifest fields")
    require(manifest["schema"] == "polaris-debian-candidate-v1" and manifest["scope"] == SCOPE
            and equal(manifest["context"], context)
            and manifest["planSHA256"] == profile_plan_sha256()
            and equal(manifest["requiredProfiles"], required_profiles(context, plan))
            and type(manifest["state"]) is str and manifest["state"] in ("PARTIAL", "VERIFIED"),
            "candidate source/plan/state")
    require(type(manifest["objects"]) is list and len(manifest["objects"]) <= COUNT_LIMIT
            and type(manifest["profiles"]) is list, "candidate counts")
    required = set(manifest["requiredProfiles"])
    entries, members = {}, {}
    for item in manifest["objects"]:
        exact(item, {"url", "member", "sha256", "bytes", "profiles", "complete"}, "candidate object fields")
        sha(item["sha256"])
        integer(item["bytes"], OBJECT_LIMIT)
        require(type(item["url"]) is str and item["url"] not in entries
                and item["member"] == "objects/" + item["sha256"] and item["complete"] is True
                and type(item["profiles"]) is list and item["profiles"]
                and all(type(p) is str for p in item["profiles"])
                and item["profiles"] == sorted(set(item["profiles"]))
                and set(item["profiles"]) <= required, "candidate identity/profile")
        for profile_id in item["profiles"]:
            allowed_url(item["url"], profile_id, plan)
        if item["member"] in members:
            require(members[item["member"]] == {"bytes": item["bytes"], "sha256": item["sha256"]},
                    "CAS alias bytes")
        members[item["member"]] = {"bytes": item["bytes"], "sha256": item["sha256"]}
        entries[item["url"]] = item
    require(sum(item["bytes"] for item in members.values()) <= UNION_LIMIT, "raw union bytes")
    for profile_id in required:
        require(sum(item["bytes"] for item in entries.values() if profile_id in item["profiles"])
                <= UNION_LIMIT, "profile raw bytes")
    seen = set()
    for profile in manifest["profiles"]:
        require(type(profile) is dict and type(profile.get("id")) is str
                and profile["id"] in required and profile["id"] not in seen, "profile receipt identity")
        validate_profile(profile, profile["id"], plan)
        seen.add(profile["id"])
        require(all(url in entries and profile["id"] in entries[url]["profiles"] for url in profile["urls"]),
                "profile complete raw coverage")
        require(all(entries[url]["sha256"] == expected for url, expected in profile["selectedDebs"].items()),
                "selected deb expected SHA")
    if manifest["state"] == "VERIFIED":
        require(seen == required, "all original profiles verified")
        covered = {url for profile in manifest["profiles"] for url in profile["urls"]}
        require(set(entries) == covered, "no unverified READY objects")
    seed = manifest["seed"]
    if seed is not None:
        exact(seed, {"artifact", "context", "manifestSHA256"}, "seed fields")
        old = validate_context(seed["context"])
        require(old is not None and all(equal(seed["context"][key], context[key])
                for key in CONTEXT_KEYS - {"runID", "runAttempt"}), "seed exact source/profile identity")
        require(artifact_ref(seed["artifact"])["name"] == RAW_NAME, "seed raw only")
        sha(seed["manifestSHA256"])
    expected = dict(members)
    raw = encode_json(manifest)
    require(len(raw) <= JSON_LIMIT, "manifest bytes")
    expected[MANIFEST] = {"bytes": len(raw), "sha256": digest(raw)}
    require(type(measurements) is dict and set(measurements) == set(expected), "exact measured member set")
    for name, value in measurements.items():
        exact(value, {"bytes", "sha256"}, "member measurement fields")
        integer(value["bytes"], JSON_LIMIT if name == MANIFEST else OBJECT_LIMIT)
        sha(value["sha256"])
        require(equal(value, expected[name]), "actual member bytes/selfSHA")
    return manifest


def supplier_ref(job, context, completed=True):
    require(type(job) is dict and job.get("name") == SUPPLIER_NAME, "supplier job name")
    integer(job.get("id"), positive=True)
    require(job.get("head_sha") == context["sourceCommit"], "supplier actual source")
    require(type(job.get("run_id")) is int and job["run_id"] == context["runID"]
            and type(job.get("run_attempt")) is int and job["run_attempt"] == context["runAttempt"],
            "actual supplier job run/attempt")
    if completed:
        require(job.get("status") == "completed" and job.get("conclusion") == "success",
                "supplier actual success required")
    else:
        require(job.get("status") == "in_progress" and job.get("conclusion") is None,
                "READY creation requires own actual active supplier")
    return {"id": job["id"], "key": SUPPLIER_KEY, "name": SUPPLIER_NAME}


def validate_ready(ready, *, context, manifest, raw_artifact, supplier_job):
    validate_context(context)
    require(equal(manifest.get("context"), context) and manifest.get("planSHA256") == profile_plan_sha256()
            and equal(manifest.get("requiredProfiles"), required_profiles(context)), "READY original manifest source")
    exact(ready, {"schema", "scope", "context", "planSHA256", "requiredProfiles",
                  "manifestSHA256", "rawArtifact", "supplierJob", "verification"}, "READY fields")
    require(ready["schema"] == "polaris-debian-ready-v1" and ready["scope"] == SCOPE
            and equal(ready["context"], context) and manifest["state"] == "VERIFIED"
            and ready["planSHA256"] == manifest["planSHA256"]
            and equal(ready["requiredProfiles"], manifest["requiredProfiles"])
            and ready["manifestSHA256"] == digest(encode_json(manifest))
            and equal(ready["rawArtifact"], artifact_ref(raw_artifact))
            and ready["rawArtifact"]["name"] == RAW_NAME
            and equal(ready["supplierJob"], supplier_ref(supplier_job, context))
            and ready["verification"] == VERIFICATION, "READY binding/actual supplier")
    # The caller independently measures the READY artifact and adds its actual
    # API ref. This prebinding cannot predict READY's own future upload digest.
    return {"schema": "polaris-debian-binding-v1", **{key: ready[key] for key in ready
            if key not in ("schema",)}}


def _validate_use_shape(use, *, binding, ready_artifact, artifact_name):
    exact(binding, BINDING_KEYS, "complete distribution binding fields")
    exact(use, {"schema", "scope", "context", "planSHA256", "requiredProfiles",
                "manifestSHA256", "rawArtifact", "readyArtifact", "supplierJob",
                "caller", "targetArch", "libc", "profiles", "verification", "consumerJob"}, "consumer use fields")
    require(use["schema"] == "polaris-debian-use-v1"
            and binding["schema"] == "polaris-debian-binding-v1", "use/binding schema")
    for key in BINDING_KEYS - {"schema"}:
        if key == "readyArtifact":
            require(equal(use[key], artifact_ref(ready_artifact)) and equal(binding[key], use[key]),
                    "actual READY artifact use")
        else:
            require(equal(use[key], binding[key]), "use binding differs: " + key)
    plan = validate_context(use["context"])
    require(binding["planSHA256"] == profile_plan_sha256(), "current trusted plan")
    expected = expected_use(use["context"]["role"], artifact_name)
    require(expected is not None and all(equal(use[key], expected[target]) for key, target in
            (("caller", "caller"), ("targetArch", "targetArch"), ("libc", "libc"))), "artifact/matrix use tuple")
    require(type(use["profiles"]) is list
            and [p.get("id") if type(p) is dict else None for p in use["profiles"]] == expected["profiles"],
            "consumer exact required profile subset")
    for profile in use["profiles"]:
        validate_profile(profile, profile["id"], plan)
    require(use["verification"] == VERIFICATION, "consumer original verifier marker")
    exact(use["consumerJob"], {"id", "key", "name", "runner"}, "consumer actual job fields")
    integer(use["consumerJob"]["id"], positive=True)
    require(all(type(use["consumerJob"][key]) is str and use["consumerJob"][key] for key in ("key", "name", "runner")), "consumer job text")
    caller = next(item for item in plan["callers"] if item["id"] == use["caller"])
    require(use["consumerJob"]["key"] == caller["job"] and caller["workflow"] == use["context"]["workflow"], "consumer source-owned job key")
    return use


def validate_use_ref(use, *, binding, ready_artifact, artifact_name, consumer_job):
    _validate_use_shape(use, binding=binding, ready_artifact=ready_artifact, artifact_name=artifact_name)
    reference = use["consumerJob"]
    require(type(consumer_job) is dict and consumer_job.get("status") == "completed"
            and consumer_job.get("conclusion") == "success", "actual consumer successful completion")
    expected = {"id": reference["id"], "run_id": use["context"]["runID"],
                "run_attempt": use["context"]["runAttempt"], "name": reference["name"],
                "runner_name": reference["runner"]}
    require(consumer_job.get("head_sha") == use["context"]["sourceCommit"], "consumer actual source")
    require(all(equal(consumer_job.get(key), value) for key, value in expected.items()),
            "consumer actual API row identity")
    return use


def _bounded_file_size(path, maximum):
    check_directory(Path(path).absolute().parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_nlink == 1 and 0 < info.st_size <= maximum, "bounded ZIP file identity")
        return info.st_size
    finally:
        os.close(fd)


def _release():
    # Lazy: publisher imports this module and calls these validators itself.
    # Never call inventory/extract or another product acceptance entrypoint.
    import github_release
    return github_release


@contextmanager
def _zip(value, maximum):
    release = _release()
    if isinstance(value, zipfile.ZipFile):
        require(value.filename is not None, "ZIP must have a measured private backing file")
        path = Path(value.filename)
        require(_bounded_file_size(path, maximum) <= maximum, "outer ZIP bytes")
        release.bounded_zip_directory(path)
        yield value
    else:
        path = Path(value)
        require(_bounded_file_size(path, maximum) <= maximum, "outer ZIP bytes")
        release.bounded_zip_directory(path)
        with zipfile.ZipFile(path) as archive:
            yield archive


def _measure_zip(value, ready=False):
    release = _release()
    maximum = JSON_LIMIT + 65536 if ready else ZIP_LIMIT
    measurements, document = {}, None
    with _zip(value, maximum) as archive:
        members = release.safe_zip_members(archive)
        require(len(members) <= (1 if ready else COUNT_LIMIT + 2), "ZIP member count")
        total = 0
        for item in members:
            if item.is_dir():
                require(not ready and item.filename == "objects/", "only exact objects directory allowed")
                continue
            name = item.filename
            json_member = name == (READY if ready else MANIFEST)
            require(json_member or (not ready and re.fullmatch(r"objects/[0-9a-f]{64}", name) is not None),
                    "unlisted data ZIP member")
            require(item.file_size <= (JSON_LIMIT if json_member else OBJECT_LIMIT), "declared member bytes")
            measure, decoded = release.measure_member(
                archive, item, json_limit=JSON_LIMIT if json_member else None, json_decoder=decode_json)
            total += measure["bytes"]
            require(total <= UNION_LIMIT + JSON_LIMIT and name not in measurements, "actual inflated bytes/member alias")
            measurements[name] = measure
            if json_member:
                document = decoded
    require(document is not None and (not ready or set(measurements) == {READY}), "required exact JSON member")
    return document, measurements


def _outer_matches(value, metadata):
    reference = artifact_ref(metadata)
    path = Path(value.filename) if isinstance(value, zipfile.ZipFile) else Path(value)
    # Stream the ZIP identity; never allocate its complete 1GiB body in memory.
    check_directory(path.absolute().parent)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_nlink == 1 and info.st_size == reference["size"], "outer ZIP kind/size")
        measured, size = hashlib.sha256(), 0
        while chunk := stream.read(1024 * 1024):
            measured.update(chunk)
            size += len(chunk)
            require(size <= ZIP_LIMIT, "outer actual bytes")
    require(reference["digest"] == "sha256:" + measured.hexdigest(), "outer ZIP actual digest")


def validate_bundle(raw_zip, ready_zip, *, raw_artifact, ready_artifact, context, supplier_job):
    _outer_matches(raw_zip, raw_artifact)
    _outer_matches(ready_zip, ready_artifact)
    manifest, measurements = _measure_zip(raw_zip)
    validate_manifest(manifest, context=context, measurements=measurements)
    ready, ready_measurements = _measure_zip(ready_zip, ready=True)
    require(ready_measurements[READY] == {"bytes": len(encode_json(ready)), "sha256": digest(encode_json(ready))},
            "canonical READY actual bytes")
    binding = validate_ready(ready, context=context, manifest=manifest,
                             raw_artifact=raw_artifact, supplier_job=supplier_job)
    binding["readyArtifact"] = artifact_ref(ready_artifact)
    require(binding["readyArtifact"]["name"] == READY_NAME, "READY artifact name")
    return binding


def _git(root, *arguments, _env=None, _timeout=20):
    require(type(_timeout) in (int, float) and 0 < _timeout <= 20, "Git metadata timeout")
    env = _env if _env is not None else dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0")
    return subprocess.check_output(["git", "--no-optional-locks", "-C", str(root), *arguments],
                                   env=env, stderr=subprocess.DEVNULL, timeout=_timeout).decode().strip()



def _annotated_object(tag, source):
    from polaris_version import validate as validate_version
    require(type(tag) is str and tag.startswith("v"), "versioned tag required")
    validate_version(tag[1:])
    require(type(source) is str and re.fullmatch(r"[0-9a-f]{40}", source) is not None, "full source SHA")
    deadline = time.monotonic() + 120

    def remote(expected=None):
        # Same actual ref/tag/direct-commit checks as remote_tag_identity, with
        # this protocol's bounded read_get and confirmed GET child cleanup.
        ref = _api("git/ref/tags/" + tag, deadline)
        require(type(ref) is dict and ref.get("ref") == "refs/tags/" + tag
                and type(ref.get("object")) is dict and ref["object"].get("type") == "tag",
                "actual annotated remote tag")
        oid = ref["object"].get("sha")
        require(type(oid) is str and re.fullmatch(r"[0-9a-f]{40}", oid) is not None
                and (expected is None or oid == expected), "actual immutable tag object")
        obj = _api("git/tags/" + oid, deadline)
        require(type(obj) is dict and obj.get("sha") == oid and obj.get("tag") == tag
                and type(obj.get("object")) is dict and obj["object"].get("type") == "commit"
                and obj["object"].get("sha") == source, "annotated direct source peel")
        return oid

    def local(*arguments, environment=None):
        remaining = deadline - time.monotonic()
        require(remaining > 0, "tag identity total deadline")
        return _git(ROOT, *arguments, _env=environment, _timeout=min(20, remaining))

    oid = remote()
    try:
        kind = local("cat-file", "-t", oid)
    except subprocess.CalledProcessError:
        require(local("remote", "get-url", "origin") in (
            "https://github.com/" + REPO, "https://github.com/" + REPO + ".git"),
            "fixed GitHub origin required")
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        require(type(token) is str and token, "read-only token required for private tag object")
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(("GIT_CONFIG_", "GIT_TRACE", "DEBUG", "TRACE"))
                       and key not in ("GIT_CURL_VERBOSE",)}
        # Reset Git's inherited header list before adding this fetch's auth.
        environment.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0",
                            "GIT_CONFIG_COUNT": "3", "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
                            "GIT_CONFIG_VALUE_0": "",
                            "GIT_CONFIG_KEY_1": "http.https://github.com/.extraheader",
                            "GIT_CONFIG_VALUE_1": "AUTHORIZATION: basic " + base64.b64encode(
                                ("x-access-token:" + token).encode()).decode(),
                            "GIT_CONFIG_KEY_2": "http.sslVerify", "GIT_CONFIG_VALUE_2": "true"})
        try:
            local("fetch", "--depth=1", "--no-tags", "--no-write-fetch-head", "origin", oid,
                  environment=environment)
        finally:
            environment.pop("GIT_CONFIG_VALUE_1", None)
            token = None
        kind = local("cat-file", "-t", oid)
    require(kind == "tag" and local("rev-parse", oid + "^{commit}") == source,
            "actual local annotated object/direct source")
    require(remote(expected=oid) == oid, "annotated remote object moved")
    return oid

def actions_context(role, env=None):
    env = os.environ if env is None else env
    require(env.get("GITHUB_SERVER_URL") == "https://github.com"
            and env.get("GITHUB_API_URL") == "https://api.github.com"
            and env.get("GH_HOST") in (None, "github.com"), "fixed GitHub server/API host")
    require(env.get("GITHUB_ACTIONS") == "true" and platform.system() == "Linux"
            and platform.machine() == "x86_64", "actual Linux amd64 host only")
    require(env.get("GITHUB_REPOSITORY") == REPO and env.get("GITHUB_REPOSITORY_ID") == str(RID)
            and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch", "actual Actions repository/event")
    for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        require(re.fullmatch(r"[1-9][0-9]*", env.get(name, "")) is not None, "actual run/attempt")
    reference = env.get("GITHUB_REF", "")
    require(reference.startswith("refs/tags/"), "tag-local material channel")
    tag = reference[len("refs/tags/"):]
    plan = load_profile_plan()
    require(role in plan["roles"], "role")
    workflow = plan["roles"][role]["workflow"]
    require(env.get("GITHUB_WORKFLOW_REF") == REPO + "/" + workflow + "@" + reference,
            "actual workflow_ref")
    source = _git(ROOT, "rev-parse", "HEAD")
    require(env.get("GITHUB_SHA") == source and env.get("GITHUB_WORKFLOW_SHA") == source,
            "actual source/workflow checkout")
    require(not _git(ROOT, "diff", "--name-only", "HEAD", "--", *INPUTS), "dirty source-owned material inputs")
    oid = _annotated_object(tag, source)
    context = {"repository": REPO, "repositoryID": RID, "sourceCommit": source,
               "sourceTree": _git(ROOT, "rev-parse", "HEAD^{tree}"), "tag": tag,
               "tagObject": oid,
               "workflow": workflow, "runID": int(env["GITHUB_RUN_ID"]),
               "runAttempt": int(env["GITHUB_RUN_ATTEMPT"]), "role": role}
    validate_context(context)
    return context


def _api(path, deadline=None):
    from github_read_transport import read_get
    sink = io.BytesIO()
    remaining = 45 if deadline is None else deadline - time.monotonic()
    require(remaining > 0, "API admission deadline")
    read_get("repos/" + REPO + "/" + path, sink, 2 * JSON_LIMIT,
             attempt_seconds=min(15, remaining), total_seconds=min(45, remaining), max_retry_wait=4)
    # Metadata may be 2MiB; it is not a material manifest.
    raw = sink.getvalue()
    require(len(raw) <= 2 * JSON_LIMIT, "API metadata bytes")
    return json.loads(raw, object_pairs_hook=_unique_pairs)


def _unique_pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate API JSON key")
        result[key] = value
    return result


def _timestamp(value):
    require(type(value) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is not None,
            "API timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _run(context, deadline):
    run = _api("actions/runs/" + str(context["runID"]) + "/attempts/" + str(context["runAttempt"]), deadline)
    expected = {"id": context["runID"], "run_attempt": context["runAttempt"],
                "head_sha": context["sourceCommit"], "head_branch": context["tag"],
                "event": "workflow_dispatch", "path": context["workflow"]}
    require(type(run) is dict and all(equal(run.get(key), value) for key, value in expected.items()),
            "actual run/attempt/source/ref/workflow")
    for key in ("repository", "head_repository"):
        require(type(run.get(key)) is dict and run[key].get("id") == RID
                and type(run[key].get("id")) is int and run[key].get("full_name") == REPO, "run repository")
    require(_timestamp(run["run_started_at"]) <= datetime.now(timezone.utc), "run start")
    return run


def _job(context, completed=True, deadline=None):
    rows, total, seen = [], None, set()
    for page in range(1, 5):
        result = _api("actions/runs/" + str(context["runID"]) + "/attempts/"
                      + str(context["runAttempt"]) + "/jobs?per_page=100&page=" + str(page), deadline)
        require(type(result) is dict and type(result.get("jobs")) is list, "jobs page")
        integer(result.get("total_count"), 400)
        require(total is None or total == result["total_count"], "unstable jobs pages")
        total = result["total_count"]
        for row in result["jobs"]:
            integer(row.get("id"), positive=True)
            require(row["id"] not in seen, "duplicate job")
            seen.add(row["id"])
            rows.append(row)
        if len(rows) == total:
            break
        require(len(rows) < total and len(result["jobs"]) == 100, "jobs pagination")
    require(len(rows) == total, "complete jobs pages")
    matches = [row for row in rows if row.get("name") == SUPPLIER_NAME]
    require(len(matches) == 1, "unique actual supplier job")
    supplier_ref(matches[0], context, completed=completed)
    return matches[0]


def _artifact(item, context, run, name):
    require(artifact_ref(item)["name"] == name and item.get("expired") is False, "artifact name/expiry")
    if name == READY_NAME:
        require(item["size_in_bytes"] <= JSON_LIMIT + 65536, "READY outer ZIP bound")
    actual = {"id": context["runID"], "repository_id": RID, "head_repository_id": RID,
              "head_branch": context["tag"], "head_sha": context["sourceCommit"]}
    require(equal(item.get("workflow_run"), actual), "artifact actual source/run")
    now = datetime.now(timezone.utc)
    require(_timestamp(run["run_started_at"]) <= _timestamp(item.get("created_at")) <= now
            < _timestamp(item.get("expires_at")), "artifact actual attempt/time")
    return item


def _select_artifact(context, artifact_id, expected_digest, name, run, deadline):
    integer(artifact_id, positive=True)
    expected_digest = normalize_digest(expected_digest)
    selected = _api("actions/artifacts/" + str(artifact_id), deadline)
    require(selected.get("id") == artifact_id and type(selected.get("id")) is int
            and selected.get("digest") == expected_digest, "actual artifact ID/digest")
    _artifact(selected, context, run, name)
    total, seen, matches = None, set(), []
    for page in range(1, 5):
        data = _api("actions/runs/" + str(context["runID"]) + "/artifacts?per_page=100&page=" + str(page), deadline)
        integer(data.get("total_count"), 400)
        require(type(data.get("artifacts")) is list and (total is None or total == data["total_count"]),
                "artifact pages")
        total = data["total_count"]
        for row in data["artifacts"]:
            integer(row.get("id"), positive=True)
            require(row["id"] not in seen, "duplicate artifact ID")
            seen.add(row["id"])
            if row.get("name") == name:
                matches.append(row)
        if len(seen) == total:
            break
        require(len(seen) < total and len(data["artifacts"]) == 100, "artifact pagination")
    require(len(seen) == total and len(matches) == 1 and equal(matches[0], selected),
            "unique stable same-run artifact")
    return selected


def normalize_digest(value):
    require(type(value) is str, "artifact digest type")
    value = value if value.startswith("sha256:") else "sha256:" + value
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None, "artifact digest")
    return value


def _prepared(root):
    root = Path(root).absolute()
    plan = load_profile_plan()
    naive = root / "naiveproxy"
    require(_git(root, "rev-parse", "HEAD") == plan["pins"]["cronetCommit"]
            and _git(naive, "rev-parse", "HEAD") == plan["pins"]["naiveCommit"], "pinned Cronet/naive checkout")
    source = naive / "src/build/linux/sysroot_scripts"
    expected = dict(plan["pins"]["sourceSHA256"])
    expected["src/build/linux/sysroot_scripts/sysroot_creator.py"] = plan["pins"]["postimageSHA256"]
    expected.update({"src/build/linux/sysroot_scripts/reversion_glibc.py": plan["pins"]["reversionSHA256"],
                     "src/build/linux/sysroot_scripts/generate_keyring.sh": plan["pins"]["keyringRecipeSHA256"]})
    for name, expected_sha in expected.items():
        require(digest(read_regular(naive / name)) == expected_sha, "prepared fixed source: " + name)
    require(read_regular(source / "polaris_cronet_material.py") == read_regular(ROOT / INPUTS[1])
            and read_regular(source / "polaris_cronet_material_inputs.json")
            == read_regular(ROOT / INPUTS[3]), "actual source-prepared copied controller/policy")
    read_regular(source / "keyring.gpg", OBJECT_LIMIT)
    return source


def _fresh_stage(root):
    naive = Path(root).absolute() / "naiveproxy"
    raw = naive / "src/out/sysroot-build"
    require(not raw.exists() and not raw.is_symlink(), "fresh consumer/supplier raw context")
    for profile in load_profile_plan()["profiles"]:
        link = naive / "src/build/linux" / ("debian_" + profile["release"] + "_" + profile["creatorArchitecture"] + "-sysroot")
        require(not link.exists() and not link.is_symlink(), "no restored sysroot link/staging")


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, "fixed module loader")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _verify_profile_data(creator, transport, profile, build_dir):
    arch = profile["creatorArchitecture"]
    require(creator.RELEASES[arch] == profile["release"]
            and creator.TRIPLES[arch] == profile["debianTriple"]
            and creator.GCC_VERSIONS[profile["release"]] == profile["gccMajor"]
            and equal(creator.APT_SOURCES_LISTS[arch], profile["aptSources"]), "original profile globals")
    # Match the original CLI's loong64-only archive switch in its own process.
    if arch == "loong64":
        creator.ARCHIVE_URL = "https://snapshot.debian.org/archive/debian-ports/20250625T074124Z/"
    require(creator.ARCHIVE_URL == profile["archivePrefix"], "original archive")
    build_dir = new_directory(build_dir)
    selected = creator.generate_package_list(arch, str(build_dir))
    require(type(selected) is dict and len(selected) <= COUNT_LIMIT, "original selected deb closure")
    deb_dir = new_directory(build_dir / "debian-packages")
    destinations = {}
    for url, expected in selected.items():
        allowed_url(url, profile["id"], load_profile_plan())
        sha(expected)
        basename = url.rsplit("/", 1)[-1]
        require(basename not in destinations or destinations[basename] == (url, expected),
                "ambiguous original deb basename")
        destinations[basename] = (url, expected)
        destination = deb_dir / basename
        creator.download_or_copy(url, str(destination))
        require(creator.hash_file(hashlib.sha256(), str(destination)) == expected, "original selected deb SHA256")
    records = transport._CANDIDATES_USED
    receipt = {"id": profile["id"], "keyringSHA256": digest(read_regular(creator.KEYRING_FILE, OBJECT_LIMIT)),
               "selectedDebs": selected, "urls": sorted(records), "verified": True}
    validate_profile(receipt, profile["id"], load_profile_plan())
    require(sum(item["bytes"] for item in records.values()) <= UNION_LIMIT, "profile bytes")
    return receipt


def _profile_worker(root, profile_id, work, receipt):
    source = _prepared(root)
    profile = next(item for item in load_profile_plan()["profiles"] if item["id"] == profile_id)
    # -I child has no cwd/PYTHONPATH import search. Only these exact source-
    # verified modules are installed under the original import names.
    transport = _load_module("polaris_cronet_material", source / "polaris_cronet_material.py")
    _load_module("reversion_glibc", source / "reversion_glibc.py")
    creator = _load_module("_polaris_original_creator", source / "sysroot_creator.py")
    result = _verify_profile_data(creator, transport, profile, Path(work) / "build")
    write_new(receipt, encode_json(result))


def _profiles(root, profile_ids, raw_store, capture, deadline):
    results = []
    for profile_id in profile_ids:
        remaining = deadline - time.monotonic()
        require(remaining > 0, "whole preparation deadline")
        with tempfile.TemporaryDirectory(prefix="debian-profile-", dir=Path(raw_store).parent) as directory:
            work = Path(directory)
            check_directory(work, private=True)
            env = {key: value for key, value in os.environ.items()
                   if key not in ("POLARIS_CRONET_CAPTURE_DIR", "POLARIS_CRONET_CAPTURE_PROFILE",
                                  "POLARIS_CRONET_RAW_STORE", "PYTHONPATH", "PYTHONHOME")}
            env["POLARIS_CRONET_RAW_STORE"] = str(raw_store)
            if capture:
                env["POLARIS_CRONET_CAPTURE_DIR"] = str(raw_store)
                env["POLARIS_CRONET_CAPTURE_PROFILE"] = profile_id
            command = [sys.executable, "-I", "-B", str(Path(__file__).absolute()), "_profile",
                       "--cronet-root", str(root), "--profile", profile_id, "--work", str(work),
                       "--receipt", str(work / "profile.json")]
            child = subprocess.Popen(command, env=env, start_new_session=True)
            try:
                code = child.wait(timeout=min(PROFILE_SECONDS, remaining))
                require(code == 0, "original profile process failed: " + profile_id)
            finally:
                if child.poll() is None:
                    primary = sys.exc_info()[1]
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait(timeout=5)
                    except (OSError, subprocess.TimeoutExpired) as cleanup:
                        if primary is not None:
                            primary.add_note("profile process group cleanup unconfirmed")
                        else:
                            raise cleanup
            record = decode_json(read_regular(work / "profile.json"))
            validate_profile(record, profile_id, load_profile_plan())
            results.append(record)
            if capture:
                current = decode_json(read_regular(Path(raw_store) / MANIFEST))
                current["profiles"] = list(results)
                replace_json(Path(raw_store) / MANIFEST, current)
    return results


def _copy_raw_objects(raw_zip, manifest, destination):
    """Import only measured CAS bytes into newly owned fd-anchored directories."""
    release = _release()
    destination = Path(destination)
    root_identity = check_directory(destination, private=True)
    object_dir = destination / "objects"
    if not object_dir.exists():
        new_directory(object_dir)
    check_directory(object_dir, private=True)
    root_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    objects_fd = None
    allowed = {item["member"]: item for item in manifest["objects"]}
    total = 0
    try:
        objects_fd = os.open("objects", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        require(os.path.samestat(root_identity, os.fstat(root_fd)), "import root identity changed")
        with _zip(raw_zip, ZIP_LIMIT) as archive:
            members = _release().safe_zip_members(archive)
            for item in members:
                if item.filename not in allowed:
                    continue
                expected = allowed[item.filename]
                name = item.filename.split("/")[1]
                temporary = ".import-" + name
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=objects_fd)
                promoted = False
                primary = None
                try:
                    measured, size = hashlib.sha256(), 0
                    with os.fdopen(fd, "wb") as stream:
                        for chunk in release.member_chunks(archive, item):
                            size += len(chunk)
                            total += len(chunk)
                            require(size <= OBJECT_LIMIT and total <= UNION_LIMIT, "actual import bytes")
                            measured.update(chunk)
                            stream.write(chunk)
                        stream.flush()
                        os.fsync(stream.fileno())
                        require(size == expected["bytes"] and measured.hexdigest() == expected["sha256"],
                                "import actual CAS bytes")
                    require(os.path.samestat(root_identity, destination.lstat())
                            and os.path.samestat(os.fstat(objects_fd), object_dir.lstat()),
                            "import ancestor/inode changed")
                    # Same owned directory only; atomic no-clobber promotion. No
                    # archive-provided hardlink or path is ever imported.
                    os.link(temporary, name, src_dir_fd=objects_fd, dst_dir_fd=objects_fd,
                            follow_symlinks=False)
                    promoted = True
                except BaseException as error:
                    primary = error
                    raise
                finally:
                    try:
                        os.unlink(temporary, dir_fd=objects_fd)
                    except OSError as cleanup:
                        if primary is not None:
                            primary.add_note("Import temporary cleanup failed: " + type(cleanup).__name__)
                        else:
                            raise
                require(promoted and os.stat(name, dir_fd=objects_fd, follow_symlinks=False).st_nlink == 1,
                        "import final link count")
    finally:
        if objects_fd is not None:
            os.close(objects_fd)
        os.close(root_fd)


def _measure_local(directory, manifest):
    measurements = {}
    paths = {item["member"] for item in manifest["objects"]} | {MANIFEST}
    actual = set()
    for path in Path(directory).iterdir():
        if path.name == "objects":
            check_directory(path, private=True)
            for child in path.iterdir():
                require(child.name == ".keep" or re.fullmatch(r"[0-9a-f]{64}", child.name) is not None,
                        "local CAS filename")
                require(child.name != ".keep", "no placeholder CAS member")
                actual.add("objects/" + child.name)
        else:
            actual.add(path.name)
    require(actual == paths, "local exact candidate member set")
    for name in paths:
        raw = read_regular(Path(directory) / name, JSON_LIMIT if name == MANIFEST else OBJECT_LIMIT)
        measurements[name] = {"bytes": len(raw), "sha256": digest(raw)}
    return measurements


def _prune_export(directory):
    manifest = decode_json(read_regular(Path(directory) / MANIFEST))
    keep = {item["member"].split("/")[1] for item in manifest["objects"]}
    for path in (Path(directory) / "objects").iterdir():
        if path.name not in keep:
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1,
                    "unexpected export cleanup type")
            path.unlink()


def _seed_checkpoint(args, context, output):
    require(bool(args.checkpoint_artifact_id) == bool(args.checkpoint_artifact_digest),
            "checkpoint ID/digest pair")
    if not args.checkpoint_artifact_id:
        return None
    integer(args.checkpoint_artifact_id, positive=True)
    expected_digest = normalize_digest(args.checkpoint_artifact_digest)
    deadline = time.monotonic() + 120
    old = _api("actions/artifacts/" + str(args.checkpoint_artifact_id), deadline)
    require(type(old.get("id")) is int and old["id"] == args.checkpoint_artifact_id
            and artifact_ref(old)["name"] == RAW_NAME and old["digest"] == expected_digest
            and old.get("expired") is False, "explicit checkpoint ID/digest")
    workflow_run = old.get("workflow_run")
    require(type(workflow_run) is dict, "checkpoint API run")
    expected_run = {"repository_id": RID, "head_repository_id": RID,
                    "head_sha": context["sourceCommit"], "head_branch": context["tag"]}
    require(all(equal(workflow_run.get(key), value) for key, value in expected_run.items()),
            "checkpoint source/repository/ref")
    integer(workflow_run.get("id"), positive=True)
    release = _release()
    with tempfile.TemporaryDirectory(prefix="debian-checkpoint-", dir=Path(output).parent) as temporary:
        scratch = Path(temporary)
        check_directory(scratch, private=True)
        budget = release.ScratchBudget(scratch)
        with _alarm(TRANSFER_SECONDS), release.artifact_archive(old, budget) as (archive, _):
            manifest, measurements = _measure_zip(archive)
            old_context = manifest.get("context")
            validate_context(old_context)
            require(old_context["runID"] == workflow_run["id"]
                    and all(equal(old_context[key], context[key])
                            for key in CONTEXT_KEYS - {"runID", "runAttempt"}),
                    "checkpoint exact source/tag/role; actual run/attempt")
            # Attempt comes from the measured manifest, then is independently
            # checked through that exact API attempt, never guessed from latest.
            run = _run(old_context, time.monotonic() + 120)
            require(run["status"] == "completed", "checkpoint actual terminal attempt")
            _artifact(old, old_context, run, RAW_NAME)
            validate_manifest(manifest, context=old_context, measurements=measurements)
            _copy_raw_objects(archive, manifest, output)
    current = decode_json(read_regular(Path(output) / MANIFEST))
    current["objects"] = manifest["objects"]
    current["profiles"] = []
    current["state"] = "PARTIAL"
    current["seed"] = {"artifact": artifact_ref(old), "context": old_context,
                       "manifestSHA256": measurements[MANIFEST]["sha256"]}
    replace_json(Path(output) / MANIFEST, current)
    return current["seed"]

@contextmanager
def _alarm(seconds):
    # Same main-thread finite primitive as the original controller; all profile
    # work happens in separate process groups with an independent <=20m bound.
    bootstrap = _load_module("_polaris_supply_deadline", ROOT / INPUTS[1])
    with bootstrap._object_alarm(seconds):
        yield


def prepare(args):
    context = actions_context(args.role)
    _prepared(args.cronet_root)
    _fresh_stage(args.cronet_root)
    deadline = time.monotonic() + PREPARE_SECONDS
    output = new_directory(args.output)
    new_directory(output / "objects")
    manifest = {"schema": "polaris-debian-candidate-v1", "scope": SCOPE, "context": context,
                "planSHA256": profile_plan_sha256(), "requiredProfiles": required_profiles(context),
                "state": "PARTIAL", "objects": [], "profiles": [], "seed": None}
    write_new(output / MANIFEST, encode_json(manifest))
    primary = None
    try:
        _seed_checkpoint(args, context, output)
        receipts = _profiles(args.cronet_root, manifest["requiredProfiles"], output, True, deadline)
        manifest = decode_json(read_regular(output / MANIFEST))
        # Discard seed candidates not actually selected/reverified this time.
        required = {url for profile in receipts for url in profile["urls"]}
        manifest["objects"] = [item for item in manifest["objects"] if item["url"] in required]
        for item in manifest["objects"]:
            item["profiles"] = sorted(profile["id"] for profile in receipts if item["url"] in profile["urls"])
        manifest["profiles"] = receipts
        manifest["state"] = "VERIFIED"
        replace_json(output / MANIFEST, manifest)
        _prune_export(output)
        validate_manifest(manifest, context=context, measurements=_measure_local(output, manifest))
        print(encode_json({"phase": "debian_raw_verified", "profiles": manifest["requiredProfiles"],
                           "objects": len(manifest["objects"]), "manifestSHA256": digest(encode_json(manifest)),
                           "scope": SCOPE}).decode().strip())
    except BaseException as error:
        primary = error
        raise
    finally:
        if primary is not None:
            try:
                manifest = decode_json(read_regular(output / MANIFEST))
                manifest["state"] = "PARTIAL"
                replace_json(output / MANIFEST, manifest)
                _prune_export(output)
            except BaseException as cleanup:
                primary.add_note("Complete-candidate checkpoint cleanup not confirmed: " + type(cleanup).__name__)


def ready(args):
    manifest = decode_json(read_regular(Path(args.input) / MANIFEST))
    context = actions_context(manifest["context"]["role"])
    validate_manifest(manifest, context=context, measurements=_measure_local(args.input, manifest))
    require(manifest["state"] == "VERIFIED", "no READY from partial candidates")
    deadline = time.monotonic() + 120
    run = _run(context, deadline)
    supplier = _job(context, completed=False, deadline=deadline)
    raw = _select_artifact(context, args.raw_artifact_id, args.raw_artifact_digest, RAW_NAME, run, deadline)
    # The raw upload must precede READY and match the exact local export. Outer
    # ID/digest is taken from the API, never predicted or treated as GPG proof.
    release = _release()
    with tempfile.TemporaryDirectory(prefix="debian-ready-check-", dir=Path(args.output).parent) as temporary:
        scratch = Path(temporary)
        check_directory(scratch, private=True)
        with _alarm(TRANSFER_SECONDS), release.artifact_archive(raw, release.ScratchBudget(scratch)) as (archive, _):
            uploaded, measurements = _measure_zip(archive)
            validate_manifest(uploaded, context=context, measurements=measurements)
            require(equal(uploaded, manifest), "uploaded raw differs from verified local export")
    record = {"schema": "polaris-debian-ready-v1", "scope": SCOPE, "context": context,
              "planSHA256": manifest["planSHA256"], "requiredProfiles": manifest["requiredProfiles"],
              "manifestSHA256": digest(encode_json(manifest)), "rawArtifact": artifact_ref(raw),
              "supplierJob": supplier_ref(supplier, context, completed=False), "verification": VERIFICATION}
    output = new_directory(args.output)
    write_new(output / READY, encode_json(record))


def _consumer_job(context, caller, deadline):
    plan = load_profile_plan()
    expected = next(item for item in plan["callers"] if item["id"] == caller)
    require(expected["workflow"] == context["workflow"] and os.environ.get("GITHUB_JOB") == expected["job"],
            "actual consumer source-owned job key")
    runner = os.environ.get("RUNNER_NAME")
    require(type(runner) is str and runner, "actual consumer runner identity")
    rows = []
    total = None
    for page in range(1, 5):
        result = _api("actions/runs/" + str(context["runID"]) + "/attempts/"
                      + str(context["runAttempt"]) + "/jobs?per_page=100&page=" + str(page), deadline)
        integer(result.get("total_count"), 400)
        require(type(result.get("jobs")) is list and (total is None or total == result["total_count"]),
                "consumer jobs page")
        total = result["total_count"]
        rows.extend(result["jobs"])
        if len(rows) == total:
            break
        require(len(rows) < total and len(result["jobs"]) == 100, "consumer jobs pagination")
    require(len(rows) == total and len({row.get("id") for row in rows}) == total, "consumer complete unique jobs")
    matches = [row for row in rows if row.get("runner_name") == runner and row.get("status") == "in_progress"]
    require(len(matches) == 1, "unique actual current consumer")
    row = matches[0]
    integer(row.get("id"), positive=True)
    require(type(row.get("run_id")) is int and row["run_id"] == context["runID"]
            and type(row.get("run_attempt")) is int and row["run_attempt"] == context["runAttempt"]
            and row.get("head_sha") == context["sourceCommit"]
            and type(row.get("name")) is str and row["name"], "consumer actual API context")
    return {"id": row["id"], "key": expected["job"], "name": row["name"], "runner": runner}


def consume(args):
    context = actions_context(args.role)
    _prepared(args.cronet_root)
    _fresh_stage(args.cronet_root)
    require(not any(os.environ.get(key) for key in
                    ("SYSROOT_ARCH", "target_os", "target_cpu", "EXTRA_FLAGS", "OPENWRT_FLAGS")),
            "unexpected inherited target/sysroot flags")
    matches = [(name, value) for name, value in load_profile_plan()["eligibleArtifacts"][args.role].items()
               if (value["caller"], value["targetArch"], value["libc"]) == (args.caller, args.target_arch, args.libc)]
    require(len(matches) == 1, "exact source-owned consumer tuple")
    artifact_name, expected = matches[0]
    deadline = time.monotonic() + 120
    run = _run(context, deadline)
    supplier = _job(context, deadline=deadline)
    consumer = _consumer_job(context, args.caller, deadline)
    ready_metadata = _select_artifact(context, args.ready_artifact_id, args.ready_artifact_digest,
                                      READY_NAME, run, deadline)
    release = _release()
    with tempfile.TemporaryDirectory(prefix="debian-consume-", dir=Path(args.output).parent) as temporary:
        scratch = Path(temporary)
        check_directory(scratch, private=True)
        budget = release.ScratchBudget(scratch)
        with _alarm(TRANSFER_SECONDS), release.artifact_archive(ready_metadata, budget) as (ready_zip, _):
            record, ready_measurements = _measure_zip(ready_zip, ready=True)
            require(ready_measurements[READY] == {"bytes": len(encode_json(record)),
                                                "sha256": digest(encode_json(record))}, "canonical READY")
            raw_metadata = _select_artifact(context, record["rawArtifact"]["id"],
                                            record["rawArtifact"]["digest"], RAW_NAME, run, deadline)
            with release.artifact_archive(raw_metadata, budget) as (raw_zip, _):
                manifest, measurements = _measure_zip(raw_zip)
                validate_manifest(manifest, context=context, measurements=measurements)
                binding = validate_ready(record, context=context, manifest=manifest,
                                         raw_artifact=raw_metadata, supplier_job=supplier)
                binding["readyArtifact"] = artifact_ref(ready_metadata)
                output = new_directory(args.output)
                raw_store = new_directory(output / "raw")
                _copy_raw_objects(raw_zip, manifest, raw_store)
                write_new(raw_store / MANIFEST, encode_json(manifest))
        # Original reauthentication starts only after all metadata/member/path/
        # digest/type/budget checks and safe import, before original dest.exists.
        receipts = _profiles(args.cronet_root, expected["profiles"], raw_store, False,
                             time.monotonic() + PROFILE_SECONDS * len(expected["profiles"]))
    use = {"schema": "polaris-debian-use-v1", **{key: value for key, value in binding.items() if key != "schema"},
           "caller": args.caller, "targetArch": args.target_arch, "libc": args.libc,
           "profiles": receipts, "consumerJob": consumer}
    # Consumer is still running: publisher later checks its actual completed
    # SUCCESS API row. No future outcome is asserted in this local receipt.
    _validate_use_shape(use, binding=binding, ready_artifact=ready_metadata, artifact_name=artifact_name)
    write_new(output / "use.json", encode_json(use))
    print(encode_json({"phase": "consumer_original_verification", "scope": SCOPE,
                       "caller": args.caller, "profiles": expected["profiles"],
                       "rawStore": str(raw_store), "verification": VERIFICATION}).decode().strip())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    command = sub.add_parser("prepare")
    command.add_argument("--cronet-root", type=Path, required=True)
    command.add_argument("--role", choices=("all", "linux", "docker"), required=True)
    command.add_argument("--output", type=Path, required=True)
    command.add_argument("--checkpoint-artifact-id", type=int)
    command.add_argument("--checkpoint-artifact-digest")
    command = sub.add_parser("ready")
    command.add_argument("--input", type=Path, required=True)
    command.add_argument("--raw-artifact-id", type=int, required=True)
    command.add_argument("--raw-artifact-digest", required=True)
    command.add_argument("--output", type=Path, required=True)
    command = sub.add_parser("consume")
    command.add_argument("--cronet-root", type=Path, required=True)
    command.add_argument("--role", choices=("all", "linux", "docker"), required=True)
    command.add_argument("--ready-artifact-id", type=int, required=True)
    command.add_argument("--ready-artifact-digest", required=True)
    command.add_argument("--caller", choices=("C1_ALL_BINARY", "C2_ALL_LINUX_CLIENT", "C3_LINUX", "C4_DOCKER"), required=True)
    command.add_argument("--target-arch", required=True)
    command.add_argument("--libc", choices=("glibc", "musl"), required=True)
    command.add_argument("--output", type=Path, required=True)
    command = sub.add_parser("_profile", help=argparse.SUPPRESS)
    command.add_argument("--cronet-root", type=Path, required=True)
    command.add_argument("--profile", required=True)
    command.add_argument("--work", type=Path, required=True)
    command.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "_profile":
        _profile_worker(args.cronet_root, args.profile, args.work, args.receipt)
    else:
        {"prepare": prepare, "ready": ready, "consume": consume}[args.command](args)


if __name__ == "__main__":
    main()
