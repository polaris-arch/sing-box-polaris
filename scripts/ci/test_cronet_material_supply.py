"""Real protocol controls; these fixtures are not Debian cryptographic acceptance."""
import argparse
import copy
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock
import zipfile

import cronet_material_supply as supply
from scripts.ci import cronet_material_bootstrap as bootstrap
from test_cronet_material_bootstrap import (ATOMIC_COPY, DOWNLOAD_NON_UNIQUE, DOWNLOAD_OR_COPY,
                                            HASH_FILE, VERIFY_CALLER)

ORIGINAL_GENERATE = 'def generate_package_list_dist_repo(\n    arch: str, dist: str, repo_name: str, build_dir: str\n) -> list[dict[str, str]]:\n    repo_basedir = f"{ARCHIVE_URL}/dists/{dist}"\n    package_list = f"{build_dir}/Packages.{dist}_{repo_name}_{arch}"\n    package_list = f"{package_list}.{PACKAGES_EXT}"\n    package_file_arch = f"{repo_name}/binary-{arch}/Packages.{PACKAGES_EXT}"\n    package_list_arch = f"{repo_basedir}/{package_file_arch}"\n\n    download_or_copy_non_unique_filename(package_list_arch, package_list)\n    verify_package_listing(package_file_arch, package_list, dist, build_dir)\n\n    # `not line.endswith(":")` is added here to handle the case of\n    # "X-Cargo-Built-Using:\\n rust-adler (= 1.0.2-2), ..."\n    with lzma.open(package_list, "rt") as src:\n        return [\n            dict(\n                line.split(": ", 1)\n                for line in package_meta.splitlines()\n                if not line.startswith(" ") and not line.endswith(":")\n            )\n            for package_meta in src.read().split("\\n\\n")\n            if package_meta\n        ]\n\n\ndef generate_package_list(arch: str, build_dir: str) -> dict[str, str]:\n    # Workaround for some misconfigured package dependencies.\n    BROKEN_DEPS = {\n        "libgcc1",\n        "qt6-base-abi",\n        "libc-dev",  # pulls in a newer libc6-dev\n    }\n\n    package_meta = {}\n    sources = APT_SOURCES_LISTS[arch]\n    for dist, repos in sources:\n        for repo_name in repos:\n            for meta in generate_package_list_dist_repo(\n                arch, dist, repo_name, build_dir\n            ):\n                package_meta[meta["Package"]] = meta\n                if "Provides" not in meta:\n                    continue\n                for provides in meta["Provides"].split(", "):\n                    # Strip version requirements\n                    provides = provides.split()[0]\n                    if provides in package_meta:\n                        continue\n                    package_meta[provides] = meta\n\n    def add_package_dependencies(package: str) -> None:\n        if package in BROKEN_DEPS:\n            return\n        meta = package_meta[package]\n        url = ARCHIVE_URL + meta["Filename"]\n        if url in package_dict:\n            return\n        package_dict[url] = meta["SHA256"]\n        if "Depends" in meta:\n            for dep in meta["Depends"].split(", "):\n                add_package_dependencies(dep.split()[0].split(":")[0])\n\n    # Read the input file and create a dictionary mapping package names to URLs\n    # and checksums.\n    missing = set(DEBIAN_PACKAGES)\n    # Add corresponding libstdc++-dev package (needed for trixie)\n    missing.add(f"libstdc++-{GCC_VERSIONS[RELEASES[arch]]}-dev")\n    package_dict: dict[str, str] = {}\n    for package in package_meta:\n        if package in missing:\n            missing.remove(package)\n            add_package_dependencies(package)\n    if missing:\n        raise Exception(f"Missing packages: {\', \'.join(missing)}")\n\n    # Write the URLs and checksums of the requested packages to the output file\n    output_file = os.path.join(\n        SCRIPT_DIR, "generated_package_lists", f"{RELEASES[arch]}.{arch}"\n    )\n    with open(output_file, "w") as f:\n        f.write("\\n".join(sorted(package_dict)) + "\\n")\n    return package_dict\n\n'
ORIGINAL_GENERATE_SHA256 = 'b33bcc2df8815744d845e8370c74fc858da91696c9b96b95cea619cdc0bd2941'


def _zip_bytes(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
    return stream.getvalue()


def fixture_bundle(role="linux", context=None):
    """Actual ZIP bytes + independently measured typed API fixture, no GPG claim."""
    plan = supply.load_profile_plan()
    context = dict(context) if context is not None else {
        "repository": supply.REPO, "repositoryID": supply.RID,
        "sourceCommit": "a" * 40, "sourceTree": "b" * 40,
        "tag": "v1.15.0-polaris-alpha.12.14", "tagObject": "c" * 40,
        "workflow": plan["roles"][role]["workflow"], "runID": 1001, "runAttempt": 1, "role": role}
    required = supply.required_profiles(context, plan)
    payloads, memberships, profiles = {}, {}, []
    for profile_id in required:
        profile = next(item for item in plan["profiles"] if item["id"] == profile_id)
        deb = profile["archivePrefix"] + "pool/main/f/fixture/fixture_" + profile_id + ".deb"
        urls = supply.profile_urls(plan, profile_id) | {deb}
        for url in urls:
            payloads[url] = ("controlled fixture bytes " + url).encode()
            memberships.setdefault(url, []).append(profile_id)
        profiles.append({"id": profile_id, "keyringSHA256": supply.digest(b"fixture public keyring"),
                         "selectedDebs": {deb: supply.digest(payloads[deb])}, "urls": sorted(urls), "verified": True})
    objects = [{"url": url, "member": "objects/" + supply.digest(body), "sha256": supply.digest(body),
                "bytes": len(body), "profiles": sorted(memberships[url]), "complete": True}
               for url, body in sorted(payloads.items())]
    manifest = {"schema": "polaris-debian-candidate-v1", "scope": supply.SCOPE, "context": context,
                "planSHA256": supply.profile_plan_sha256(), "requiredProfiles": required,
                "state": "VERIFIED", "objects": objects, "profiles": profiles, "seed": None}
    files = {supply.MANIFEST: supply.encode_json(manifest)}
    files.update({item["member"]: payloads[item["url"]] for item in objects})
    raw_zip = _zip_bytes(files)
    def artifact(artifact_id, name, data, created):
        return {"id": artifact_id, "name": name, "digest": "sha256:" + supply.digest(data),
                "size_in_bytes": len(data), "expired": False, "created_at": created,
                "updated_at": created, "expires_at": "2099-01-01T00:00:00Z",
                "workflow_run": {"id": context["runID"], "repository_id": supply.RID,
                                 "head_repository_id": supply.RID, "head_sha": context["sourceCommit"],
                                 "head_branch": context["tag"]}}
    raw_artifact = artifact(2001, supply.RAW_NAME, raw_zip, "2020-01-01T00:00:30Z")
    supplier = {"id": 3000, "name": supply.SUPPLIER_NAME, "run_id": context["runID"],
                "run_attempt": context["runAttempt"], "head_sha": context["sourceCommit"],
                "status": "completed", "conclusion": "success", "runner_name": "Hosted supplier",
                "started_at": "2020-01-01T00:00:00Z", "completed_at": "2020-01-01T00:02:00Z"}
    ready = {"schema": "polaris-debian-ready-v1", "scope": supply.SCOPE, "context": context,
             "planSHA256": manifest["planSHA256"], "requiredProfiles": required,
             "manifestSHA256": supply.digest(files[supply.MANIFEST]),
             "rawArtifact": supply.artifact_ref(raw_artifact),
             "supplierJob": supply.supplier_ref(supplier, context), "verification": supply.VERIFICATION}
    ready_zip = _zip_bytes({supply.READY: supply.encode_json(ready)})
    ready_artifact = artifact(2002, supply.READY_NAME, ready_zip, "2020-01-01T00:01:00Z")
    measurements = {name: {"bytes": len(body), "sha256": supply.digest(body)} for name, body in files.items()}
    binding = supply.validate_ready(ready, context=context, manifest=manifest,
                                    raw_artifact=raw_artifact, supplier_job=supplier)
    binding["readyArtifact"] = supply.artifact_ref(ready_artifact)
    consumer_jobs, by_artifact = [], {}
    for number, (name, expected) in enumerate(sorted(plan["eligibleArtifacts"][role].items()), 4000):
        job = {"id": number, "name": "controlled " + expected["caller"] + " " + name,
               "runner_name": "Hosted consumer " + str(number), "run_id": context["runID"],
               "run_attempt": context["runAttempt"], "head_sha": context["sourceCommit"],
               "status": "completed", "conclusion": "success",
               "started_at": "2020-01-01T00:02:10Z", "completed_at": "2020-01-01T00:03:00Z"}
        consumer_jobs.append(job)
        by_artifact[name] = job
    return {"context": context, "manifest": manifest, "ready": ready,
            "raw_artifact": raw_artifact, "ready_artifact": ready_artifact, "supplier_job": supplier,
            "raw_zip": raw_zip, "ready_zip": ready_zip, "measurements": measurements,
            "binding": binding, "consumer_jobs": consumer_jobs, "consumer_job_by_artifact": by_artifact,
            "files": files, "payloads": payloads}


def fixture_use(bundle, artifact_name):
    expected = supply.expected_use(bundle["context"]["role"], artifact_name)
    if expected is None:
        raise ValueError("not an eligible material consumer")
    job = bundle["consumer_job_by_artifact"][artifact_name]
    caller = next(item for item in supply.load_profile_plan()["callers"] if item["id"] == expected["caller"])
    return {"schema": "polaris-debian-use-v1",
            **{key: copy.deepcopy(value) for key, value in bundle["binding"].items() if key != "schema"},
            "caller": expected["caller"], "targetArch": expected["targetArch"], "libc": expected["libc"],
            "profiles": [copy.deepcopy(next(item for item in bundle["manifest"]["profiles"] if item["id"] == profile_id))
                         for profile_id in expected["profiles"]],
            "consumerJob": {"id": job["id"], "key": caller["job"], "name": job["name"], "runner": job["runner_name"]}}


class MaterialProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def zipped(self, bundle, raw=None, ready=None):
        first, second = self.root / "raw.zip", self.root / "ready.zip"
        first.write_bytes(bundle["raw_zip"] if raw is None else raw)
        second.write_bytes(bundle["ready_zip"] if ready is None else ready)
        return first, second

    def validate(self, bundle):
        raw, ready = self.zipped(bundle)
        return supply.validate_bundle(raw, ready, raw_artifact=bundle["raw_artifact"],
                ready_artifact=bundle["ready_artifact"], context=bundle["context"], supplier_job=bundle["supplier_job"])

    def test_real_archive_measurement_and_exact_role_scope(self):
        for role, count in (("all", 18), ("linux", 7), ("docker", 7)):
            with self.subTest(role=role):
                bundle = fixture_bundle(role)
                self.assertEqual(self.validate(bundle), bundle["binding"])
                self.assertEqual(len(bundle["consumer_jobs"]), count)
                for artifact in bundle["consumer_job_by_artifact"]:
                    use = fixture_use(bundle, artifact)
                    self.assertIs(supply.validate_use_ref(use, binding=bundle["binding"],
                        ready_artifact=bundle["ready_artifact"], artifact_name=artifact,
                        consumer_job=bundle["consumer_job_by_artifact"][artifact]), use)

    def test_context_plan_and_profile_mismatches(self):
        original = fixture_bundle()
        changes = [("sourceCommit", "d" * 40), ("sourceTree", "e" * 40), ("tagObject", "f" * 40),
                   ("tag", "v1.15.0-polaris-alpha.12.13"), ("runID", 1002), ("runAttempt", 2),
                   ("repositoryID", True), ("workflow", ".github/workflows/build.yml")]
        for key, value in changes:
            with self.subTest(key=key):
                context = dict(original["context"], **{key: value})
                with self.assertRaises(ValueError):
                    supply.validate_manifest(original["manifest"], context=context, measurements=original["measurements"])
        for field, value in (("planSHA256", "0" * 64), ("requiredProfiles", []), ("state", "READY")):
            manifest = copy.deepcopy(original["manifest"])
            manifest[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                supply.validate_manifest(manifest, context=original["context"], measurements=original["measurements"])

    def test_strict_json_types_members_and_counters(self):
        bundle = fixture_bundle()
        for field, value in (("bytes", True), ("bytes", supply.OBJECT_LIMIT + 1), ("complete", 1),
                             ("member", "objects/../keyring.gpg"), ("profiles", ["unknown"])):
            manifest = copy.deepcopy(bundle["manifest"])
            manifest["objects"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                supply.validate_manifest(manifest, context=bundle["context"], measurements=bundle["measurements"])
        with self.assertRaises(ValueError):
            supply.decode_json(b'{"source":1,"source":2}')
        with self.assertRaises(ValueError):
            supply.decode_json(b'{"value":NaN}')
        measured = dict(bundle["measurements"], **{"keyring.gpg": {"bytes": 0, "sha256": "0" * 64}})
        with self.assertRaises(ValueError):
            supply.validate_manifest(bundle["manifest"], context=bundle["context"], measurements=measured)

    def test_no_ready_from_partial_or_failed_supplier(self):
        bundle = fixture_bundle()
        partial = dict(bundle["manifest"], state="PARTIAL")
        with self.assertRaises(ValueError):
            supply.validate_ready(bundle["ready"], context=bundle["context"], manifest=partial,
                    raw_artifact=bundle["raw_artifact"], supplier_job=bundle["supplier_job"])
        for status, conclusion in (("in_progress", None), ("completed", "failure"), ("completed", "cancelled"),
                                   ("completed", "skipped")):
            with self.subTest(status=status, conclusion=conclusion), self.assertRaises(ValueError):
                supply.validate_ready(bundle["ready"], context=bundle["context"], manifest=bundle["manifest"],
                    raw_artifact=bundle["raw_artifact"],
                    supplier_job=dict(bundle["supplier_job"], status=status, conclusion=conclusion))

    def test_ready_creation_has_no_future_success_cycle(self):
        bundle = fixture_bundle()
        current = dict(bundle["supplier_job"], status="in_progress", conclusion=None)
        self.assertEqual(supply.supplier_ref(current, bundle["context"], completed=False)["id"], current["id"])
        with self.assertRaises(ValueError):
            supply.supplier_ref(current, bundle["context"])
        with self.assertRaises(ValueError):
            supply.supplier_ref(bundle["supplier_job"], bundle["context"], completed=False)

    def test_same_role_wrong_artifact_job_profile_rejected(self):
        bundle = fixture_bundle("all")
        names = ["binary-linux_amd64-glibc", "binary-linux_arm64-glibc"]
        use = fixture_use(bundle, names[0])
        with self.assertRaises(ValueError):
            supply.validate_use_ref(use, binding=bundle["binding"], ready_artifact=bundle["ready_artifact"],
                    artifact_name=names[1], consumer_job=bundle["consumer_job_by_artifact"][names[1]])
        for change in ({"id": True}, {"run_id": 999}, {"run_attempt": 2}, {"head_sha": "d" * 40},
                       {"runner_name": "other"}, {"conclusion": "failure"}, {"status": "in_progress"}):
            job = dict(bundle["consumer_job_by_artifact"][names[0]], **change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                supply.validate_use_ref(use, binding=bundle["binding"], ready_artifact=bundle["ready_artifact"],
                                        artifact_name=names[0], consumer_job=job)

    def test_actual_zip_tamper_extra_path_kind_duplicate_refused(self):
        bundle = fixture_bundle()
        mutations = []
        files = dict(bundle["files"], **{"../keyring.gpg": b"bad"})
        mutations.append(_zip_bytes(files))
        mutations.append(_zip_bytes(dict(bundle["files"], **{"unlisted": b"data"})))
        member = next(name for name in bundle["files"] if name.startswith("objects/"))
        files = dict(bundle["files"])
        files[member] += b"corrupt"
        mutations.append(_zip_bytes(files))
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr(supply.MANIFEST, bundle["files"][supply.MANIFEST])
            link = zipfile.ZipInfo(member)
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, b"/tmp/escape")
        mutations.append(stream.getvalue())
        for number, raw in enumerate(mutations):
            metadata = dict(bundle["raw_artifact"], digest="sha256:" + supply.digest(raw), size_in_bytes=len(raw))
            first, second = self.zipped(bundle, raw=raw)
            with self.subTest(number=number), self.assertRaises(ValueError):
                supply.validate_bundle(first, second, raw_artifact=metadata,
                    ready_artifact=bundle["ready_artifact"], context=bundle["context"], supplier_job=bundle["supplier_job"])

    def test_exact_fd_owned_import_and_no_symlink_ancestor(self):
        bundle = fixture_bundle()
        first, second = self.zipped(bundle)
        self.validate(bundle)
        destination = supply.new_directory(self.root / "store")
        supply._copy_raw_objects(first, bundle["manifest"], destination)
        for item in bundle["manifest"]["objects"]:
            path = destination / item["member"]
            self.assertEqual(path.read_bytes(), bundle["payloads"][item["url"]])
            self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        unsafe = supply.new_directory(self.root / "unsafe")
        outside = supply.new_directory(self.root / "outside")
        (unsafe / "objects").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            supply._copy_raw_objects(first, bundle["manifest"], unsafe)
        self.assertEqual(list(outside.iterdir()), [])

    def test_mixed_seed_source_or_ready_reference_rejected(self):
        bundle = fixture_bundle()
        for change in ({"sourceCommit": "d" * 40}, {"tagObject": "e" * 40},
                       {"role": "all", "workflow": ".github/workflows/build.yml"}):
            manifest = copy.deepcopy(bundle["manifest"])
            manifest["seed"] = {"artifact": supply.artifact_ref(bundle["raw_artifact"]),
                                "context": dict(bundle["context"], **change), "manifestSHA256": "f" * 64}
            with self.subTest(change=change), self.assertRaises(ValueError):
                supply.validate_manifest(manifest, context=bundle["context"], measurements=bundle["measurements"])
        use = fixture_use(bundle, next(iter(bundle["consumer_job_by_artifact"])))
        wrong = dict(bundle["ready_artifact"], id=999)
        with self.assertRaises(ValueError):
            supply.validate_use_ref(use, binding=bundle["binding"], ready_artifact=wrong,
                artifact_name=next(iter(bundle["consumer_job_by_artifact"])),
                consumer_job=bundle["consumer_jobs"][0])


class ExplicitCheckpointTests(unittest.TestCase):
    def test_explicit_failed_generation_is_data_only_and_reauthenticated(self):
        bundle = fixture_bundle()
        old_context = bundle["context"]
        context = dict(old_context, runID=old_context["runID"] + 1)
        old_run = {"id": old_context["runID"], "run_attempt": old_context["runAttempt"],
                   "head_sha": old_context["sourceCommit"], "head_branch": old_context["tag"],
                   "event": "workflow_dispatch", "path": old_context["workflow"],
                   "repository": {"id": supply.RID, "full_name": supply.REPO},
                   "head_repository": {"id": supply.RID, "full_name": supply.REPO},
                   "run_started_at": "2020-01-01T00:00:00Z", "status": "completed", "conclusion": "failure"}
        # Real safe archive primitives run; only GitHub transport is controlled.
        release = supply._release()
        def transfer(path, sink, maximum, **kwargs):
            self.assertEqual(path, "repos/" + supply.REPO + "/actions/artifacts/2001/zip")
            self.assertLessEqual(len(bundle["raw_zip"]), maximum)
            sink.write(bundle["raw_zip"])
            return {"bytes": len(bundle["raw_zip"]), "sha256": supply.digest(bundle["raw_zip"])}
        def api(path, deadline=None):
            if path == "actions/artifacts/2001":
                return copy.deepcopy(bundle["raw_artifact"])
            if path in ("actions/runs/1001", "actions/runs/1001/attempts/1"):
                return dict(old_run)
            if path.startswith("actions/runs/1001/artifacts?"):
                return {"total_count": 1, "artifacts": [copy.deepcopy(bundle["raw_artifact"])]}
            raise AssertionError("unexpected metadata path " + path)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = supply.new_directory(root / "new-generation")
            supply.new_directory(output / "objects")
            initial = dict(bundle["manifest"], context=context, objects=[], profiles=[], state="PARTIAL")
            supply.write_new(output / supply.MANIFEST, supply.encode_json(initial))
            args = argparse.Namespace(checkpoint_artifact_id=2001,
                                      checkpoint_artifact_digest=bundle["raw_artifact"]["digest"])
            with mock.patch.object(supply, "_api", side_effect=api), \
                 mock.patch.object(release, "read_get", side_effect=transfer):
                seed = supply._seed_checkpoint(args, context, output)
            current = supply.decode_json((output / supply.MANIFEST).read_bytes())
            self.assertEqual(seed["context"], old_context)
            self.assertEqual(current["context"], context)
            self.assertEqual(current["profiles"], [])
            self.assertEqual(current["state"], "PARTIAL")
            self.assertEqual(current["objects"], bundle["manifest"]["objects"])
            self.assertFalse((output / supply.READY).exists())
            measured = supply._measure_local(output, current)
            supply.validate_manifest(current, context=context, measurements=measured)
            # The old supplier's success marker is not borrowed even when the
            # selected immutable checkpoint itself had VERIFIED state.
            with self.assertRaises(ValueError):
                supply.validate_ready(bundle["ready"], context=context, manifest=current,
                    raw_artifact=bundle["raw_artifact"], supplier_job=bundle["supplier_job"])

    def test_checkpoint_pair_is_explicit_default_empty(self):
        context = fixture_bundle()["context"]
        for artifact_id, artifact_digest in ((2001, None), (None, "a" * 64), (-1, "a" * 64)):
            args = argparse.Namespace(checkpoint_artifact_id=artifact_id, checkpoint_artifact_digest=artifact_digest)
            with self.subTest(artifact_id=artifact_id), mock.patch.object(supply, "_api") as transport:
                with self.assertRaises(ValueError):
                    supply._seed_checkpoint(args, context, Path("unused"))
                transport.assert_not_called()
        args = argparse.Namespace(checkpoint_artifact_id=None, checkpoint_artifact_digest=None)
        with mock.patch.object(supply, "_api") as transport:
            self.assertIsNone(supply._seed_checkpoint(args, context, Path("unused")))
            transport.assert_not_called()


class AnnotatedObjectTests(unittest.TestCase):
    def fake_api(self, path, deadline=None):
        oid, source, tag = "b" * 40, "a" * 40, "v1.15.0-polaris-alpha.12.14"
        if path == "git/ref/tags/" + tag:
            return {"ref": "refs/tags/" + tag, "object": {"type": "tag", "sha": oid}}
        if path == "git/tags/" + oid:
            return {"sha": oid, "tag": tag, "object": {"type": "commit", "sha": source}}
        raise AssertionError("unexpected bounded tag API " + path)

    def test_shallow_lightweight_ref_fetches_only_verified_annotated_oid(self):
        source, oid = "a" * 40, "b" * 40
        state = {"fetched": False}
        def git(root, *args, **kwargs):
            self.assertLessEqual(kwargs["_timeout"], 20)
            if args == ("cat-file", "-t", oid):
                if not state["fetched"]:
                    raise subprocess.CalledProcessError(1, ["git", *args])
                return "tag"
            if args == ("remote", "get-url", "origin"):
                return "https://github.com/" + supply.REPO
            if args == ("rev-parse", oid + "^{commit}"):
                return source
            if args == ("fetch", "--depth=1", "--no-tags", "--no-write-fetch-head", "origin", oid):
                environment = kwargs["_env"]
                auth = "AUTHORIZATION: basic " + supply.base64.b64encode(
                    b"x-access-token:unit-fixture-token-not-a-secret").decode()
                self.assertNotIn("unit-fixture-token-not-a-secret", " ".join(args))
                self.assertNotIn(auth, " ".join(args))
                self.assertEqual(environment["GIT_CONFIG_COUNT"], "3")
                self.assertEqual(
                    [(environment["GIT_CONFIG_KEY_" + str(index)],
                      environment["GIT_CONFIG_VALUE_" + str(index)]) for index in range(3)],
                    [("http.https://github.com/.extraheader", ""),
                     ("http.https://github.com/.extraheader", auth),
                     ("http.sslVerify", "true")])
                state["environment"] = environment
                state["fetched"] = True
                return ""
            raise AssertionError("unexpected local tag operation " + str(args))
        with mock.patch.dict(os.environ, {"GH_TOKEN": "unit-fixture-token-not-a-secret"}), \
             mock.patch.object(supply, "_api", side_effect=self.fake_api) as remote, \
             mock.patch.object(supply, "_git", side_effect=git):
            self.assertEqual(supply._annotated_object("v1.15.0-polaris-alpha.12.14", source), oid)
        self.assertTrue(state["fetched"])
        self.assertNotIn("GIT_CONFIG_VALUE_1", state["environment"])
        self.assertEqual(state["environment"]["GIT_CONFIG_VALUE_0"], "")
        self.assertEqual(state["environment"]["GIT_CONFIG_VALUE_2"], "true")
        self.assertEqual(remote.call_count, 4)

    def test_wrong_local_object_type_or_moved_remote_remains_fatal(self):
        source = "a" * 40
        with mock.patch.object(supply, "_api", side_effect=self.fake_api), \
             mock.patch.object(supply, "_git", return_value="commit"):
            with self.assertRaises(ValueError):
                supply._annotated_object("v1.15.0-polaris-alpha.12.14", source)


class OriginalAuthenticationTests(unittest.TestCase):
    def test_original_gpgv_packages_deb_chain_and_self_consistent_poison(self):
        # Source's complete Python discovery is Linux-only. No authentication is
        # mocked here; the temporary key signs real compressed Package hashes.
        self.assertIsNotNone(shutil.which("gpg"))
        self.assertIsNotNone(shutil.which("gpgv"))
        self.assertEqual(supply.digest(ORIGINAL_GENERATE.encode()), ORIGINAL_GENERATE_SHA256)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = supply.new_directory(root / "gnupg")
            command = ["gpg", "--homedir", str(home), "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]
            subprocess.run(command + ["--quick-generate-key", "MS08 offline fixture <ms08@example.invalid>",
                                      "ed25519", "sign", "0"], check=True, timeout=60,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                keyring = root / "keyring.gpg"
                subprocess.run(command + ["--output", str(keyring), "--export"], check=True, timeout=30,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                plan = supply.load_profile_plan()
                profile = next(item for item in plan["profiles"] if item["id"] == "bullseye-amd64")
                base = profile["archivePrefix"]
                debs = {
                    base + "pool/main/f/fixture/libc6-dev_1_amd64.deb": b"controlled libc6-dev raw body",
                    base + "pool/main/f/fixture/libc6_1_amd64.deb": b"controlled libc6 raw body",
                    base + "pool/main/f/fixture/libstdc++-10-dev_1_amd64.deb": b"controlled libstdc++ raw body"}
                package_blocks = []
                for url, body in debs.items():
                    filename = url[len(base):]
                    name = filename.rsplit("/", 1)[1].split("_", 1)[0]
                    block = "Package: " + name + "\nFilename: " + filename + "\nSHA256: " + supply.digest(body) + "\n"
                    if name == "libc6-dev":
                        block += "Depends: libc6\n"
                    package_blocks.append(block)
                packages = lzma.compress(("\n".join(package_blocks) + "\n").encode())
                release = ("SHA256:\n" + "".join(
                    " " + supply.digest(packages) + " " + str(len(packages)) + " " + repo
                    + "/binary-amd64/Packages.xz\n" for repo in ("main", "contrib", "non-free"))).encode()
                release_file = root / "Release"
                release_file.write_bytes(release)
                signature_file = root / "Release.gpg"
                subprocess.run(command + ["--output", str(signature_file), "--detach-sign", str(release_file)],
                               check=True, timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                signature = signature_file.read_bytes()
                originals = {}
                for url in supply.profile_urls(plan, profile["id"]):
                    originals[url] = signature if url.endswith("Release.gpg") else (
                        release if url.endswith("/Release") else packages)
                originals.update(debs)
                for poison in ("none", "signature", "packages", "deb"):
                    with self.subTest(poison=poison):
                        trial = supply.new_directory(root / poison)
                        helper = supply.new_directory(trial / "helper")
                        supply.new_directory(helper / "generated_package_lists")
                        store = supply.new_directory(trial / "raw")
                        supply.new_directory(store / "objects")
                        payloads = dict(originals)
                        if poison == "signature":
                            for url in payloads:
                                if url.endswith("/Release"):
                                    payloads[url] += b"authenticated body changed\n"
                        elif poison == "packages":
                            for url in payloads:
                                if url.endswith("Packages.xz"):
                                    payloads[url] = b"self-consistent wrong compressed bytes"
                        elif poison == "deb":
                            payloads[next(iter(debs))] += b"corrupt raw deb"
                        objects = []
                        for url, body in sorted(payloads.items()):
                            sha = supply.digest(body)
                            member = "objects/" + sha
                            target = store / member
                            if not target.exists():
                                supply.write_new(target, body)
                            objects.append({"url": url, "member": member, "sha256": sha, "bytes": len(body),
                                            "profiles": [profile["id"]], "complete": True})
                        fixture = fixture_bundle()
                        manifest = dict(fixture["manifest"], state="PARTIAL", objects=objects, profiles=[])
                        supply.write_new(store / supply.MANIFEST, supply.encode_json(manifest))
                        # All poison bytes have valid storage hashes: only the
                        # original actual GPG/Packages/deb chain can reject them.
                        supply.validate_manifest(manifest, context=fixture["context"],
                                                  measurements=supply._measure_local(store, manifest))
                        namespace = {"os": os, "re": __import__("re"), "shutil": shutil, "tempfile": tempfile,
                                     "hashlib": hashlib, "subprocess": subprocess, "lzma": lzma,
                                     "ARCHIVE_URL": base, "SCRIPT_DIR": str(helper), "KEYRING_FILE": str(keyring),
                                     "RELEASE_FILE": "Release", "RELEASE_FILE_GPG": "Release.gpg",
                                     "PACKAGES_EXT": "xz", "DEBIAN_PACKAGES": ["libc6-dev"],
                                     "RELEASES": {"amd64": "bullseye"}, "TRIPLES": {"amd64": "x86_64-linux-gnu"},
                                     "GCC_VERSIONS": {"bullseye": 10},
                                     "APT_SOURCES_LISTS": {"amd64": profile["aptSources"]},
                                     "download_file": lambda url, dest: bootstrap.download_file(url, dest, object())}
                        exec(ATOMIC_COPY + DOWNLOAD_NON_UNIQUE + DOWNLOAD_OR_COPY + HASH_FILE
                             + VERIFY_CALLER + ORIGINAL_GENERATE, namespace)
                        creator = SimpleNamespace(**namespace)
                        with mock.patch.dict(os.environ, {"POLARIS_CRONET_RAW_STORE": str(store)}), \
                             mock.patch.object(bootstrap, "_CHARGED", 0), \
                             mock.patch.object(bootstrap, "_CANDIDATES_USED", {}), \
                             mock.patch.object(subprocess, "run", wraps=subprocess.run) as real_process:
                            os.environ.pop("POLARIS_CRONET_CAPTURE_DIR", None)
                            os.environ.pop("POLARIS_CRONET_CAPTURE_PROFILE", None)
                            if poison == "none":
                                receipt = supply._verify_profile_data(creator, bootstrap, profile, trial / "build")
                                self.assertIs(receipt["verified"], True)
                                self.assertEqual(receipt["selectedDebs"], {url: supply.digest(body) for url, body in debs.items()})
                            else:
                                if poison == "signature":
                                    with self.assertRaises(subprocess.CalledProcessError):
                                        supply._verify_profile_data(creator, bootstrap, profile, trial / "build")
                                elif poison == "packages":
                                    with self.assertRaisesRegex(Exception, "Checksum mismatch"):
                                        supply._verify_profile_data(creator, bootstrap, profile, trial / "build")
                                else:
                                    with self.assertRaisesRegex(ValueError, "original selected deb SHA256"):
                                        supply._verify_profile_data(creator, bootstrap, profile, trial / "build")
                            self.assertTrue(real_process.call_args_list)
                            self.assertTrue(all(call.args[0][0] == "gpgv" for call in real_process.call_args_list))
            finally:
                subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"], check=True, timeout=10,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    unittest.main()
