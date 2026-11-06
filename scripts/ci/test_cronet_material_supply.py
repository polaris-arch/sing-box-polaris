"""Real protocol controls; these fixtures are not Debian cryptographic acceptance."""
import argparse
import copy
from contextlib import contextmanager
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
                                            HASH_FILE, VERIFY_CALLER, Requests, Response, SSLError)

ORIGINAL_GENERATE = 'def generate_package_list_dist_repo(\n    arch: str, dist: str, repo_name: str, build_dir: str\n) -> list[dict[str, str]]:\n    repo_basedir = f"{ARCHIVE_URL}/dists/{dist}"\n    package_list = f"{build_dir}/Packages.{dist}_{repo_name}_{arch}"\n    package_list = f"{package_list}.{PACKAGES_EXT}"\n    package_file_arch = f"{repo_name}/binary-{arch}/Packages.{PACKAGES_EXT}"\n    package_list_arch = f"{repo_basedir}/{package_file_arch}"\n\n    download_or_copy_non_unique_filename(package_list_arch, package_list)\n    verify_package_listing(package_file_arch, package_list, dist, build_dir)\n\n    # `not line.endswith(":")` is added here to handle the case of\n    # "X-Cargo-Built-Using:\\n rust-adler (= 1.0.2-2), ..."\n    with lzma.open(package_list, "rt") as src:\n        return [\n            dict(\n                line.split(": ", 1)\n                for line in package_meta.splitlines()\n                if not line.startswith(" ") and not line.endswith(":")\n            )\n            for package_meta in src.read().split("\\n\\n")\n            if package_meta\n        ]\n\n\ndef generate_package_list(arch: str, build_dir: str) -> dict[str, str]:\n    # Workaround for some misconfigured package dependencies.\n    BROKEN_DEPS = {\n        "libgcc1",\n        "qt6-base-abi",\n        "libc-dev",  # pulls in a newer libc6-dev\n    }\n\n    package_meta = {}\n    sources = APT_SOURCES_LISTS[arch]\n    for dist, repos in sources:\n        for repo_name in repos:\n            for meta in generate_package_list_dist_repo(\n                arch, dist, repo_name, build_dir\n            ):\n                package_meta[meta["Package"]] = meta\n                if "Provides" not in meta:\n                    continue\n                for provides in meta["Provides"].split(", "):\n                    # Strip version requirements\n                    provides = provides.split()[0]\n                    if provides in package_meta:\n                        continue\n                    package_meta[provides] = meta\n\n    def add_package_dependencies(package: str) -> None:\n        if package in BROKEN_DEPS:\n            return\n        meta = package_meta[package]\n        url = ARCHIVE_URL + meta["Filename"]\n        if url in package_dict:\n            return\n        package_dict[url] = meta["SHA256"]\n        if "Depends" in meta:\n            for dep in meta["Depends"].split(", "):\n                add_package_dependencies(dep.split()[0].split(":")[0])\n\n    # Read the input file and create a dictionary mapping package names to URLs\n    # and checksums.\n    missing = set(DEBIAN_PACKAGES)\n    # Add corresponding libstdc++-dev package (needed for trixie)\n    missing.add(f"libstdc++-{GCC_VERSIONS[RELEASES[arch]]}-dev")\n    package_dict: dict[str, str] = {}\n    for package in package_meta:\n        if package in missing:\n            missing.remove(package)\n            add_package_dependencies(package)\n    if missing:\n        raise Exception(f"Missing packages: {\', \'.join(missing)}")\n\n    # Write the URLs and checksums of the requested packages to the output file\n    output_file = os.path.join(\n        SCRIPT_DIR, "generated_package_lists", f"{RELEASES[arch]}.{arch}"\n    )\n    with open(output_file, "w") as f:\n        f.write("\\n".join(sorted(package_dict)) + "\\n")\n    return package_dict\n\n'
ORIGINAL_GENERATE_SHA256 = 'b33bcc2df8815744d845e8370c74fc858da91696c9b96b95cea619cdc0bd2941'

# Recovered mandatory Filename URLs from the exact 20250625 sid index. Bodies
# below remain controlled fixtures, not Debian package or product acceptance.
SID_LIBC6_DEV_URL = ("https://snapshot.debian.org/archive/debian-ports/20250625T074124Z/"
                    "pool-loong64/main/g/glibc/libc6-dev_2.41-9_loong64.deb")
SID_LIBSTDCPP13_DEV_URL = ("https://snapshot.debian.org/archive/debian-ports/20250625T074124Z/"
                         "pool-loong64/main/g/gcc-13/libstdc++-13-dev_13.4.0-1_loong64.deb")
SID_ALL_DEP_URL = ("https://snapshot.debian.org/archive/debian-ports/20250625T074124Z/"
                   "pool/main/f/fixture/architecture-all_1_all.deb")


def _zip_bytes(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
    return stream.getvalue()


def fixture_bundle(role="linux", context=None, authenticated=None):
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
        receipt, originals = authenticated if authenticated is not None else (None, {})
        actual = receipt is not None and receipt["id"] == profile_id
        debs = (set(receipt["selectedDebs"]) if actual else
                {SID_LIBC6_DEV_URL, SID_LIBSTDCPP13_DEV_URL, SID_ALL_DEP_URL}
                if profile_id == "sid-loong64" else
                {profile["archivePrefix"] + "pool/main/f/fixture/fixture_" + profile_id + ".deb"})
        urls = supply.profile_urls(plan, profile_id) | debs
        for url in urls:
            payloads[url] = originals[url] if actual else ("controlled fixture bytes " + url).encode()
            memberships.setdefault(url, []).append(profile_id)
        profiles.append(copy.deepcopy(receipt) if actual else
                        {"id": profile_id, "keyringSHA256": supply.digest(b"fixture public keyring"),
                         "selectedDebs": {deb: supply.digest(payloads[deb]) for deb in sorted(debs)},
                         "urls": sorted(urls), "verified": True})
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
            "consumerJob": {"id": job["id"], "key": expected.get("job", caller["job"]), "name": job["name"], "runner": job["runner_name"]}}


def fixture_local_use(bundle, artifact_name):
    """Subset wire data from a measured fixture; no new authentication claim."""
    expected = supply.expected_use(bundle["context"]["role"], artifact_name)
    manifest = copy.deepcopy(bundle["manifest"])
    subset = set(expected["profiles"])
    manifest.update(schema=supply.LOCAL_MANIFEST, requiredProfiles=expected["profiles"])
    manifest["profiles"] = [profile for profile in manifest["profiles"] if profile["id"] in subset]
    manifest["objects"] = [item for item in manifest["objects"] if subset.intersection(item["profiles"])]
    for item in manifest["objects"]:
        item["profiles"] = sorted(subset.intersection(item["profiles"]))
    remote = fixture_use(bundle, artifact_name)
    return {"schema": supply.LOCAL_USE, "scope": supply.SCOPE, "acquisition": "local-original",
            "context": copy.deepcopy(bundle["context"]), "planSHA256": manifest["planSHA256"],
            "artifact": artifact_name, "caller": expected["caller"], "targetArch": expected["targetArch"],
            "libc": expected["libc"], "requiredProfiles": list(expected["profiles"]),
            "manifestSHA256": supply.digest(supply.encode_json(manifest)), "manifest": manifest,
            "verification": supply.VERIFICATION, "consumerJob": remote["consumerJob"]}


class LocalOriginalUseTests(unittest.TestCase):
    def run_local(self, bundle, artifact, output, verify=None):
        wire = fixture_local_use(bundle, artifact)
        expected = supply.expected_use(bundle["context"]["role"], artifact)
        def seed(args, context, store, *, profiles, prepared):
            self.assertIs(prepared, True)
            self.assertEqual(profiles, expected["profiles"])
            manifest = supply.decode_json(supply.read_regular(store / supply.MANIFEST))
            manifest["objects"] = copy.deepcopy(wire["manifest"]["objects"])
            for item in manifest["objects"]:
                path = store / item["member"]
                if not path.exists():
                    supply.write_new(path, bundle["payloads"][item["url"]])
            supply.replace_json(store / supply.MANIFEST, manifest)
        def capture(root, profiles, store, enabled, deadline):
            self.assertIs(enabled, False)
            self.assertEqual(profiles, expected["profiles"])
            return (verify(store, profiles) if verify is not None else copy.deepcopy(wire["manifest"]["profiles"]))
        args = argparse.Namespace(cronet_root=output.parent, role=bundle["context"]["role"],
            caller=expected["caller"], target_arch=expected["targetArch"], libc=expected["libc"], output=output,
            checkpoint_artifact_id=bundle["raw_artifact"]["id"],
            checkpoint_artifact_digest=bundle["raw_artifact"]["digest"])
        with mock.patch.dict(os.environ, {"GITHUB_JOB":wire["consumerJob"]["key"]}, clear=True), \
             mock.patch.object(supply, "actions_context", return_value=bundle["context"]), \
             mock.patch.object(supply, "_prepared"), mock.patch.object(supply, "_fresh_stage"), \
             mock.patch.object(supply, "_consumer_job", return_value=wire["consumerJob"]), \
             mock.patch.object(supply, "_seed_checkpoint", side_effect=seed), \
             mock.patch.object(supply, "_profiles", side_effect=capture):
            supply.consume_local(args)
        use = supply.decode_json(supply.read_regular(output / "use.json"))
        self.validate(bundle, artifact, use)
        return use

    def validate(self, bundle, artifact, use):
        return supply.validate_use_ref(use, binding=bundle["binding"], ready_artifact=bundle["ready_artifact"],
            artifact_name=artifact, consumer_job=bundle["consumer_job_by_artifact"][artifact],
            canonical_manifest=bundle["manifest"])

    def test_all_source_owned_subsets_join_exact_canonical_cas(self):
        counts = {"all": (18, 27), "linux": (7, 7), "docker": (7, 7)}
        for role, (rows, profiles) in counts.items():
            bundle = fixture_bundle(role)
            names = supply.load_profile_plan()["eligibleArtifacts"][role]
            self.assertEqual(len(names), rows)
            self.assertEqual(sum(len(value["profiles"]) for value in names.values()), profiles)
            for artifact in names:
                use = fixture_local_use(bundle, artifact)
                self.assertIs(self.validate(bundle, artifact, use), use)
                self.assertNotIn("readyArtifact", use)
                self.assertNotIn("rawArtifact", use)
                self.assertNotIn("supplierJob", use)
                # A subset wire record must never be accepted as canonical v1.
                with self.assertRaises(ValueError):
                    supply.validate_manifest(use["manifest"], context=use["context"], measurements={})

    def test_local_entry_measures_cas_and_toolchain_has_no_origin_fallback(self):
        bundle = fixture_bundle("all")
        before = dict(os.environ)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "consumer"
            use = self.run_local(bundle, "binary-linux_arm64-glibc", output)
            self.assertEqual(use["requiredProfiles"], ["bullseye-amd64", "bullseye-arm64"])
            with mock.patch.dict(os.environ, {"POLARIS_CRONET_RAW_STORE":str(output / "raw")}, clear=True):
                unknown = next(p for p in supply.load_profile_plan()["profiles"] if p["id"] == "sid-loong64")
                with self.assertRaisesRegex(bootstrap.MaterialError, "CANDIDATE_REQUIRED_MISSING"):
                    bootstrap._reuse_candidate(unknown["archivePrefix"] + "pool/main/x/not-selected.deb",
                                               output / "missing", bootstrap.load_policy())
            self.assertEqual(dict(os.environ), before)

    def test_local_cli_requires_candidate_pair_and_rejects_ready_or_profile_override(self):
        common = ["--cronet-root", "/fixture", "--role", "linux", "--caller", "C3_LINUX",
                  "--target-arch", "amd64", "--libc", "musl", "--output", "/fixture-out"]
        for command, extra in [("consume", []), ("consume-local", ["--ready-artifact-id", "1"]),
                               ("consume-local", ["--checkpoint-artifact-id", "1"]),
                               ("consume-local", ["--profiles", "sid-loong64"])]:
            with self.subTest(command=command, extra=extra), \
                 mock.patch("sys.argv", ["cronet_material_supply.py", command, *common, *extra]), \
                 self.assertRaises(SystemExit), mock.patch.object(supply, "_prepared") as prepared:
                supply.main()
            prepared.assert_not_called()
        with mock.patch("sys.argv", ["cronet_material_supply.py", "consume-local", *common,
                         "--checkpoint-artifact-id", "2001", "--checkpoint-artifact-digest", "a" * 64]), \
             mock.patch.object(supply, "consume_local") as consume:
            supply.main()
        self.assertEqual(consume.call_args.args[0].checkpoint_artifact_id, 2001)
        self.assertEqual(consume.call_args.args[0].checkpoint_artifact_digest, "a" * 64)

    def test_local_entry_rejects_inherited_capture_before_any_worker(self):
        bundle = fixture_bundle("linux")
        args = argparse.Namespace(cronet_root="/fixture", role="linux", caller="C3_LINUX",
                                  target_arch="amd64", libc="musl", output="/unused")
        for name in ("POLARIS_CRONET_CAPTURE_DIR", "POLARIS_CRONET_CAPTURE_PROFILE", "POLARIS_CRONET_RAW_STORE"):
            with mock.patch.dict(os.environ, {"GITHUB_JOB":"build", name:"/inherited"}, clear=True), \
                 mock.patch.object(supply, "actions_context", return_value=bundle["context"]), \
                 mock.patch.object(supply, "_prepared"), mock.patch.object(supply, "_fresh_stage"), \
                 mock.patch.object(supply, "_profiles") as worker, \
                 self.assertRaisesRegex(ValueError, "fresh local consumer environment"):
                supply.consume_local(args)
            worker.assert_not_called()

    def test_local_canonical_join_rejects_self_consistent_poison_and_missing_authority(self):
        bundle = fixture_bundle("all")
        artifact = "binary-linux_loong64-glibc"
        original = fixture_local_use(bundle, artifact)
        mutations = [
            lambda u:u.update(acquisition="remote-ready"),
            lambda u:u.update(schema="unknown-local"),
            lambda u:u.update(artifact="binary-linux_amd64-glibc"),
            lambda u:u.update(caller="C2_ALL_LINUX_CLIENT"),
            lambda u:u.update(targetArch="amd64"),
            lambda u:u.update(libc="musl"),
            lambda u:u.update(planSHA256="f"*64),
            lambda u:u["context"].update(sourceCommit="f"*40),
            lambda u:u["context"].update(sourceTree="f"*40),
            lambda u:u["context"].update(tag="v1.15.0-polaris-alpha.12.15"),
            lambda u:u["context"].update(role="linux"),
            lambda u:u["context"].update(runAttempt=2),
            lambda u:u["consumerJob"].update(key="build_windows"),
            lambda u:u["consumerJob"].update(id=True),
            lambda u:u["manifest"].update(objects=u["manifest"]["objects"][:-1]),
            lambda u:u["manifest"]["objects"][0].update(bytes=67108865),
            lambda u:u["manifest"]["objects"][0].update(bytes=True),
            lambda u:u["manifest"]["objects"][0].update(member="objects/../alias"),
            lambda u:u["manifest"]["objects"][0].update(bytes=u["manifest"]["objects"][0]["bytes"]+1),
            lambda u:u["manifest"]["objects"][0].update(profiles=[]),
            lambda u:u["manifest"].update(profiles=[]),
            lambda u:u["manifest"].update(seed={}),
            lambda u:u.pop("manifestSHA256")]
        for mutate in mutations:
            use = copy.deepcopy(original)
            mutate(use)
            if "manifestSHA256" in use:
                use["manifestSHA256"] = supply.digest(supply.encode_json(use["manifest"]))
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.validate(bundle, artifact, use)
        with self.assertRaises(ValueError):
            supply.validate_use_ref(original, binding=bundle["binding"], ready_artifact=bundle["ready_artifact"],
                artifact_name=artifact, consumer_job=bundle["consumer_job_by_artifact"][artifact])
        partial = copy.deepcopy(bundle)
        partial["manifest"]["state"] = "PARTIAL"
        partial["binding"]["manifestSHA256"] = supply.digest(supply.encode_json(partial["manifest"]))
        with self.assertRaisesRegex(ValueError, "independent full canonical manifest required"):
            self.validate(partial, artifact, original)
        different = copy.deepcopy(original)
        different["manifest"]["profiles"][0]["keyringSHA256"] = "f"*64
        different["manifestSHA256"] = supply.digest(supply.encode_json(different["manifest"]))
        self.validate(bundle, artifact, different)
        for status in ("in_progress", "queued", "cancelled"):
            bad = copy.deepcopy(bundle)
            bad["consumer_job_by_artifact"][artifact].update(status=status)
            with self.subTest(status=status), self.assertRaises(ValueError):
                self.validate(bad, artifact, original)
        failed = copy.deepcopy(bundle)
        failed["consumer_job_by_artifact"][artifact].update(conclusion="failure")
        with self.assertRaises(ValueError):
            self.validate(failed, artifact, original)

    def test_exact_docker_job_and_no_nonconsumer_local_entry(self):
        plan = supply.load_profile_plan()
        jobs = {"amd64":"build_binary", "arm64":"build_binary_arm64", "386":"build_binary_386",
                "arm":"build_binary_armv7", "mipsle":"build_binary_mipsle",
                "riscv64":"build_binary_riscv64", "loong64":"build_binary_loong64"}
        for artifact, entry in plan["eligibleArtifacts"]["docker"].items():
            with mock.patch.dict(os.environ, {"GITHUB_JOB": jobs[entry["targetArch"]]}):
                self.assertEqual(supply.resolve_consumer("docker", "C4_DOCKER", entry["targetArch"], "musl")[0], artifact)
            with mock.patch.dict(os.environ, {"GITHUB_JOB":"build_binary_s390x"}), self.assertRaises(ValueError):
                supply.resolve_consumer("docker", "C4_DOCKER", entry["targetArch"], "musl")
        with mock.patch.dict(os.environ, {"GITHUB_JOB":"build"}), self.assertRaises(ValueError):
            supply.resolve_consumer("all", "C1_ALL_BINARY", "amd64", "purego")
        with mock.patch.dict(os.environ, {"GITHUB_JOB":"build_binary_s390x"}), self.assertRaises(ValueError):
            supply.resolve_consumer("docker", "C4_DOCKER", "s390x", "musl")


class ProfileURLTests(unittest.TestCase):
    def test_exact_sid_roots_and_all_architecture_pool_are_admitted(self):
        plan = supply.load_profile_plan()
        for url in (SID_LIBC6_DEV_URL, SID_LIBSTDCPP13_DEV_URL, SID_ALL_DEP_URL):
            with self.subTest(url=url):
                supply.allowed_url(url, "sid-loong64", plan)
        for profile in plan["profiles"]:
            for url in supply.profile_urls(plan, profile["id"]) | {
                    profile["archivePrefix"] + "pool/main/f/fixture/lib_1:2+3~4_all.deb",
                    profile["archivePrefix"] + "pool/main/f/fixture/lib_1%3A2%2B3~4_all.deb"}:
                with self.subTest(profile=profile["id"], url=url):
                    supply.allowed_url(url, profile["id"], plan)

    def test_ports_namespace_cannot_be_borrowed_by_other_profiles_or_archives(self):
        plan = supply.load_profile_plan()
        for profile in plan["profiles"]:
            if profile["id"] == "sid-loong64":
                continue
            for url in (SID_LIBC6_DEV_URL,
                        profile["archivePrefix"] + "pool-loong64/main/f/fixture/lib_1_all.deb"):
                with self.subTest(profile=profile["id"], url=url), \
                     self.assertRaisesRegex(ValueError, "logical URL/profile archive"):
                    supply.allowed_url(url, profile["id"], plan)
        for field, value in (("id", "sid-other"), ("creatorArchitecture", "amd64"),
                             ("archivePrefix", "https://snapshot.debian.org/archive/debian-ports/20250626T074124Z/"),
                             ("archivePrefix", "https://snapshot.debian.org/archive/debian/20250625T074124Z/"),
                             ("archivePrefix", "https://snapshot-cloudflare.debian.org/archive/debian-ports/20250625T074124Z/")):
            changed = copy.deepcopy(plan)
            sid = next(p for p in changed["profiles"] if p["id"] == "sid-loong64")
            sid[field] = value
            url = sid["archivePrefix"] + "pool-loong64/main/f/fixture/lib_1_loong64.deb"
            with self.subTest(field=field, value=value), \
                 self.assertRaisesRegex(ValueError, "logical URL/profile archive"):
                supply.allowed_url(url, sid["id"], changed)

    def test_both_namespaces_retain_identical_path_and_encoding_guards(self):
        plan = supply.load_profile_plan()
        base = "https://snapshot.debian.org/archive/debian-ports/20250625T074124Z/"
        for directory in ("pool/", "pool-loong64/"):
            for relative in ("main//lib.deb", "main/./lib.deb", "main/../lib.deb",
                             "main/lib\\bad.deb", "main/%2f/lib.deb", "main/%2F/lib.deb",
                             "main/%5c/lib.deb", "main/%5C/lib.deb", "main/%2e/lib.deb",
                             "main/%2E/lib.deb", "main/lib.deb?query", "main/lib.deb#fragment",
                             "main/lib.tar", "main/lib.deb/"):
                with self.subTest(directory=directory, relative=relative), \
                     self.assertRaisesRegex(ValueError, "logical deb URL spelling"):
                    supply.allowed_url(base + directory + relative, "sid-loong64", plan)
            for filename in ("lib_1:2+3~4_loong64.deb", "lib_1%3A2%2B3~4_loong64.deb"):
                supply.allowed_url(base + directory + "main/f/fixture/" + filename, "sid-loong64", plan)
        for url in (base + "pool-loong64evil/main/lib.deb", base + "pool-other/main/lib.deb",
                    SID_LIBC6_DEV_URL.replace("https:", "http:", 1),
                    SID_LIBC6_DEV_URL.replace("snapshot.debian.org", "example.invalid", 1),
                    SID_LIBC6_DEV_URL.replace("snapshot.debian.org", "user@snapshot.debian.org", 1),
                    SID_LIBC6_DEV_URL.replace("snapshot.debian.org", "snapshot.debian.org:443", 1),
                    SID_LIBC6_DEV_URL.replace("20250625T074124Z", "20250626T074124Z", 1)):
            with self.subTest(url=url), self.assertRaisesRegex(ValueError, "logical URL/profile archive"):
                supply.allowed_url(url, "sid-loong64", plan)
        sid_metadata = sorted(supply.profile_urls(plan, "sid-loong64"))[0]
        for url, profile_id in ((sid_metadata.replace("//dists/", "/dists/"), "sid-loong64"),
                                (sid_metadata, "bullseye-amd64")):
            with self.subTest(url=url, profile=profile_id), \
                 self.assertRaisesRegex(ValueError, "logical URL/profile archive"):
                supply.allowed_url(url, profile_id, plan)


class SidTransportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.dest = self.root / "result"
        self.dest.write_bytes(b"previous verified body")

    def request(self, logical, requests, policy=None, charged=0):
        flags = {key: "" for key in ("POLARIS_CRONET_RAW_STORE", "POLARIS_CRONET_CAPTURE_DIR",
                                     "POLARIS_CRONET_CAPTURE_PROFILE")}
        with mock.patch.dict(os.environ, flags), \
             mock.patch.object(bootstrap, "_CHARGED", charged), \
             mock.patch.object(bootstrap, "_LOG_BYTES", 0), \
             mock.patch.object(bootstrap, "load_policy", return_value=policy or bootstrap.load_policy()):
            bootstrap.download_file(logical, self.dest, requests)
            return bootstrap._CHARGED

    def test_both_sid_directories_keep_approved_redirects_and_filename_labels(self):
        base = "https://snapshot.debian.org/archive/debian-ports/20250625T074124Z/"
        cases = [(SID_LIBC6_DEV_URL, "libc6-dev_2.41-9_loong64.deb"),
                 (SID_LIBSTDCPP13_DEV_URL, "libstdc%2B%2B-13-dev_13.4.0-1_loong64.deb"),
                 (SID_ALL_DEP_URL, "architecture-all_1_all.deb")]
        for directory in ("pool/", "pool-loong64/"):
            for basename in ("libfixture_1:2+build1_loong64.deb", "libfixture_1%3A2%2Bbuild1_loong64.deb"):
                cases.append((base + directory + "main/f/fixture/" + basename,
                              "libfixture_1%3A2%2Bbuild1_loong64.deb"))
        for logical, label in cases:
            mirror = logical.replace("snapshot.debian.org", "snapshot-cloudflare.debian.org", 1)
            path = "/file/" + "a" * 40 + "/" + label
            responses = [Response(status=302, headers={"Location": mirror}),
                         Response(status=302, headers={"Location": path}),
                         Response(body=b"done", headers={"Content-Length": "4"})]
            requests = Requests(*responses)
            with self.subTest(logical=logical):
                supply.allowed_url(logical, "sid-loong64", supply.load_profile_plan())
                self.assertEqual(self.request(logical, requests), 4)
                self.assertEqual(self.dest.read_bytes(), b"done")
                self.assertEqual([url for url, _ in requests.calls],
                    [logical, mirror, "https://snapshot-cloudflare.debian.org" + path])
                self.assertTrue(all(r.closed for r in responses))
                self.assertTrue(all(not kwargs["allow_redirects"] for _, kwargs in requests.calls))

    def test_both_sid_directories_keep_redirect_rejections_and_four_request_cap(self):
        base = "https://snapshot.debian.org/archive/debian-ports/20250625T074124Z/"
        for directory in ("pool/", "pool-loong64/"):
            logical = base + directory + "main/f/fixture/lib_1:2+3_loong64.deb"
            path = "/file/" + "a" * 40 + "/lib_1%3A2%2B3_loong64.deb"
            invalid = [(path.replace("lib_1%3A2%2B3", "other"), "REDIRECT_IDENTITY"),
                       (path.replace("%2B", "%252B"), "REDIRECT_IDENTITY"),
                       (path.replace("lib_", "%2flib_"), "REDIRECT_IDENTITY"),
                       ("https://example.invalid" + path, "URL_AUTHORITY_OR_QUERY"),
                       ("http://snapshot.debian.org" + path, "URL_AUTHORITY_OR_QUERY"),
                       (logical.replace("20250625T074124Z", "20250626T074124Z"), "REDIRECT_IDENTITY"),
                       (logical.replace("/main/", "/other/"), "REDIRECT_IDENTITY"),
                       (path + "?query", "URL_AUTHORITY_OR_QUERY"),
                       (path + "#fragment", "URL_AUTHORITY_OR_QUERY")]
            for location, code in invalid:
                response = Response(status=302, headers={"Location": location})
                requests = Requests(response)
                with self.subTest(directory=directory, location=location), \
                     self.assertRaisesRegex(bootstrap.MaterialError, "^" + code + "$"):
                    self.request(logical, requests)
                self.assertEqual(len(requests.calls), 1)
                self.assertTrue(response.closed)
                self.assertEqual(self.dest.read_bytes(), b"previous verified body")
            for statuses, code in (([302] * 4, "REDIRECT_BUDGET"),
                                   ([302, 503, 503, 503], "HTTP_TRANSIENT_EXHAUSTED")):
                responses = [Response(status=s, headers={"Location": path}) for s in statuses]
                requests = Requests(*responses)
                with self.subTest(directory=directory, code=code), mock.patch.object(bootstrap.time, "sleep"), \
                     self.assertRaisesRegex(bootstrap.MaterialError, "^" + code + "$"):
                    self.request(logical, requests)
                self.assertEqual(len(requests.calls), 4)
                self.assertTrue(all(r.closed for r in responses))

    def test_both_sid_directories_keep_body_process_wall_and_tls_stops(self):
        base = "https://snapshot.debian.org/archive/debian-ports/20250625T074124Z/"
        alarm = bootstrap._object_alarm
        for directory in ("pool/", "pool-loong64/"):
            logical = base + directory + "main/f/fixture/lib_1_loong64.deb"
            for action, code in ((SSLError("controlled TLS failure"), "TLS_FAILURE"),
                                 (Response(status=404), "HTTP_PERMANENT")):
                requests = Requests(action)
                with self.subTest(directory=directory, code=code), \
                     self.assertRaisesRegex(bootstrap.MaterialError, "^" + code + "$"):
                    self.request(logical, requests)
                self.assertEqual(len(requests.calls), 1)
            policy = bootstrap.load_policy()
            policy["limits"]["objectBytes"] = 4
            response = Response(body=b"abcdef")
            with self.assertRaisesRegex(bootstrap.MaterialError, "^BODY_BUDGET_NO_VERIFIED_EOF$"):
                self.request(logical, Requests(response), policy)
            self.assertEqual(response.position, 4)
            policy = bootstrap.load_policy()
            policy["limits"]["creatorProcessBytes"] = 5
            response = Response(body=b"ab", headers={"Content-Length": "2"})
            with self.assertRaisesRegex(bootstrap.MaterialError, "^PROCESS_BYTES$"):
                self.request(logical, Requests(response), policy, charged=4)
            self.assertEqual(response.position, 0)
            response = Response(body=b"late", delay=0.1)
            with mock.patch.object(bootstrap, "_object_alarm", side_effect=lambda seconds: alarm(0.02)), \
                 self.assertRaisesRegex(bootstrap.MaterialError, "^OBJECT_DEADLINE$"):
                self.request(logical, Requests(response))
            self.assertTrue(response.closed)
            self.assertEqual(self.dest.read_bytes(), b"previous verified body")
            self.assertEqual(list(self.root.glob(".polaris-material-*")), [])


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

    def test_sid_namespace_guard_reaches_receipt_manifest_and_consumer_use(self):
        bundle = fixture_bundle("all")
        artifact = "binary-linux_loong64-glibc"
        for replacement, reason in (("pool-other/", "logical URL/profile archive"),
                                    ("pool-loong64evil/", "logical URL/profile archive"),
                                    ("pool-loong64/../", "logical deb URL spelling")):
            bad = SID_LIBC6_DEV_URL.replace("pool-loong64/", replacement, 1)
            manifest = copy.deepcopy(bundle["manifest"])
            receipt = next(p for p in manifest["profiles"] if p["id"] == "sid-loong64")
            receipt["selectedDebs"][bad] = receipt["selectedDebs"].pop(SID_LIBC6_DEV_URL)
            receipt["urls"] = sorted(bad if u == SID_LIBC6_DEV_URL else u for u in receipt["urls"])
            item = next(o for o in manifest["objects"] if o["url"] == SID_LIBC6_DEV_URL)
            item["url"] = bad
            encoded = supply.encode_json(manifest)
            measured = dict(bundle["measurements"], **{
                supply.MANIFEST: {"bytes": len(encoded), "sha256": supply.digest(encoded)}})
            use = fixture_use(bundle, artifact)
            use["profiles"][-1] = receipt
            with self.subTest(replacement=replacement):
                with self.assertRaisesRegex(ValueError, reason):
                    supply.validate_profile(receipt, "sid-loong64", supply.load_profile_plan())
                with self.assertRaisesRegex(ValueError, reason):
                    supply.validate_manifest(manifest, context=bundle["context"], measurements=measured)
                with self.assertRaisesRegex(ValueError, reason):
                    supply.validate_use_ref(use, binding=bundle["binding"], ready_artifact=bundle["ready_artifact"],
                        artifact_name=artifact, consumer_job=bundle["consumer_job_by_artifact"][artifact])
        manifest = copy.deepcopy(bundle["manifest"])
        item = next(o for o in manifest["objects"] if o["url"] == SID_LIBC6_DEV_URL)
        item["profiles"] = ["bullseye-amd64", "sid-loong64"]
        with self.assertRaisesRegex(ValueError, "logical URL/profile archive"):
            supply.validate_manifest(manifest, context=bundle["context"], measurements=bundle["measurements"])

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
                       {"role": "docker", "workflow": ".github/workflows/docker.yml"}):
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
        bundle = fixture_bundle("all")
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


class PreparedCandidateTests(unittest.TestCase):
    """Real ZIP/CAS/import controls; controlled receipts never claim GPG acceptance."""
    def candidate(self):
        bundle = fixture_bundle("all")
        bundle["manifest"]["state"] = "PARTIAL"
        bundle["manifest"]["profiles"] = []
        self.repack(bundle)
        return bundle

    def repack(self, bundle):
        bundle["files"][supply.MANIFEST] = supply.encode_json(bundle["manifest"])
        bundle["raw_zip"] = _zip_bytes(bundle["files"])
        bundle["raw_artifact"]["digest"] = "sha256:" + supply.digest(bundle["raw_zip"])
        bundle["raw_artifact"]["size_in_bytes"] = len(bundle["raw_zip"])

    @contextmanager
    def transport(self, bundle, mutate_run=None, mutate_jobs=None, mutate_artifact=None):
        context = bundle["context"]
        run = {"id": context["runID"], "run_attempt": context["runAttempt"],
               "head_sha": context["sourceCommit"], "head_branch": context["tag"],
               "event": "workflow_dispatch", "path": context["workflow"],
               "repository": {"id": supply.RID, "full_name": supply.REPO},
               "head_repository": {"id": supply.RID, "full_name": supply.REPO},
               "run_started_at": "2020-01-01T00:00:00Z", "status": "completed", "conclusion": "failure"}
        source = dict(bundle["supplier_job"], id=2999, name="Calculate version", conclusion="success")
        jobs = [source, dict(bundle["supplier_job"], conclusion="failure"),
                dict(source, id=2998, name="Build binary", conclusion="skipped")]
        artifact = copy.deepcopy(bundle["raw_artifact"])
        if mutate_run is not None: mutate_run(run)
        if mutate_jobs is not None: mutate_jobs(jobs)
        if mutate_artifact is not None: mutate_artifact(artifact)
        def api(path, deadline=None):
            if path == "actions/artifacts/2001": return copy.deepcopy(artifact)
            if path == "actions/runs/1001/attempts/1": return copy.deepcopy(run)
            if path == "actions/runs/1001/artifacts?per_page=100&page=1":
                return {"total_count": 1, "artifacts": [copy.deepcopy(artifact)]}
            if path == "actions/runs/1001/attempts/1/jobs?per_page=100&page=1":
                return {"total_count": len(jobs), "jobs": copy.deepcopy(jobs)}
            raise AssertionError("unexpected prepared metadata request: " + path)
        def transfer(path, sink, maximum, **kwargs):
            self.assertEqual(path, "repos/" + supply.REPO + "/actions/artifacts/2001/zip")
            self.assertLessEqual(len(bundle["raw_zip"]), maximum)
            sink.write(bundle["raw_zip"])
            return {"bytes": len(bundle["raw_zip"]), "sha256": supply.digest(bundle["raw_zip"])}
        with mock.patch.object(supply, "_api", side_effect=api), \
             mock.patch.object(supply._release(), "read_get", side_effect=transfer):
            yield

    def args(self, bundle, role, root):
        return argparse.Namespace(role=role, cronet_root=root, output=root / "out", materials_only=False,
            checkpoint_artifact_id=2001, checkpoint_artifact_digest=bundle["raw_artifact"]["digest"])

    def context(self, bundle, role):
        return dict(bundle["context"], role=role, runID=1002,
                    workflow=supply.load_profile_plan()["roles"][role]["workflow"])

    def store(self, context, output):
        supply.new_directory(output); supply.new_directory(output / "objects")
        supply.write_new(output / supply.MANIFEST, supply.encode_json({
            "schema": "polaris-debian-candidate-v1", "scope": supply.SCOPE, "context": context,
            "planSHA256": supply.profile_plan_sha256(), "requiredProfiles": supply.required_profiles(context),
            "state": "PARTIAL", "objects": [], "profiles": [], "seed": None}))

    def test_measured_partial_all_candidate_imports_each_role_without_borrowing_ready(self):
        bundle = self.candidate()
        for role in ("all", "linux", "docker"):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); context = self.context(bundle, role); output = root / "raw"
                self.store(context, output)
                with self.transport(bundle):
                    seed = supply._seed_checkpoint(self.args(bundle, role, root), context, output, prepared=True)
                current = supply.decode_json(supply.read_regular(output / supply.MANIFEST))
                supply.validate_manifest(current, context=context, measurements=supply._measure_local(output, current))
                self.assertEqual(seed["context"], bundle["context"])
                self.assertEqual(current["context"], context)
                self.assertEqual(current["state"], "PARTIAL"); self.assertEqual(current["profiles"], [])
                self.assertFalse((output / supply.READY).exists())
                self.assertTrue(all(set(item["profiles"]) <= set(current["requiredProfiles"])
                                    for item in current["objects"]))

    def test_incompatible_source_tag_plan_attempt_artifact_and_nonmaterials_frontier_are_rejected(self):
        baseline = self.candidate()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); context = self.context(baseline, "linux")
            self.store(context, root / "raw")
            with self.transport(baseline):
                seed = supply._seed_checkpoint(self.args(baseline, "linux", root), context, root / "raw", prepared=True)
            self.assertEqual(seed["context"], baseline["context"])
            self.assertEqual(seed["artifact"], supply.artifact_ref(baseline["raw_artifact"]))
        cases = ["sourceCommit", "sourceTree", "tag", "tagObject", "plan", "run", "attempt", "artifact",
                 "outer", "member", "product", "source_failed", "job_attempt", "duplicate_job",
                 "cancelled", "artifact_time", "role"]
        guards = {
            "sourceCommit": "checkpoint source/repository/ref", "sourceTree": "candidate exact source/tag identity",
            "tag": "checkpoint source/repository/ref", "tagObject": "candidate exact source/tag identity",
            "plan": "candidate source/plan/state", "run": "actual run/attempt/source/ref/workflow",
            "attempt": "actual run/attempt/source/ref/workflow", "artifact": "explicit checkpoint ID/digest",
            "outer": "explicit checkpoint ID/digest", "member": "actual member bytes/selfSHA",
            "product": "Materials-only actual job frontier", "source_failed": "Materials source/supplier completion",
            "job_attempt": "Materials actual source/run/attempt job", "duplicate_job": "duplicate job",
            "cancelled": "completed Materials run required", "artifact_time": "candidate artifact actual supplier attempt/time",
            "role": "completed Materials run required"}
        self.assertEqual(set(guards), set(cases))
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                bundle = copy.deepcopy(baseline); root = Path(temporary)
                context = self.context(bundle, "linux")
                if case in ("sourceCommit", "sourceTree", "tag", "tagObject"):
                    context[case] = "v1.15.0-polaris-alpha.12.99" if case == "tag" else "d" * 40
                if case == "plan":
                    bundle["manifest"]["planSHA256"] = "d" * 64; self.repack(bundle)
                if case == "member":
                    name = bundle["manifest"]["objects"][0]["member"]
                    bundle["files"][name] += b"tampered"; self.repack(bundle)
                args = self.args(bundle, "linux", root)
                if case == "outer": args.checkpoint_artifact_digest = "e" * 64
                def run(row):
                    if case == "run": row["id"] += 1
                    if case == "attempt": row["run_attempt"] += 1
                    if case == "cancelled": row["conclusion"] = "cancelled"
                def jobs(rows):
                    if case == "product": rows[2]["conclusion"] = "success"
                    if case == "source_failed": rows[0]["conclusion"] = "failure"
                    if case == "job_attempt": rows[1]["run_attempt"] += 1
                    if case == "duplicate_job": rows[2]["id"] = rows[1]["id"]
                    if case == "artifact_time": rows[1]["completed_at"] = "2020-01-01T00:00:20Z"
                def artifact(row):
                    if case == "artifact": row["id"] += 1
                if case == "role":
                    bundle["manifest"]["context"]["role"] = "linux"
                    bundle["manifest"]["context"]["workflow"] = ".github/workflows/linux.yml"
                    self.repack(bundle); args = self.args(bundle, "linux", root)
                self.store(context, root / "raw")
                with self.transport(bundle, run, jobs, artifact), \
                     self.assertRaisesRegex(ValueError, "^Debian material admission: " + guards[case] + "$"):
                    supply._seed_checkpoint(args, context, root / "raw", prepared=True)

    def test_final_prepare_reauthenticates_strictly_and_retains_candidate_identity(self):
        bundle = self.candidate()
        for role in ("all", "linux", "docker"):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); context = self.context(bundle, role); args = self.args(bundle, role, root)
                def verify(cronet, profiles, store, capture, deadline, *, independent):
                    self.assertIs(capture, False); self.assertIs(independent, True)
                    current = supply.decode_json(supply.read_regular(store / supply.MANIFEST))
                    self.assertEqual(current["seed"]["context"], bundle["context"])
                    return [copy.deepcopy(p) for p in fixture_bundle("all")["manifest"]["profiles"] if p["id"] in profiles]
                with self.transport(bundle), mock.patch.object(supply, "actions_context", return_value=context), \
                     mock.patch.object(supply, "_prepared"), mock.patch.object(supply, "_fresh_stage"), \
                     mock.patch.object(supply, "_profiles", side_effect=verify):
                    supply.prepare(args)
                manifest = supply.decode_json(supply.read_regular(args.output / supply.MANIFEST))
                self.assertEqual(manifest["state"], "VERIFIED")
                self.assertEqual(manifest["seed"]["context"], bundle["context"])
                self.assertFalse((args.output / supply.READY).exists())

    def test_final_and_local_empty_pair_stop_before_profiles(self):
        bundle = self.candidate()
        with tempfile.TemporaryDirectory() as temporary:
            args = self.args(bundle, "all", Path(temporary)); args.checkpoint_artifact_id = None
            args.checkpoint_artifact_digest = None
            with mock.patch.dict(os.environ, {}, clear=True), \
                 mock.patch.object(supply, "actions_context", return_value=self.context(bundle, "all")), \
                 mock.patch.object(supply, "_prepared"), mock.patch.object(supply, "_fresh_stage"), \
                 mock.patch.object(supply, "_profiles") as worker:
                with self.assertRaisesRegex(ValueError, "NOT_READY"): supply.prepare(args)
                with self.assertRaisesRegex(ValueError, "NOT_READY"): supply.consume_local(args)
                worker.assert_not_called()
            args.materials_only = True; args.role = "linux"
            with mock.patch.object(supply, "actions_context", return_value=self.context(bundle, "linux")), \
                 mock.patch.object(supply, "_prepared"), mock.patch.object(supply, "_fresh_stage"), \
                 self.assertRaisesRegex(ValueError, "all-role union"):
                supply.prepare(args)

    def test_partial_missing_own_profile_never_contacts_origin_and_auth_failure_has_no_use(self):
        for failure in ("none", "missing", "authentication"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                bundle = self.candidate(); root = Path(temporary); context = self.context(bundle, "all")
                expected = supply.expected_use("all", "binary-linux_arm64-glibc")
                if failure == "missing":
                    removed = next(item for item in bundle["manifest"]["objects"]
                                   if item["profiles"] == ["bullseye-arm64"])
                    bundle["manifest"]["objects"].remove(removed)
                    del bundle["files"][removed["member"]]; self.repack(bundle)
                args = self.args(bundle, "all", root)
                args.caller = expected["caller"]; args.target_arch = "arm64"; args.libc = "glibc"
                requests = Requests()
                def verify(cronet, profiles, store, capture, deadline):
                    self.assertEqual(cronet, args.cronet_root); self.assertEqual(store, args.output / "raw")
                    self.assertIs(capture, False); self.assertEqual(profiles, expected["profiles"])
                    with mock.patch.dict(os.environ, {"POLARIS_CRONET_RAW_STORE": str(store)}, clear=True):
                        if failure == "missing":
                            bootstrap.download_file(removed["url"], root / "missing", requests)
                        if failure == "authentication":
                            raise ValueError("controlled original GPG/Packages/deb authentication failure")
                        return [copy.deepcopy(p) for p in fixture_bundle("all")["manifest"]["profiles"]
                                if p["id"] in profiles]
                verify_probe = mock.Mock(wraps=verify)
                with self.transport(bundle), mock.patch.dict(os.environ, {"GITHUB_JOB": "build"}, clear=True), \
                     mock.patch.object(supply, "actions_context", return_value=context), \
                     mock.patch.object(supply, "_prepared"), mock.patch.object(supply, "_fresh_stage"), \
                     mock.patch.object(supply, "_consumer_job", return_value={"id": 4001, "key": "build", "name": "Build binary", "runner": "fixture"}), \
                     mock.patch.object(supply, "_profiles", side_effect=verify_probe) as profiles_worker:
                    if failure == "missing":
                        with self.assertRaisesRegex(bootstrap.MaterialError, "^CANDIDATE_REQUIRED_MISSING$") as refused:
                            supply.consume_local(args)
                        self.assertEqual(refused.exception.code, "CANDIDATE_REQUIRED_MISSING")
                    elif failure == "authentication":
                        with self.assertRaisesRegex(ValueError, "^controlled original GPG/Packages/deb authentication failure$"):
                            supply.consume_local(args)
                    else:
                        supply.consume_local(args)
                profiles_worker.assert_called_once_with(args.cronet_root, expected["profiles"], args.output / "raw", False, mock.ANY)
                verify_probe.assert_called_once_with(args.cronet_root, expected["profiles"], args.output / "raw", False, mock.ANY)
                self.assertEqual(requests.calls, [])
                if failure == "none":
                    use = supply.decode_json(supply.read_regular(args.output / "use.json"))
                    self.assertEqual(use["requiredProfiles"], expected["profiles"])
                    self.assertEqual(use["manifest"]["state"], "VERIFIED")
                    self.assertEqual(use["context"], context)
                    self.assertEqual(use["manifest"]["seed"]["context"], bundle["context"])
                else:
                    self.assertFalse((args.output / "use.json").exists())

    def test_consumer_subset_joins_current_canonical_with_same_immutable_candidate(self):
        donor = self.candidate()
        for role, artifact in (("all", "binary-linux_arm64-glibc"), ("linux", "binary-linux_arm64"),
                               ("docker", "binary-linux-arm64")):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); context = self.context(donor, role)
                canonical = fixture_bundle(role, context=context)
                canonical["manifest"]["seed"] = {"artifact": supply.artifact_ref(donor["raw_artifact"]),
                    "context": donor["context"], "manifestSHA256": supply.digest(donor["files"][supply.MANIFEST])}
                canonical["binding"]["manifestSHA256"] = supply.digest(supply.encode_json(canonical["manifest"]))
                wire = fixture_local_use(canonical, artifact)
                expected = supply.expected_use(role, artifact)
                args = self.args(donor, role, root)
                args.caller = expected["caller"]; args.target_arch = expected["targetArch"]; args.libc = expected["libc"]
                requests = Requests()
                def verify(cronet, profiles, store, capture, deadline):
                    self.assertIs(capture, False); self.assertEqual(profiles, expected["profiles"])
                    manifest = supply.decode_json(supply.read_regular(store / supply.MANIFEST))
                    self.assertEqual(manifest["seed"], canonical["manifest"]["seed"])
                    with mock.patch.dict(os.environ, {"POLARIS_CRONET_RAW_STORE": str(store)}, clear=True), \
                         mock.patch.object(bootstrap, "_CHARGED", 0), \
                         mock.patch.object(bootstrap, "_CANDIDATES_USED", {}):
                        for number, url in enumerate(sorted({url for p in wire["manifest"]["profiles"] for url in p["urls"]})):
                            bootstrap.download_file(url, root / ("reverified-" + str(number)), requests)
                    return wire["manifest"]["profiles"]
                with self.transport(donor), mock.patch.dict(os.environ, {"GITHUB_JOB": wire["consumerJob"]["key"]}, clear=True), \
                     mock.patch.object(supply, "actions_context", return_value=context), \
                     mock.patch.object(supply, "_prepared"), mock.patch.object(supply, "_fresh_stage"), \
                     mock.patch.object(supply, "_consumer_job", return_value=wire["consumerJob"]), \
                     mock.patch.object(supply, "_profiles", side_effect=verify):
                    supply.consume_local(args)
                use = supply.decode_json(supply.read_regular(args.output / "use.json"))
                LocalOriginalUseTests().validate(canonical, artifact, use)
                self.assertEqual(requests.calls, [])
                wrong = copy.deepcopy(use)
                wrong["manifest"]["seed"]["context"]["runID"] += 1
                wrong["manifestSHA256"] = supply.digest(supply.encode_json(wrong["manifest"]))
                with self.assertRaisesRegex(ValueError, "prepared candidate identity"):
                    LocalOriginalUseTests().validate(canonical, artifact, wrong)

    def test_materials_attempts_other_profiles_once_preserves_complete_raw_and_reports_failure(self):
        bundle = fixture_bundle("all")
        profile_ids = bundle["manifest"]["requiredProfiles"]
        for failed in (profile_ids[0], profile_ids[3], None):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); args = self.args(bundle, "all", root)
                args.materials_only = True; args.checkpoint_artifact_id = None; args.checkpoint_artifact_digest = None
                attempted = []
                class Child:
                    pid = 4567
                    def __init__(self, command, env, start_new_session):
                        self.profile = command[command.index("--profile") + 1]
                        self.receipt = Path(command[command.index("--receipt") + 1])
                        self.env = env; self.returncode = None; attempted.append(self.profile)
                    def wait(child, timeout):
                        self.assertGreater(timeout, 0); self.assertLessEqual(timeout, supply.PROFILE_SECONDS)
                        receipt = next(p for p in bundle["manifest"]["profiles"] if p["id"] == child.profile)
                        urls = receipt["urls"][:1] if child.profile == failed else receipt["urls"]
                        with mock.patch.dict(os.environ, child.env, clear=True):
                            for number, url in enumerate(urls):
                                destination = child.receipt.parent / ("body-" + str(number))
                                destination.write_bytes(bundle["payloads"][url])
                                bootstrap._capture_candidate(url, destination, bootstrap.load_policy())
                        child.returncode = 1 if child.profile == failed else 0
                        if child.returncode == 0: supply.write_new(child.receipt, supply.encode_json(receipt))
                        return child.returncode
                    def poll(child): return child.returncode
                with mock.patch.object(supply, "actions_context", return_value=bundle["context"]), \
                     mock.patch.object(supply, "_prepared"), mock.patch.object(supply, "_fresh_stage"), \
                     mock.patch.object(supply.subprocess, "Popen", side_effect=Child):
                    if failed is None: supply.prepare(args)
                    else:
                        with self.assertRaisesRegex(ValueError, "profiles NOT_READY"): supply.prepare(args)
                self.assertEqual(attempted, profile_ids)
                manifest = supply.decode_json(supply.read_regular(args.output / supply.MANIFEST))
                self.assertEqual([p["id"] for p in manifest["profiles"]], [p for p in profile_ids if p != failed])
                self.assertEqual(manifest["state"], "VERIFIED" if failed is None else "PARTIAL")
                supply.validate_manifest(manifest, context=bundle["context"],
                                         measurements=supply._measure_local(args.output, manifest))
                self.assertFalse((args.output / supply.READY).exists())

    def test_profile_timeout_cleanup_and_whole_deadline_never_expand_preparation(self):
        bundle = fixture_bundle("all"); ids = bundle["manifest"]["requiredProfiles"]
        for mode in ("timeout", "whole", "cleanup"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); output = root / "raw"; self.store(bundle["context"], output)
                attempted = []
                class Child:
                    pid = 4567
                    def __init__(child, command, env, start_new_session):
                        child.profile = command[command.index("--profile") + 1]
                        child.receipt = Path(command[command.index("--receipt") + 1])
                        child.calls = 0; child.returncode = None; attempted.append(child.profile)
                    def wait(child, timeout):
                        child.calls += 1
                        self.assertLessEqual(timeout, supply.PROFILE_SECONDS)
                        if child.profile == ids[0]:
                            if mode != "whole" and child.calls == 1:
                                raise subprocess.TimeoutExpired("controlled profile", timeout)
                            child.returncode = -9; return child.returncode
                        receipt = next(p for p in bundle["manifest"]["profiles"] if p["id"] == child.profile)
                        supply.write_new(child.receipt, supply.encode_json(receipt))
                        child.returncode = 0; return 0
                    def poll(child): return child.returncode
                with mock.patch.object(supply.subprocess, "Popen", side_effect=Child), \
                     mock.patch.object(supply.os, "killpg", side_effect=OSError("controlled cleanup") if mode == "cleanup" else None) as kill, \
                     mock.patch.object(supply.time, "monotonic", side_effect=[0, 2401] if mode == "whole" else None,
                                       return_value=0), self.assertRaisesRegex(ValueError, "cleanup unconfirmed" if mode == "cleanup" else "profiles NOT_READY"):
                    supply._profiles(root, ids, output, True, supply.PREPARE_SECONDS, independent=True)
                self.assertEqual(attempted, ids if mode == "timeout" else ids[:1])
                self.assertEqual(kill.call_count, 0 if mode == "whole" else 1)

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
        self.check_original_authentication("bullseye-amd64")

    def test_original_signed_sid_mixed_index_selects_both_namespaces(self):
        self.check_original_authentication("sid-loong64")

    def test_original_signed_sid_index_still_rejects_unapproved_namespace(self):
        self.check_original_authentication("sid-loong64",
            rejected_url=SID_LIBC6_DEV_URL.replace("pool-loong64/", "pool-loong64evil/", 1))

    def check_original_authentication(self, profile_id, rejected_url=None):
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
                profile = next(item for item in plan["profiles"] if item["id"] == profile_id)
                base = profile["archivePrefix"]
                arch, distro = profile["creatorArchitecture"], profile["release"]
                role = "all" if profile_id == "sid-loong64" else "linux"
                if profile_id == "sid-loong64":
                    debs = {SID_LIBC6_DEV_URL: b"controlled libc6-dev raw body",
                            SID_LIBSTDCPP13_DEV_URL: b"controlled libstdc++ raw body",
                            SID_ALL_DEP_URL: b"controlled Architecture:all dependency"}
                    if rejected_url is not None:
                        debs[rejected_url] = debs.pop(SID_LIBC6_DEV_URL)
                else:
                    debs = {
                        base + "pool/main/f/fixture/libc6-dev_1_amd64.deb": b"controlled libc6-dev raw body",
                        base + "pool/main/f/fixture/libc6_1_amd64.deb": b"controlled libc6 raw body",
                        base + "pool/main/f/fixture/libstdc++-10-dev_1_amd64.deb": b"controlled libstdc++ raw body"}
                package_blocks = []
                for url, body in debs.items():
                    filename = url[len(base):]
                    name = filename.rsplit("/", 1)[1].split("_", 1)[0]
                    architecture = "all" if name == "architecture-all" else arch
                    block = ("Package: " + name + "\nArchitecture: " + architecture + "\nFilename: "
                             + filename + "\nSHA256: " + supply.digest(body) + "\n")
                    if name == "libc6-dev":
                        block += "Depends: " + ("architecture-all" if arch == "loong64" else "libc6") + "\n"
                    package_blocks.append(block)
                packages = lzma.compress(("\n".join(package_blocks) + "\n").encode())
                release = ("SHA256:\n" + "".join(
                    " " + supply.digest(packages) + " " + str(len(packages)) + " " + repo
                    + "/binary-" + arch + "/Packages.xz\n"
                    for repo in sorted({repo for _, repos in profile["aptSources"] for repo in repos}))).encode()
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
                for poison in (("guard",) if rejected_url is not None else ("none", "signature", "packages", "deb")):
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
                            if url == rejected_url:
                                # Authenticate the signed Filename, but do not
                                # smuggle its unapproved deb into the raw store.
                                continue
                            sha = supply.digest(body)
                            member = "objects/" + sha
                            target = store / member
                            if not target.exists():
                                supply.write_new(target, body)
                            objects.append({"url": url, "member": member, "sha256": sha, "bytes": len(body),
                                            "profiles": [profile["id"]], "complete": True})
                        fixture = fixture_bundle(role)
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
                                     "RELEASES": {arch: distro}, "TRIPLES": {arch: profile["debianTriple"]},
                                     "GCC_VERSIONS": {distro: profile["gccMajor"]},
                                     "APT_SOURCES_LISTS": {arch: profile["aptSources"]},
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
                                if arch == "loong64":
                                    self.assertIn(SID_LIBC6_DEV_URL, receipt["selectedDebs"])
                                    self.assertIn(SID_LIBSTDCPP13_DEV_URL, receipt["selectedDebs"])
                                    self.assertIn(SID_ALL_DEP_URL, receipt["selectedDebs"])
                                # Carry this original authenticated receipt and
                                # exact raw bytes through the existing envelope.
                                accepted = fixture_bundle(role, authenticated=(receipt, originals))
                                raw_zip, ready_zip = trial / "raw.zip", trial / "ready.zip"
                                raw_zip.write_bytes(accepted["raw_zip"])
                                ready_zip.write_bytes(accepted["ready_zip"])
                                self.assertEqual(supply.validate_bundle(raw_zip, ready_zip,
                                    raw_artifact=accepted["raw_artifact"], ready_artifact=accepted["ready_artifact"],
                                    context=accepted["context"], supplier_job=accepted["supplier_job"]), accepted["binding"])
                                for artifact in accepted["consumer_job_by_artifact"]:
                                    use = fixture_use(accepted, artifact)
                                    supply.validate_use_ref(use, binding=accepted["binding"],
                                        ready_artifact=accepted["ready_artifact"], artifact_name=artifact,
                                        consumer_job=accepted["consumer_job_by_artifact"][artifact])
                            else:
                                if poison == "signature":
                                    with self.assertRaises(subprocess.CalledProcessError):
                                        supply._verify_profile_data(creator, bootstrap, profile, trial / "build")
                                elif poison == "packages":
                                    with self.assertRaisesRegex(Exception, "Checksum mismatch"):
                                        supply._verify_profile_data(creator, bootstrap, profile, trial / "build")
                                elif poison == "guard":
                                    with self.assertRaisesRegex(ValueError, "logical URL/profile archive"):
                                        supply._verify_profile_data(creator, bootstrap, profile, trial / "build")
                                else:
                                    with self.assertRaisesRegex(ValueError, "original selected deb SHA256"):
                                        supply._verify_profile_data(creator, bootstrap, profile, trial / "build")
                            # Reach the real local entry as well. Only transport
                            # bytes/Actions identity are fixtures; this profile's
                            # original creator and actual gpgv are not replaced.
                            candidate_receipt = {"id": profile_id, "keyringSHA256": supply.digest(keyring.read_bytes()),
                                "selectedDebs": {url:supply.digest(body) for url, body in debs.items()},
                                "urls": sorted(supply.profile_urls(plan, profile_id) | set(debs)), "verified": True}
                            local_bundle = fixture_bundle(role, authenticated=(candidate_receipt, payloads))
                            artifact = "binary-linux_loong64-glibc" if arch == "loong64" else "binary-linux_amd64"
                            def verify_local(raw_store, profile_ids):
                                receipts = []
                                for requested in profile_ids:
                                    if requested != profile_id:
                                        # Host envelope is ordinary protocol data
                                        # in this signed sid-only fixture.
                                        receipts.append(copy.deepcopy(next(r for r in local_bundle["manifest"]["profiles"]
                                                                              if r["id"] == requested)))
                                        continue
                                    with mock.patch.dict(os.environ, {"POLARIS_CRONET_RAW_STORE":str(raw_store)}), \
                                         mock.patch.object(bootstrap, "_CHARGED", 0), \
                                         mock.patch.object(bootstrap, "_CANDIDATES_USED", {}):
                                        receipts.append(supply._verify_profile_data(creator, bootstrap, profile,
                                                                                   trial / "local-original-build"))
                                return receipts
                            controls = LocalOriginalUseTests()
                            if poison == "none":
                                local = controls.run_local(local_bundle, artifact, trial / "local-output", verify_local)
                                selected = next(r for r in local["manifest"]["profiles"] if r["id"] == profile_id)
                                self.assertEqual(selected["selectedDebs"], candidate_receipt["selectedDebs"])
                            else:
                                exception = subprocess.CalledProcessError if poison == "signature" else Exception
                                message = {"signature":"gpgv", "packages":"Checksum mismatch",
                                           "guard":"logical URL/profile archive", "deb":"original selected deb SHA256"}[poison]
                                with self.assertRaisesRegex(exception, message):
                                    controls.run_local(local_bundle, artifact, trial / "local-output", verify_local)
                                self.assertFalse((trial / "local-output/use.json").exists())
                            self.assertTrue(real_process.call_args_list)
                            self.assertTrue(all(call.args[0][0] == "gpgv" for call in real_process.call_args_list))
            finally:
                subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"], check=True, timeout=10,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    unittest.main()
