"""Remote CI unit evidence for the actual controller, never a producer receipt."""
import contextlib
import copy
import difflib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts.ci import cronet_material_bootstrap as material

OLD_DOWNLOAD = "def download_file(url: str, dest: str, retries=5) -> None:\n    \"\"\"\n    Downloads a file from a URL to a specified destination with retry logic,\n    directory creation, and atomic write.\n    \"\"\"\n    print(f\"Downloading from {url} -> {dest}\")\n    # Create directories if they don't exist\n    os.makedirs(os.path.dirname(dest), exist_ok=True)\n\n    for attempt in range(retries):\n        try:\n            with requests.get(url, stream=True) as response:\n                response.raise_for_status()\n\n                # Use a temporary file to write data\n                with tempfile.NamedTemporaryFile(\n                    mode=\"wb\", delete=False, dir=os.path.dirname(dest)\n                ) as temp_file:\n                    for chunk in response.iter_content(chunk_size=8192):\n                        temp_file.write(chunk)\n\n                # Rename temporary file to destination file\n                os.rename(temp_file.name, dest)\n                print(f\"Downloaded {dest}\")\n                break\n\n        except requests.RequestException as e:\n            print(f\"Attempt {attempt} failed: {e}\")\n            # Exponential back-off\n            time.sleep(2**attempt)\n    else:\n        raise Exception(f\"Failed to download file after {retries} attempts\")\n\n\n"
DOWNLOAD_OR_COPY = "def download_or_copy(source: str, destination: str) -> None:\n    \"\"\"\n    Downloads a file from the given URL or copies it from a local path to the\n    specified destination.\n    \"\"\"\n    if os.path.exists(destination):\n        print(f\"{destination} already in place\")\n        return\n\n    if source.startswith((\"http://\", \"https://\")):\n        download_file(source, destination)\n    else:\n        atomic_copyfile(source, destination)\n\n\n"
HASH_FILE = "def hash_file(hasher, file_name: str) -> str:\n    with open(file_name, \"rb\") as f:\n        while chunk := f.read(8192):\n            hasher.update(chunk)\n    return hasher.hexdigest()\n\n\n"
INSTALL_CALLER = "def install_into_sysroot(\n    build_dir: str, install_root: str, packages: dict[str, str]\n) -> None:\n    \"\"\"\n    Installs libraries and headers into the sysroot environment.\n    \"\"\"\n    banner(\"Install Libs And Headers Into Jail\")\n\n    debian_packages_dir = os.path.join(build_dir, \"debian-packages\")\n    os.makedirs(debian_packages_dir, exist_ok=True)\n\n    debian_dir = os.path.join(install_root, \"debian\")\n    os.makedirs(debian_dir, exist_ok=True)\n    for package, sha256sum in packages.items():\n        package_name = os.path.basename(package)\n        package_path = os.path.join(debian_packages_dir, package_name)\n\n        banner(f\"Installing {package_name}\")\n        download_or_copy(package, package_path)\n        if hash_file(hashlib.sha256(), package_path) != sha256sum:\n            raise ValueError(f\"SHA256 mismatch for {package_path}\")\n\n        sub_banner(f\"Extracting to {install_root}\")\n        subprocess.run(\n            [\"dpkg-deb\", \"-x\", package_path, install_root], check=True\n        )\n\n        base_package = get_base_package_name(package_path)\n        debian_package_dir = os.path.join(debian_dir, base_package, \"DEBIAN\")\n\n        # Extract the control file\n        os.makedirs(debian_package_dir, exist_ok=True)\n        with subprocess.Popen(\n            [\"dpkg-deb\", \"-e\", package_path, debian_package_dir],\n            stdout=subprocess.PIPE,\n            stderr=subprocess.PIPE,\n        ) as proc:\n            _, err = proc.communicate()\n            if proc.returncode != 0:\n                message = \"Failed to extract control from\"\n                raise Exception(\n                    f\"{message} {package_path}: {err.decode('utf-8')}\"\n                )\n\n    # Prune /usr/share, leaving only allowlisted directories.\n    USR_SHARE_ALLOWLIST = {\n        \"fontconfig\",\n        \"pkgconfig\",\n        \"wayland\",\n        \"wayland-protocols\",\n    }\n    usr_share = os.path.join(install_root, \"usr\", \"share\")\n    for item in os.listdir(usr_share):\n        full_path = os.path.join(usr_share, item)\n        if os.path.isdir(full_path) and item not in USR_SHARE_ALLOWLIST:\n            shutil.rmtree(full_path)\n\n\n"
ORIGIN = "https://snapshot.debian.org/archive/debian/20250129T203412Z//dists/bullseye/Release"
MIRROR = ORIGIN.replace("snapshot.debian.org", "snapshot-cloudflare.debian.org", 1)


class RequestError(Exception):
  pass


class ConnectionError(RequestError):
  pass


class Timeout(RequestError):
  pass


class ConnectTimeout(ConnectionError, Timeout):
  pass


class ReadTimeout(Timeout):
  pass


class ProxyError(ConnectionError):
  pass


class SSLError(ConnectionError):
  pass


class RawError(Exception):
  pass


class RawSSL(RawError):
  pass


class RawTimeout(RawError):
  pass


class Response:
  def __init__(self, status=200, body=b"good", headers=None, fail_after=None,
         delay=0, observe=None):
    self.status_code = status
    self.body = body
    self.headers = {} if headers is None else headers
    self.position = 0
    self.fail_after = fail_after
    self.delay = delay
    self.observe = observe
    self.closed = False
    self.raw = self

  def read(self, amount, decode_content=False):
    if decode_content:
      raise AssertionError("unexpected body decoding")
    if self.observe:
      self.observe()
    if self.delay:
      time.sleep(self.delay)
    if self.fail_after is not None and self.position >= self.fail_after:
      raise RawTimeout("proxy credentials must never appear")
    data = self.body[self.position:self.position + amount]
    self.position += len(data)
    return data

  def close(self):
    self.closed = True


class Requests:
  exceptions = SimpleNamespace(RequestException=RequestError,
                 ConnectionError=ConnectionError,
                 Timeout=Timeout, ConnectTimeout=ConnectTimeout,
                 ReadTimeout=ReadTimeout, ProxyError=ProxyError, SSLError=SSLError)
  packages = SimpleNamespace(urllib3=SimpleNamespace(exceptions=SimpleNamespace(
    SSLError=RawSSL, ReadTimeoutError=RawTimeout, HTTPError=RawError)))

  def __init__(self, *actions):
    self.actions = list(actions)
    self.calls = []
    self.session_closed = False
    owner = self

    class Session:
      def __enter__(self):
        return self

      def __exit__(self, *args):
        owner.session_closed = True

      def resolve_redirects(self, *args, **kwargs):
        raise AssertionError("automatic redirect processing")

      def get(self, url, **kwargs):
        response = owner.get(url, **kwargs)
        self.resolve_redirects(response, None)
        return response

    self.Session = Session

  def get(self, url, **kwargs):
    self.calls.append((url, kwargs))
    if not self.actions:
      raise AssertionError("extra HTTP request")
    action = self.actions.pop(0)
    if isinstance(action, Exception):
      raise action
    return action


class ReachedExtraction(Exception):
  pass


class CronetMaterialTests(unittest.TestCase):
  def setUp(self):
    self.temporary = tempfile.TemporaryDirectory(prefix="cronet-material-unit-")
    self.addCleanup(self.temporary.cleanup)
    self.root = Path(self.temporary.name)
    self.dest = self.root / "result"
    self.dest.write_bytes(b"previous verified destination")
    self.policy = material.load_policy()
    self.addCleanup(mock.patch.stopall)
    mock.patch.object(material, "_CHARGED", 0).start()
    mock.patch.object(material, "_LOG_BYTES", 0).start()
    self.log = io.StringIO()
    self.stdout = contextlib.redirect_stdout(self.log)
    self.stdout.__enter__()
    self.addCleanup(self.stdout.__exit__, None, None, None)

  def request(self, requests, policy=None):
    with mock.patch.object(material, "load_policy", return_value=policy or self.policy):
      material.download_file(ORIGIN, self.dest, requests)

  def failure(self, code, requests, policy=None):
    with self.assertRaises(material.MaterialError) as caught:
      self.request(requests, policy)
    self.assertEqual(caught.exception.code, code)
    self.assertEqual(self.dest.read_bytes(), b"previous verified destination")
    self.assertEqual(list(self.root.glob(".polaris-material-*")), [])
    self.assertNotIn("proxy credentials", self.log.getvalue())

  def test_policy_and_patch_fixed_identity_and_import_has_no_effect(self):
    self.assertEqual(self.policy["cronetCommit"], "4d18a60dc3a8d327065b058f92fbbfc9391b84bc")
    self.assertEqual(self.policy["naiveCommit"], "be1be963131154ba82761a7ed85ba426b2027319")
    self.assertEqual(self.policy["limits"], {
      "httpRequests": 4, "redirectHops": 3, "sourceAttempts": 4,
      "connectSeconds": 10, "readIdleSeconds": 20,
      "objectWallSeconds": 180, "objectBytes": 67108864,
      "creatorProcessBytes": 1073741824, "logBytes": 2097152})
    self.assertEqual(self.policy["archivePrefixes"], [
      "/archive/debian/20250129T203412Z/",
      "/archive/debian-ports/20250625T074124Z/"])
    with mock.patch.object(material, "POLICY_SHA256", "0" * 64):
      with self.assertRaisesRegex(material.MaterialError, "^POLICY_DIGEST$"):
        material.load_policy()
    source = Path(material.__file__).read_bytes()
    with mock.patch.object(os, "open", side_effect=AssertionError("import I/O")), \
       mock.patch.object(signal, "setitimer", side_effect=AssertionError("import alarm")), \
       mock.patch.object(subprocess, "check_output", side_effect=AssertionError("import git")):
      exec(source, {"__name__": "unit_import", "__file__": material.__file__})

  def test_origin_503_then_official_mirror_and_atomic_completion(self):
    def observe():
      self.assertEqual(self.dest.read_bytes(), b"previous verified destination")
      self.assertEqual(len(list(self.root.glob(".polaris-material-*"))), 1)

    first = Response(status=503)
    second = Response(body=b"complete new body", headers={"Content-Length": "17"},
              observe=observe)
    requests = Requests(first, second)
    with mock.patch.object(material.time, "sleep"):
      self.request(requests)
    self.assertEqual(self.dest.read_bytes(), b"complete new body")
    self.assertEqual([url for url, _ in requests.calls], [ORIGIN, MIRROR])
    self.assertTrue(first.closed and second.closed)
    self.assertTrue(requests.session_closed)
    for _, kwargs in requests.calls:
      self.assertEqual(kwargs["timeout"], (10, 20))
      self.assertFalse(kwargs["allow_redirects"])
      self.assertEqual(kwargs["headers"], {"Accept-Encoding": "identity"})
    self.assertEqual(list(self.root.glob(".polaris-material-*")), [])

  def test_permanent_ssl_and_unapproved_redirect_stop_without_fallback(self):
    for first, code in [
      (Response(status=404), "HTTP_PERMANENT"),
      (ConnectionError("proxy credentials must never appear"), "NETWORK_PERMANENT"),
      (ProxyError("proxy credentials must never appear"), "NETWORK_PERMANENT"),
      (SSLError("proxy credentials must never appear"), "TLS_FAILURE"),
      (Response(status=302, headers={"Location": "https://example.invalid/file/abc"}), "URL_AUTHORITY_OR_QUERY"),
      (Response(status=302, headers={"Location": "http://snapshot.debian.org/file/" + "a" * 40}), "URL_AUTHORITY_OR_QUERY"),
      (Response(status=302, headers={"Location": ORIGIN.replace("20250129T203412Z", "20260101T000000Z")}), "REDIRECT_IDENTITY"),
    ]:
      with self.subTest(code=code):
        requests = Requests(first)
        self.failure(code, requests)
        self.assertEqual(len(requests.calls), 1)
        if isinstance(first, Response):
          self.assertTrue(first.closed)

  def test_every_redirect_consumes_the_same_four_request_budget(self):
    content = "https://snapshot-cloudflare.debian.org/file/" + "a" * 40
    responses = [Response(status=302, headers={"Location": content}) for _ in range(3)]
    responses.append(Response(body=b"final"))
    requests = Requests(*responses)
    self.request(requests)
    self.assertEqual(len(requests.calls), 4)
    self.assertEqual(self.dest.read_bytes(), b"final")
    self.assertTrue(all(response.closed for response in responses))
    self.dest.write_bytes(b"previous verified destination")
    loop = [Response(status=302, headers={"Location": content}) for _ in range(4)]
    requests = Requests(*loop)
    self.failure("REDIRECT_BUDGET", requests)
    self.assertEqual(len(requests.calls), 4)
    self.assertTrue(all(response.closed for response in loop))

  def test_redirect_plus_transient_never_multiplies_budget(self):
    content = "https://snapshot.debian.org/file/" + "b" * 40
    responses = [Response(status=302, headers={"Location": content}),
           Response(status=503), Response(status=503), Response(status=503)]
    requests = Requests(*responses)
    with mock.patch.object(material.time, "sleep"):
      self.failure("HTTP_TRANSIENT_EXHAUSTED", requests)
    self.assertEqual(len(requests.calls), 4)
    self.assertEqual([url for url, _ in requests.calls][2:], [MIRROR, ORIGIN])
    self.assertTrue(all(response.closed for response in responses))

  def test_connect_and_read_timeouts_retry_under_the_same_request_budget(self):
    requests = Requests(ConnectTimeout("connect timeout"), ReadTimeout("read timeout"),
              Response(body=b"done"))
    with mock.patch.object(material.time, "sleep"):
      self.request(requests)
    self.assertEqual(len(requests.calls), 3)
    self.assertEqual([url for url, _ in requests.calls], [ORIGIN, MIRROR, ORIGIN])
    self.assertEqual(self.dest.read_bytes(), b"done")

  def test_timeout_stream_cleanup_and_charge_unknown_partial_conservatively(self):
    broken = Response(body=b"x" * 9000, fail_after=8192)
    good = Response(body=b"done")
    requests = Requests(Timeout("proxy credentials"), broken, good)
    with mock.patch.object(material.time, "sleep"):
      self.request(requests)
    self.assertEqual(len(requests.calls), 3)
    self.assertEqual(material._CHARGED, 16388)
    self.assertEqual(self.dest.read_bytes(), b"done")
    self.assertTrue(broken.closed and good.closed)
    self.assertEqual(list(self.root.glob(".polaris-material-*")), [])
    self.assertNotIn("proxy credentials", self.log.getvalue())

  def test_length_and_encoding_failures_preserve_destination(self):
    for response, code in [
      (Response(body=b"short", headers={"Content-Length": "6"}), "SHORT_BODY"),
      (Response(headers={"Content-Length": "-1"}), "CONTENT_LENGTH"),
      (Response(headers={"Content-Length": "67108865"}), "OBJECT_BYTES"),
      (Response(headers={"Content-Encoding": "gzip"}), "CONTENT_ENCODING"),
    ]:
      with self.subTest(code=code):
        requests = Requests(response)
        self.failure(code, requests)
        self.assertEqual(len(requests.calls), 1)
        self.assertTrue(response.closed)

  def test_unknown_length_and_process_caps_stop_before_extra_body_read(self):
    policy = copy.deepcopy(self.policy)
    policy["limits"]["objectBytes"] = 4
    response = Response(body=b"abcdef")
    self.failure("BODY_BUDGET_NO_VERIFIED_EOF", Requests(response), policy)
    self.assertEqual(response.position, 4)
    self.assertEqual(material._CHARGED, 4)
    policy = copy.deepcopy(self.policy)
    policy["limits"]["creatorProcessBytes"] = 5
    response = Response(body=b"ab", headers={"Content-Length": "2"})
    self.failure("PROCESS_BYTES", Requests(response), policy)
    self.assertEqual(response.position, 0)
    self.assertEqual(material._CHARGED, 4)

  def test_fsync_rename_and_response_close_failure_remove_owned_partial(self):
    for operation in ("fsync", "replace"):
      response = Response(body=b"new body")
      with mock.patch.object(material.os, operation, side_effect=OSError("proxy credentials")):
        self.failure("ATOMIC_IO", Requests(response))
      self.assertTrue(response.closed)
    response = Response(body=b"new body")
    with mock.patch.object(response, "close", side_effect=RequestError("proxy credentials")):
      self.failure("RESPONSE_CLOSE", Requests(response))

  def test_real_object_alarm_restores_handler_and_cleans_response_and_temp(self):
    handler = signal.getsignal(signal.SIGALRM)
    timer = signal.getitimer(signal.ITIMER_REAL)
    self.assertEqual(timer, (0.0, 0.0))
    actual_alarm = material._object_alarm
    response = Response(body=b"late body", delay=0.1)
    with mock.patch.object(material, "_object_alarm", side_effect=lambda seconds: actual_alarm(0.02)):
      self.failure("OBJECT_DEADLINE", Requests(response))
    self.assertTrue(response.closed)
    self.assertIs(signal.getsignal(signal.SIGALRM), handler)
    self.assertEqual(signal.getitimer(signal.ITIMER_REAL), timer)

  def test_conflicting_timer_and_non_main_thread_refuse_without_altering_alarm(self):
    handler = signal.getsignal(signal.SIGALRM)
    timer = signal.getitimer(signal.ITIMER_REAL)
    self.assertEqual(timer, (0.0, 0.0))
    try:
      signal.setitimer(signal.ITIMER_REAL, 60)
      with self.assertRaises(material.MaterialError) as caught:
        with material._object_alarm(1):
          self.fail("conflicting timer admitted")
      self.assertEqual(caught.exception.code, "DEADLINE_TIMER_CONFLICT")
      remaining, interval = signal.getitimer(signal.ITIMER_REAL)
      self.assertGreater(remaining, 50)
      self.assertEqual(interval, 0)
      self.assertIs(signal.getsignal(signal.SIGALRM), handler)
    finally:
      signal.setitimer(signal.ITIMER_REAL, 0)
    failures = []

    def child():
      try:
        with material._object_alarm(1):
          failures.append("admitted")
      except material.MaterialError as error:
        failures.append(error.code)

    worker = threading.Thread(target=child)
    worker.start()
    worker.join(timeout=2)
    self.assertFalse(worker.is_alive())
    self.assertEqual(failures, ["DEADLINE_CONTEXT"])
    self.assertIs(signal.getsignal(signal.SIGALRM), handler)
    self.assertEqual(signal.getitimer(signal.ITIMER_REAL), timer)

  def fixture_overlay(self):
    source = ("# controlled source prefix\n" + OLD_DOWNLOAD +
          "def get_build_dir(arch):\n    return arch\n").encode()
    begin = source.index(b"def download_file(")
    end = source.index(b"def get_build_dir(", begin)
    result = source[:begin] + material.REPLACEMENT + source[end:]
    patch = "".join(difflib.unified_diff(
      source.decode().splitlines(True), result.decode().splitlines(True),
      fromfile="a/" + self.policy["helper"],
      tofile="b/" + self.policy["helper"], n=3)).encode()
    policy = copy.deepcopy(self.policy)
    policy["sourceSHA256"][policy["helper"]] = material.digest(source)
    policy["overlaySHA256"] = material.digest(patch)
    policy["postimageSHA256"] = material.digest(result)
    return source, result, patch, policy

  def test_actual_overlay_rejects_preimage_patch_boundary_and_postimage(self):
    source, result, patch, policy = self.fixture_overlay()
    self.assertEqual(material.apply_overlay(source, patch, policy), result)
    for field, changed, code in [
      ("preimage", source + b"\n", "HELPER_PREIMAGE"),
      ("patch", patch + b"\n", "OVERLAY_DIGEST"),
      ("postimage", "0" * 64, "HELPER_POSTIMAGE"),
      ("function", "0" * 64, "OVERLAY_FUNCTION_BOUNDARY"),
    ]:
      values = copy.deepcopy(policy)
      actual_source, actual_patch = source, patch
      if field == "preimage":
        actual_source = changed
      elif field == "patch":
        actual_patch = changed
      else:
        values["postimageSHA256" if field == "postimage" else "downloadFunctionSHA256"] = changed
      with self.assertRaises(material.MaterialError) as caught:
        material.apply_overlay(actual_source, actual_patch, values)
      self.assertEqual(caught.exception.code, code)
    extra = patch + b"# unrelated overlay\n"
    policy["overlaySHA256"] = material.digest(extra)
    with self.assertRaises(material.MaterialError) as caught:
      material.apply_overlay(source, extra, policy)
    self.assertEqual(caught.exception.code, "OVERLAY_EXACT_DIFF")

  def test_prepare_exact_fixture_and_pin_dirty_file_fences(self):
    source, result, patch, policy = self.fixture_overlay()
    clone = self.root / "clone"
    naive = clone / "naiveproxy"
    source_root = self.root / "source"
    for name in policy["sourceSHA256"]:
      path = naive / name
      path.parent.mkdir(parents=True, exist_ok=True)
      value = source if name == policy["helper"] else b"fixed fixture shell\n"
      path.write_bytes(value)
      path.chmod(0o755)
      policy["sourceSHA256"][name] = material.digest(value)
    files = {
      ".github/patches/cronet-sysroot-transport.patch": patch,
      "scripts/ci/cronet_material_bootstrap.py": Path(material.__file__).read_bytes(),
      "release/ci/cronet-material-inputs.json": json.dumps(policy).encode(),
    }
    for name, content in files.items():
      path = source_root / name
      path.parent.mkdir(parents=True, exist_ok=True)
      path.write_bytes(content)

    def git(root, *args):
      if args[0] == "rev-parse":
        return policy["naiveCommit"] if Path(root) == naive else policy["cronetCommit"]
      if args[0] == "ls-tree":
        return "160000 commit " + policy["naiveCommit"] + "\tnaiveproxy"
      if args[0] == "diff":
        return ""
      raise AssertionError("unexpected git operation")

    policy_sha = material.digest(files["release/ci/cronet-material-inputs.json"])
    for which, code in [("cronet", "CRONET_PIN"), ("gitlink", "NAIVE_GITLINK"),
              ("naive", "NAIVE_PIN"), ("dirty", "DIRTY_UPSTREAM_HELPER")]:
      def wrong(root, *args):
        if ((which == "cronet" and args[0] == "rev-parse" and Path(root) == clone)
            or (which == "naive" and args[0] == "rev-parse" and Path(root) == naive)
            or (which == "gitlink" and args[0] == "ls-tree")
            or (which == "dirty" and args[0] == "diff")):
          return "wrong"
        return git(root, *args)
      with mock.patch.object(material, "_git", side_effect=wrong), \
         mock.patch.object(material, "POLICY_SHA256", policy_sha):
        with self.assertRaises(material.MaterialError) as caught:
          material._prepare(clone, source_root, policy)
      self.assertEqual(caught.exception.code, code)
      self.assertEqual((naive / policy["helper"]).read_bytes(), source)
    shell = naive / "src/get-clang.sh"
    previous = shell.read_bytes()
    shell.write_bytes(b"changed helper")
    try:
      with mock.patch.object(material, "_git", side_effect=git), \
         mock.patch.object(material, "POLICY_SHA256", policy_sha):
        with self.assertRaises(material.MaterialError) as caught:
          material._prepare(clone, source_root, policy)
      self.assertEqual(caught.exception.code, "UPSTREAM_PREIMAGE")
    finally:
      shell.write_bytes(previous)
    with mock.patch.object(material, "_git", side_effect=git), \
       mock.patch.object(material, "POLICY_SHA256", policy_sha):
      material._prepare(clone, source_root, policy)
    helper = naive / policy["helper"]
    self.assertEqual(helper.read_bytes(), result)
    self.assertEqual(helper.stat().st_mode & 0o777, 0o755)
    target = helper.parent
    self.assertEqual((target / policy["copyNames"]["module"]).read_bytes(),
             files["scripts/ci/cronet_material_bootstrap.py"])
    self.assertEqual((target / policy["copyNames"]["policy"]).read_bytes(),
             files["release/ci/cronet-material-inputs.json"])
    self.assertIn("copiedModuleSHA256", self.log.getvalue())

  def caller_namespace(self, requests):
    source, result, patch, policy = self.fixture_overlay()
    candidate = material.apply_overlay(source, patch, policy)
    namespace = {"requests": requests, "os": os, "hashlib": hashlib,
           "subprocess": subprocess, "re": re,
           "banner": lambda text: None, "sub_banner": lambda text: None}
    exec(candidate, namespace)
    exec(DOWNLOAD_OR_COPY + HASH_FILE + INSTALL_CALLER, namespace)
    return namespace

  def test_actual_patched_wrapper_preserves_original_deb_hash_before_extract(self):
    helper = self.policy["helper"]
    # These are exact unchanged pinned upstream function slices, not a
    # replacement checksum implementation. No .deb or toolchain is acquired.
    self.assertEqual(material.digest(INSTALL_CALLER.encode()), "e37e57a90a34e778fae0db1f79bbd5cb6514a5476a90cbf2d1c073f0ea8a1114")
    for good in (False, True):
      with self.subTest(good=good):
        requests = Requests(Response(body=b"controlled package bytes"))
        namespace = self.caller_namespace(requests)
        package = ORIGIN.rsplit("/", 1)[0] + "/fixture.deb"
        expected = hashlib.sha256(b"controlled package bytes" if good else b"corrupt").hexdigest()
        build = self.root / ("good" if good else "bad")
        install = build / "install"
        with mock.patch.dict(sys.modules, {"polaris_cronet_material": material}), \
           mock.patch.object(material, "load_policy", return_value=self.policy), \
           mock.patch.object(subprocess, "run", side_effect=ReachedExtraction) as extract:
          with self.assertRaises(ReachedExtraction if good else ValueError):
            namespace["install_into_sysroot"](str(build), str(install), {package: expected})
        self.assertEqual(extract.call_count, 1 if good else 0)
        self.assertEqual(len(requests.calls), 1)
        if good:
          self.assertEqual(extract.call_args.args[0][0], "dpkg-deb")



if __name__ == "__main__":
  unittest.main()
