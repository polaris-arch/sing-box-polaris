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
import shutil
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


# Exact unchanged function slices from pinned be1be963 sysroot_creator.py.
ATOMIC_COPY = "def atomic_copyfile(source: str, destination: str) -> None:\n    dest_dir = os.path.dirname(destination)\n    with tempfile.NamedTemporaryFile(\n        mode=\"wb\", delete=False, dir=dest_dir\n    ) as temp_file:\n        temp_filename = temp_file.name\n    shutil.copyfile(source, temp_filename)\n    os.rename(temp_filename, destination)\n\n\n"
DOWNLOAD_NON_UNIQUE = "def download_or_copy_non_unique_filename(url: str, dest: str) -> None:\n    \"\"\"\n    Downloads a file from a given URL to a destination with a unique filename,\n    based on the SHA-256 hash of the URL.\n    \"\"\"\n    hash_digest = hashlib.sha256(url.encode()).hexdigest()\n    unique_dest = f\"{dest}.{hash_digest}\"\n    download_or_copy(url, unique_dest)\n    atomic_copyfile(unique_dest, dest)\n\n\n"
VERIFY_CALLER = "def verify_package_listing(\n    file_path: str, output_file: str, dist: str, build_dir: str\n) -> None:\n    \"\"\"\n    Verifies the downloaded Packages.xz file against its checksum and GPG keys.\n    \"\"\"\n    # Paths for Release and Release.gpg files\n    repo_basedir = f\"{ARCHIVE_URL}/dists/{dist}\"\n    release_list = f\"{repo_basedir}/{RELEASE_FILE}\"\n    release_list_gpg = f\"{repo_basedir}/{RELEASE_FILE_GPG}\"\n\n    release_file = os.path.join(build_dir, f\"{dist}-{RELEASE_FILE}\")\n    release_file_gpg = os.path.join(build_dir, f\"{dist}-{RELEASE_FILE_GPG}\")\n\n    if not os.path.exists(KEYRING_FILE):\n        raise Exception(f\"KEYRING_FILE not found: {KEYRING_FILE}\")\n\n    # Download Release and Release.gpg files\n    download_or_copy_non_unique_filename(release_list, release_file)\n    download_or_copy_non_unique_filename(release_list_gpg, release_file_gpg)\n\n    # Verify Release file with GPG\n    subprocess.run(\n        [\"gpgv\", \"--keyring\", KEYRING_FILE, release_file_gpg, release_file],\n        check=True,\n    )\n\n    # Find the SHA256 checksum for the specific file in the Release file\n    sha256sum_pattern = re.compile(\n        r\"([a-f0-9]{64})\\s+\\d+\\s+\" + re.escape(file_path) + r\"$\"\n    )\n    sha256sum_match = None\n    with open(release_file, \"r\") as f:\n        for line in f:\n            if match := sha256sum_pattern.search(line):\n                sha256sum_match = match.group(1)\n                break\n\n    if not sha256sum_match:\n        raise Exception(f\"Checksum for {file_path} not found in {release_file}\")\n\n    if hash_file(hashlib.sha256(), output_file) != sha256sum_match:\n        raise Exception(f\"Checksum mismatch for {output_file}\")\n\n\n"


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

  def request(self, requests, policy=None, logical=ORIGIN):
    with mock.patch.object(material, "load_policy", return_value=policy or self.policy):
      material.download_file(logical, self.dest, requests)

  def failure(self, code, requests, policy=None, logical=ORIGIN):
    with self.assertRaises(material.MaterialError) as caught:
      self.request(requests, policy, logical)
    self.assertEqual(caught.exception.code, code)
    self.assertEqual(self.dest.read_bytes(), b"previous verified destination")
    self.assertEqual(list(self.root.glob(".polaris-material-*")), [])
    self.assertNotIn("proxy credentials", self.log.getvalue())

  def test_policy_and_patch_fixed_identity_and_import_has_no_effect(self):
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


  def test_named_file_labels_and_exact_resource_basenames(self):
    resources = [
      ("dists/bullseye/Packages", "Packages"),
      ("dists/bullseye/main/binary-amd64/Packages.xz", "Packages.xz"),
      ("dists/bullseye/Release", "Release"),
      ("dists/bullseye/Release.gpg", "Release.gpg"),
      ("pool/main/f/fixture/libfixture_1:2+build1_amd64.deb",
       "libfixture_1%3A2%2Bbuild1_amd64.deb"),
      ("pool/main/f/fixture/libfixture_1%3A2%2Bbuild1_amd64.deb",
       "libfixture_1%3A2%2Bbuild1_amd64.deb"),
    ]
    for prefix in self.policy["archivePrefixes"]:
      for resource, basename in resources:
        logical = "https://snapshot.debian.org" + prefix + "/" + resource
        for filename in (None, "0" * 64, "f" * 64, basename):
          path = "/file/" + "a" * 40 + ("/" + filename if filename else "")
          for location in (logical, path, "https://snapshot.debian.org" + path,
                   "https://snapshot-cloudflare.debian.org" + path):
            with self.subTest(logical=logical, location=location):
              old = self.dest.read_bytes()
              def observe():
                self.assertEqual(self.dest.read_bytes(), old)
              responses = [Response(status=302, headers={"Location": location}),
                     Response(body=b"not a filename digest", observe=observe)]
              requests = Requests(*responses)
              self.request(requests, logical=logical)
              host = "snapshot-cloudflare.debian.org" if "cloudflare" in location else "snapshot.debian.org"
              self.assertEqual([url for url, _ in requests.calls],
                       [logical, logical if location == logical else "https://" + host + path])
              self.assertEqual(self.dest.read_bytes(), b"not a filename digest")
              if filename in ("0" * 64, "f" * 64):
                self.assertNotEqual(hashlib.sha256(self.dest.read_bytes()).hexdigest(), filename)
              self.assertTrue(all(response.closed for response in responses))
              self.assertTrue(requests.session_closed)
              self.assertEqual(list(self.root.glob(".polaris-material-*")), [])

  def test_named_file_relative_mirror_and_shared_request_hop_budget(self):
    for filename in ("0" * 64, "Release"):
      path = "/file/" + "b" * 40 + "/" + filename
      responses = [Response(status=503), Response(status=302, headers={"Location": path}), Response(body=b"done")]
      requests = Requests(*responses)
      with mock.patch.object(material.time, "sleep"):
        self.request(requests)
      self.assertEqual([url for url, _ in requests.calls],
               [ORIGIN, MIRROR, "https://snapshot-cloudflare.debian.org" + path])
      for statuses, code in [([302, 302, 302, 200], None),
                 ([302] * 4, "REDIRECT_BUDGET"),
                 ([302, 503, 503, 503], "HTTP_TRANSIENT_EXHAUSTED")]:
        self.dest.write_bytes(b"previous verified destination")
        responses = [Response(status=status, headers={"Location": path}, body=b"done") for status in statuses]
        requests = Requests(*responses)
        with mock.patch.object(material.time, "sleep"):
          if code:
            self.failure(code, requests)
          else:
            self.request(requests)
        self.assertEqual(len(requests.calls), 4)
        self.assertTrue(all(response.closed for response in responses))

  def test_named_file_refuses_malformed_identity_without_fallback(self):
    root = "/file/" + "a" * 40
    invalid = [("/file/" + first + "/" + "0" * 64, "REDIRECT_IDENTITY")
           for first in ("a" * 39, "a" * 41, "a" * 64, "A" * 40, "g" * 40)]
    invalid += [(root + "/" + suffix, "REDIRECT_IDENTITY") for suffix in (
      "", "0" * 63, "0" * 65, "A" * 64, "g" * 64, "Release/", "/Release",
      "Release/extra", ".", "..", "../" + "a" * 40 + "/Release", "%2e", "%2e%2e",
      "%2fRelease", "%5cRelease", "Release%2Egpg", "Release%00", "Release%7f",
      "Release%252f", "Other", "Packages.xz", "Rélease", "Release\\extra")]
    invalid += [
      (root + "/Release?x=1", "URL_AUTHORITY_OR_QUERY"),
      (root + "/Release?", "URL_AUTHORITY_OR_QUERY"),
      (root + "/Release#", "URL_AUTHORITY_OR_QUERY"),
      (root + "/Release\x00", "URL_IDENTITY"),
      ("\x00" + root + "/Release", "URL_IDENTITY"),
      (root + "/Release\x7f", "URL_IDENTITY"),
      ("https://example.invalid" + root + "/Release", "URL_AUTHORITY_OR_QUERY"),
      ("http://snapshot.debian.org" + root + "/Release", "URL_AUTHORITY_OR_QUERY"),
      ("https://u@snapshot.debian.org" + root + "/Release", "URL_AUTHORITY_OR_QUERY"),
      ("https://snapshot.debian.org:443" + root + "/Release", "URL_AUTHORITY_OR_QUERY"),
    ]
    for location, code in invalid:
      with self.subTest(location=location):
        response = Response(status=302, headers={"Location": location})
        requests = Requests(response)
        self.failure(code, requests)
        self.assertEqual(len(requests.calls), 1)
        self.assertTrue(response.closed and requests.session_closed)
    logical = ORIGIN.rsplit("/", 1)[0] + "/libfixture_1:2+build1_amd64.deb"
    for filename in ("libfixture_1:2+build1_amd64.deb",
             "libfixture_1%3a2%2bbuild1_amd64.deb",
             "libfixture_1%253A2%252Bbuild1_amd64.deb"):
      requests = Requests(Response(status=302, headers={"Location": root + "/" + filename}))
      self.failure("REDIRECT_IDENTITY", requests, logical=logical)
      self.assertEqual(len(requests.calls), 1)

    responses = [Response(status=302, headers={"Location": root}),
           Response(status=302, headers={"Location": "a" * 40 + "//Release"})]
    requests = Requests(*responses)
    self.failure("REDIRECT_IDENTITY", requests)
    self.assertEqual(len(requests.calls), 2)
    self.assertTrue(all(response.closed for response in responses))

  def test_named_file_retains_pinned_gpg_then_packages_checksum(self):
    self.assertEqual(material.digest(VERIFY_CALLER.encode()), "5b930889ae475073e5b737b3c828694d4516756f48923905f2a67d482f3d03c8")
    self.assertEqual(material.digest(DOWNLOAD_NON_UNIQUE.encode()), "5c28e8486017c75e4d2bd81d1e79b93577a696ec0ffe836f386a67529f704e68")
    self.assertEqual(material.digest(ATOMIC_COPY.encode()), "e5a9765786bb4961cef6e391d4c5f9a1e9993112c94fa910accf3755e093f821")
    for failure in ("gpg", "packages", None):
      with self.subTest(failure=failure):
        build = self.root / (failure or "valid")
        build.mkdir()
        listing = build / "Packages.xz"
        listing.write_bytes(b"controlled packages")
        keyring = build / "keyring"
        keyring.write_bytes(b"controlled keyring")
        checksum = hashlib.sha256(b"corrupt" if failure == "packages" else listing.read_bytes()).hexdigest()
        release = ("SHA256:\n " + checksum + " 19 main/binary-amd64/Packages.xz\n").encode()
        responses = [Response(status=302, headers={"Location": "/file/" + "a" * 40 + "/Release"}),
               Response(body=release),
               Response(status=302, headers={"Location": "/file/" + "b" * 40 + "/Release.gpg"}),
               Response(body=b"controlled signature")]
        requests = Requests(*responses)
        namespace = self.caller_namespace(requests)
        namespace.update(ARCHIVE_URL=ORIGIN.split("/dists/", 1)[0],
                 RELEASE_FILE="Release", RELEASE_FILE_GPG="Release.gpg", KEYRING_FILE=str(keyring))
        hash_probe = mock.Mock(wraps=namespace["hash_file"])
        effect = subprocess.CalledProcessError(1, "gpgv") if failure == "gpg" else None
        with mock.patch.dict(sys.modules, {"polaris_cronet_material": material}), \
           mock.patch.object(material, "load_policy", return_value=self.policy), \
           mock.patch.object(subprocess, "run", side_effect=effect) as verify, \
           mock.patch.dict(namespace, {"hash_file": hash_probe}):
          if failure == "gpg":
            with self.assertRaises(subprocess.CalledProcessError):
              namespace["verify_package_listing"]("main/binary-amd64/Packages.xz", str(listing), "bullseye", str(build))
          elif failure == "packages":
            with self.assertRaisesRegex(Exception, "Checksum mismatch"):
              namespace["verify_package_listing"]("main/binary-amd64/Packages.xz", str(listing), "bullseye", str(build))
          else:
            namespace["verify_package_listing"]("main/binary-amd64/Packages.xz", str(listing), "bullseye", str(build))
        self.assertEqual(verify.call_count, 1)
        self.assertEqual(verify.call_args.args[0][0], "gpgv")
        self.assertTrue(verify.call_args.kwargs["check"])
        self.assertEqual(hash_probe.call_count, 0 if failure == "gpg" else 1)
        self.assertEqual(len(requests.calls), 4)
        self.assertTrue(all(response.closed for response in responses))
        self.assertEqual(list(self.root.glob(".polaris-material-*")), [])

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
           "subprocess": subprocess, "re": re, "shutil": shutil, "tempfile": tempfile,
           "banner": lambda text: None, "sub_banner": lambda text: None}
    exec(candidate, namespace)
    exec(ATOMIC_COPY + DOWNLOAD_NON_UNIQUE + DOWNLOAD_OR_COPY + HASH_FILE +
       INSTALL_CALLER + VERIFY_CALLER, namespace)
    return namespace

  def test_actual_patched_wrapper_preserves_original_deb_hash_before_extract(self):
    helper = self.policy["helper"]
    # These are exact unchanged pinned upstream function slices, not a
    # replacement checksum implementation. No .deb or toolchain is acquired.
    self.assertEqual(material.digest(INSTALL_CALLER.encode()), "e37e57a90a34e778fae0db1f79bbd5cb6514a5476a90cbf2d1c073f0ea8a1114")
    for good in (False, True):
      with self.subTest(good=good):
        responses = [Response(status=302, headers={"Location": "/file/" + "a" * 40 + "/" + "f" * 64}),
               Response(body=b"controlled package bytes")]
        requests = Requests(*responses)
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
        self.assertEqual(len(requests.calls), 2)
        self.assertTrue(all(response.closed for response in responses))
        if good:
          self.assertEqual(extract.call_args.args[0][0], "dpkg-deb")




class CandidateDataTests(unittest.TestCase):
  def setUp(self):
    self.temporary = tempfile.TemporaryDirectory()
    self.addCleanup(self.temporary.cleanup)
    self.root = Path(self.temporary.name)

  def store(self, empty=False):
    from test_cronet_material_supply import fixture_bundle
    bundle = fixture_bundle()
    store = self.root / "store"
    store.mkdir(mode=0o700)
    (store / "objects").mkdir(mode=0o700)
    manifest = dict(bundle["manifest"], state="PARTIAL", profiles=[])
    if empty:
      manifest["objects"] = []
    for item in manifest["objects"]:
      path = store / item["member"]
      if not path.exists():
        path.write_bytes(bundle["payloads"][item["url"]])
    (store / "candidate-manifest.json").write_bytes(
      (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode())
    return store, bundle

  def test_reuse_is_zero_network_storage_telemetry_not_http200(self):
    store, bundle = self.store()
    url = bundle["manifest"]["objects"][0]["url"]
    requests = Requests()
    log = io.StringIO()
    with mock.patch.dict(os.environ, {"POLARIS_CRONET_RAW_STORE": str(store)}), \
       mock.patch.object(material, "_CHARGED", 0), \
       mock.patch.object(material, "_CANDIDATES_USED", {}), contextlib.redirect_stdout(log):
      os.environ.pop("POLARIS_CRONET_CAPTURE_DIR", None)
      material.download_file(url, self.root / "copy", requests)
    self.assertEqual((self.root / "copy").read_bytes(), bundle["payloads"][url])
    self.assertEqual(requests.calls, [])
    records = [json.loads(line) for line in log.getvalue().splitlines()]
    self.assertEqual([record["phase"] for record in records], ["candidate_reuse"])
    self.assertEqual(records[0]["requests"], 0)
    self.assertNotIn("status", records[0])

  def test_missing_strict_candidate_never_falls_back_to_snapshot(self):
    store, bundle = self.store(empty=True)
    requests = Requests()
    with mock.patch.dict(os.environ, {"POLARIS_CRONET_RAW_STORE": str(store)}):
      os.environ.pop("POLARIS_CRONET_CAPTURE_DIR", None)
      with self.assertRaises(material.MaterialError) as caught:
        material.download_file(ORIGIN, self.root / "missing", requests)
    self.assertEqual(caught.exception.code, "CANDIDATE_REQUIRED_MISSING")
    self.assertEqual(requests.calls, [])
    self.assertFalse((self.root / "missing").exists())

  def test_capture_only_promotes_complete_eof_candidates(self):
    for failed in (False, True):
      with self.subTest(failed=failed), tempfile.TemporaryDirectory(dir=self.root) as temporary:
        trial = Path(temporary)
        store = trial / "raw"
        store.mkdir(mode=0o700)
        (store / "objects").mkdir(mode=0o700)
        from test_cronet_material_supply import fixture_bundle
        manifest = dict(fixture_bundle()["manifest"], state="PARTIAL", profiles=[], objects=[])
        (store / "candidate-manifest.json").write_bytes(material_json(manifest))
        response = Response(body=b"complete candidate", fail_after=1 if failed else None)
        requests = Requests(*[Response(body=b"complete candidate", fail_after=1) for _ in range(4)]) if failed else Requests(response)
        with mock.patch.dict(os.environ, {"POLARIS_CRONET_RAW_STORE": str(store),
             "POLARIS_CRONET_CAPTURE_DIR": str(store), "POLARIS_CRONET_CAPTURE_PROFILE": "bullseye-amd64"}), \
           mock.patch.object(material, "_CHARGED", 0), mock.patch.object(material, "_CANDIDATES_USED", {}), \
           mock.patch.object(material, "_LOG_BYTES", 0):
          if failed:
            with self.assertRaises(material.MaterialError):
              material.download_file(ORIGIN, trial / "dest", requests)
          else:
            material.download_file(ORIGIN, trial / "dest", requests)
        actual = json.loads((store / "candidate-manifest.json").read_bytes())
        self.assertEqual(len(actual["objects"]), 0 if failed else 1)
        self.assertEqual(actual["state"], "PARTIAL")
        self.assertEqual(actual["profiles"], [])
        self.assertEqual(len(list((store / "objects").iterdir())), 0 if failed else 1)


  def test_reuse_obeys_original_object_alarm_and_restores_state(self):
    store, bundle = self.store()
    url = bundle["manifest"]["objects"][0]["url"]
    requests = Requests()
    destination = self.root / "deadline-copy"
    previous = signal.getsignal(signal.SIGALRM)
    timer = signal.getitimer(signal.ITIMER_REAL)
    actual_read = material.os.read
    identity = (store / bundle["manifest"]["objects"][0]["member"]).stat()
    actual_alarm = material._object_alarm
    def slow_raw(fd, maximum):
      if os.path.samestat(os.fstat(fd), identity):
        time.sleep(0.1)
      return actual_read(fd, maximum)
    with mock.patch.dict(os.environ, {"POLARIS_CRONET_RAW_STORE": str(store)}), \
       mock.patch.object(material, "_CHARGED", 0), \
       mock.patch.object(material, "_CANDIDATES_USED", {}), \
       mock.patch.object(material.os, "read", side_effect=slow_raw), \
       mock.patch.object(material, "_object_alarm", side_effect=lambda seconds: actual_alarm(0.02)) as alarm:
      os.environ.pop("POLARIS_CRONET_CAPTURE_DIR", None)
      with self.assertRaises(material.MaterialError) as caught:
        material.download_file(url, destination, requests)
    self.assertEqual(caught.exception.code, "OBJECT_DEADLINE")
    self.assertEqual(alarm.call_count, 1)
    self.assertEqual(requests.calls, [])
    self.assertFalse(destination.exists())
    self.assertIs(signal.getsignal(signal.SIGALRM), previous)
    self.assertEqual(signal.getitimer(signal.ITIMER_REAL), timer)


  @contextlib.contextmanager
  def observe_cas_reads(self, path, failure=False):
    identity = path.stat()
    actual = material.os.read
    reads = []
    def read(fd, maximum):
      if os.path.samestat(os.fstat(fd), identity):
        reads.append((maximum, material._CHARGED))
        if failure:
          actual(fd, min(3, maximum))
          raise OSError("partial CAS read fixture")
      return actual(fd, maximum)
    with mock.patch.object(material.os, "read", side_effect=read):
      yield reads

  def test_reuse_rejects_remaining_budget_before_cas_body_reader(self):
    store, bundle = self.store()
    item = bundle["manifest"]["objects"][0]
    self.assertGreater(item["bytes"], 0)
    cap = material.load_policy()["limits"]["creatorProcessBytes"]
    initial = cap - item["bytes"] + 1
    requests = Requests()
    actual_open = material.os.open
    target = store / item["member"]
    def open_file(path, flags, *args, **kwargs):
      if Path(path) == target:
        raise AssertionError("insufficient budget reached the CAS file")
      return actual_open(path, flags, *args, **kwargs)
    with mock.patch.dict(os.environ, {"POLARIS_CRONET_RAW_STORE": str(store)}), \
       mock.patch.object(material, "_CHARGED", initial), \
       mock.patch.object(material, "_CANDIDATES_USED", {}), \
       mock.patch.object(material.os, "open", side_effect=open_file), \
       self.observe_cas_reads(target) as reads:
      os.environ.pop("POLARIS_CRONET_CAPTURE_DIR", None)
      with self.assertRaises(material.MaterialError) as caught:
        material.download_file(item["url"], self.root / "budget-denied", requests)
      self.assertEqual(caught.exception.code, "PROCESS_BYTES")
      self.assertEqual(material._CHARGED, initial)
      self.assertEqual(material._CANDIDATES_USED, {})
    self.assertEqual(reads, [])
    self.assertEqual(requests.calls, [])
    self.assertFalse((self.root / "budget-denied").exists())

  def test_reuse_exact_remaining_budget_reads_no_extra_probe_byte(self):
    store, bundle = self.store()
    item = bundle["manifest"]["objects"][0]
    cap = material.load_policy()["limits"]["creatorProcessBytes"]
    initial = cap - item["bytes"]
    requests = Requests()
    destination = self.root / "exact-budget"
    with mock.patch.dict(os.environ, {"POLARIS_CRONET_RAW_STORE": str(store)}), \
       mock.patch.object(material, "_CHARGED", initial), \
       mock.patch.object(material, "_CANDIDATES_USED", {}), \
       self.observe_cas_reads(store / item["member"]) as reads:
      os.environ.pop("POLARIS_CRONET_CAPTURE_DIR", None)
      material.download_file(item["url"], destination, requests)
      self.assertEqual(material._CHARGED, cap)
    self.assertEqual(reads, [(item["bytes"], cap)])
    self.assertEqual(destination.read_bytes(), bundle["payloads"][item["url"]])
    self.assertEqual(requests.calls, [])

  def test_reuse_read_and_integrity_errors_keep_full_reservation(self):
    store, bundle = self.store()
    item = bundle["manifest"]["objects"][0]
    target = store / item["member"]
    payload = bundle["payloads"][item["url"]]
    self.assertGreater(len(payload), 0)
    for failure in ("read", "hash", "short", "size"):
      with self.subTest(failure=failure):
        if failure == "hash":
          target.write_bytes(bytes([payload[0] ^ 1]) + payload[1:])
        elif failure == "size":
          target.write_bytes(payload + b"x")
        else:
          target.write_bytes(payload)
        requests = Requests()
        destination = self.root / ("failed-" + failure)
        actual_read = material.os.read
        identity = target.stat()
        def short(fd, maximum):
          if os.path.samestat(os.fstat(fd), identity):
            return actual_read(fd, max(0, maximum - 1))
          return actual_read(fd, maximum)
        short_read = (mock.patch.object(material.os, "read", side_effect=short)
                      if failure == "short" else contextlib.nullcontext())
        with mock.patch.dict(os.environ, {"POLARIS_CRONET_RAW_STORE": str(store)}), \
           mock.patch.object(material, "_CHARGED", 0), \
           mock.patch.object(material, "_CANDIDATES_USED", {}), \
           short_read, \
           self.observe_cas_reads(target, failure=failure == "read") as reads:
          os.environ.pop("POLARIS_CRONET_CAPTURE_DIR", None)
          with self.assertRaises(material.MaterialError) as caught:
            material.download_file(item["url"], destination, requests)
          self.assertEqual(caught.exception.code,
                           "SOURCE_FILE_READ" if failure == "read" else "CANDIDATE_INTEGRITY")
          self.assertEqual(material._CHARGED, item["bytes"])
          self.assertEqual(material._CANDIDATES_USED, {})
        self.assertEqual(reads, [] if failure == "size" else [(item["bytes"], item["bytes"])])
        self.assertEqual(requests.calls, [])
        self.assertFalse(destination.exists())



def material_json(value):
  return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


if __name__ == "__main__":
  unittest.main()
