#!/usr/bin/env python3
"""Pinned CI overlay and bounded Debian transport; import performs no I/O."""
import argparse
import contextlib
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

POLICY_SHA256 = "d1d1a6414ba2c947f8b12292b09d243682d1dccd2cea7818bbee7911dc0187e5"
REPLACEMENT = "def download_file(url: str, dest: str, retries=5) -> None:\n    # Fixed source-owned transport; retries cannot override its global budgets.\n    from polaris_cronet_material import download_file as bounded_download\n    bounded_download(url, dest, requests)\n\n\n".encode()
_CHARGED = 0
_LOG_BYTES = 0


class MaterialError(Exception):
  def __init__(self, code):
    self.code = code
    super().__init__(code)


class _Transient(Exception):
  pass


def digest(data):
  return hashlib.sha256(data).hexdigest()


def read_regular(path, maximum=1048576):
  path = Path(path)
  try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as handle:
      info = os.fstat(handle.fileno())
      if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
        raise MaterialError("SOURCE_FILE_KIND_OR_OWNER")
      data = handle.read(maximum + 1)
      if len(data) > maximum:
        raise MaterialError("SOURCE_FILE_SIZE")
      return data
  except OSError:
    raise MaterialError("SOURCE_FILE_READ") from None


def load_policy():
  source = Path(__file__).absolute()
  if source.name == "polaris_cronet_material.py":
    path = source.with_name("polaris_cronet_material_inputs.json")
  else:
    path = source.parents[2] / "release/ci/cronet-material-inputs.json"
  raw = read_regular(path, 16384)
  if digest(raw) != POLICY_SHA256:
    raise MaterialError("POLICY_DIGEST")
  return json.loads(raw)


def _emit(policy, **fields):
  # Only caller-owned classes and approved public URLs enter this log.
  global _LOG_BYTES
  line = json.dumps(fields, sort_keys=True, separators=(",", ":"))
  size = len(line.encode()) + 1
  if size <= 4096 and _LOG_BYTES + size <= policy["limits"]["logBytes"]:
    print(line, flush=True)
    _LOG_BYTES += size


def _directory(path):
  path = Path(path).absolute()
  for entry in (path, *path.parents):
    info = entry.lstat()
    if not stat.S_ISDIR(info.st_mode):
      raise MaterialError("DIRECTORY_KIND")
  if path.stat().st_uid != os.geteuid():
    raise MaterialError("DIRECTORY_OWNER")


def _create_parent(path):
  path = Path(path).absolute()
  missing = []
  current = path
  while not current.exists() and not current.is_symlink():
    missing.append(current)
    current = current.parent
  _directory(current)
  for entry in reversed(missing):
    entry.mkdir(mode=0o700)
    _directory(entry)


def _destination(path):
  path = Path(path).absolute()
  _directory(path.parent)
  if path.exists() or path.is_symlink():
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
      raise MaterialError("DESTINATION_KIND_OR_OWNER")
  return path


def _atomic_bytes(path, data, absent=False, mode=0o600):
  path = _destination(path)
  if absent and path.exists():
    raise MaterialError("COPY_COLLISION")
  temporary = None
  try:
    with tempfile.NamedTemporaryFile(mode="wb", prefix=".polaris-material-",
                     dir=path.parent, delete=False) as handle:
      temporary = Path(handle.name)
      os.fchmod(handle.fileno(), mode)
      handle.write(data)
      handle.flush()
      os.fsync(handle.fileno())
    _destination(path)
    if absent and path.exists():
      raise MaterialError("COPY_COLLISION")
    os.replace(temporary, path)
    temporary = None
  finally:
    if temporary is not None:
      temporary.unlink(missing_ok=True)


def _git(root, *args):
  env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_NO_LAZY_FETCH="1",
         GIT_TERMINAL_PROMPT="0")
  try:
    return subprocess.check_output(
      ["git", "--no-optional-locks", "-C", str(root), *args],
      env=env, stderr=subprocess.DEVNULL, timeout=20).decode().strip()
  except (OSError, subprocess.SubprocessError, UnicodeError):
    raise MaterialError("SOURCE_GIT_IDENTITY") from None


def apply_overlay(source, patch, policy):
  helper = policy["helper"]
  if digest(source) != policy["sourceSHA256"][helper]:
    raise MaterialError("HELPER_PREIMAGE")
  if digest(patch) != policy["overlaySHA256"]:
    raise MaterialError("OVERLAY_DIGEST")
  begin = source.index(b"def download_file(")
  end = source.index(b"def get_build_dir(", begin)
  if digest(source[begin:end]) != policy["downloadFunctionSHA256"]:
    raise MaterialError("OVERLAY_FUNCTION_BOUNDARY")
  result = source[:begin] + REPLACEMENT + source[end:]
  if digest(result) != policy["postimageSHA256"]:
    raise MaterialError("HELPER_POSTIMAGE")
  expected = "".join(difflib.unified_diff(
    source.decode().splitlines(True), result.decode().splitlines(True),
    fromfile="a/" + helper, tofile="b/" + helper, n=3)).encode()
  if patch != expected:
    raise MaterialError("OVERLAY_EXACT_DIFF")
  return result


def _prepare(root, source_root, policy):
  root = Path(root).absolute()
  source_root = Path(source_root).absolute()
  naive = root / "naiveproxy"
  _directory(root)
  _directory(naive)
  if _git(root, "rev-parse", "HEAD") != policy["cronetCommit"]:
    raise MaterialError("CRONET_PIN")
  expected = "160000 commit " + policy["naiveCommit"] + "\tnaiveproxy"
  if _git(root, "ls-tree", "HEAD", "--", "naiveproxy") != expected:
    raise MaterialError("NAIVE_GITLINK")
  if _git(naive, "rev-parse", "HEAD") != policy["naiveCommit"]:
    raise MaterialError("NAIVE_PIN")
  names = tuple(policy["sourceSHA256"])
  if _git(naive, "diff", "--name-only", "HEAD", "--", *names):
    raise MaterialError("DIRTY_UPSTREAM_HELPER")
  actual = {}
  for name, expected_sha in policy["sourceSHA256"].items():
    path = naive / name
    _directory(path.parent)
    actual[name] = read_regular(path)
    if digest(actual[name]) != expected_sha:
      raise MaterialError("UPSTREAM_PREIMAGE")
  patch = read_regular(source_root / ".github/patches/cronet-sysroot-transport.patch")
  result = apply_overlay(actual[policy["helper"]], patch, policy)
  module = read_regular(source_root / "scripts/ci/cronet_material_bootstrap.py")
  policy_raw = read_regular(source_root / "release/ci/cronet-material-inputs.json", 16384)
  if digest(policy_raw) != POLICY_SHA256:
    raise MaterialError("POLICY_DIGEST")
  target = naive / Path(policy["helper"]).parent
  copies = [(target / policy["copyNames"]["module"], module),
        (target / policy["copyNames"]["policy"], policy_raw)]
  for path, _ in copies:
    if path.exists() or path.is_symlink():
      raise MaterialError("COPY_COLLISION")
  installed = []
  try:
    for path, content in copies:
      _atomic_bytes(path, content, absent=True)
      installed.append((path, path.stat()))
      if read_regular(path) != content:
        raise MaterialError("COPY_POSTIMAGE")
    helper_path = naive / policy["helper"]
    if read_regular(helper_path) != actual[policy["helper"]]:
      raise MaterialError("HELPER_CHANGED_BEFORE_PUBLISH")
    _atomic_bytes(helper_path, result, mode=stat.S_IMODE(helper_path.stat().st_mode))
  except BaseException:
    for path, identity in installed:
      if path.exists() and os.path.samestat(identity, path.lstat()):
        path.unlink()
    raise
  _emit(policy, phase="prepared", cronet=policy["cronetCommit"],
      naive=policy["naiveCommit"], policySHA256=digest(policy_raw),
      bootstrapSHA256=digest(module), overlaySHA256=digest(patch),
      helperBeforeSHA256=digest(actual[policy["helper"]]),
      helperAfterSHA256=digest(result),
      copiedModuleSHA256=digest(read_regular(copies[0][0])),
      copiedPolicySHA256=digest(read_regular(copies[1][0])))


def prepare(root):
  source_root = Path(__file__).absolute().parents[2]
  policy = load_policy()
  version = read_regular(source_root / ".github/CRONET_GO_VERSION", 128)
  if version.decode().strip() != policy["cronetCommit"]:
    raise MaterialError("SOURCE_CRONET_VERSION")
  _prepare(root, source_root, policy)


@contextlib.contextmanager
def _object_alarm(seconds):
  # The existing creator runs on Linux's main thread. Refuse unsupported or
  # conflicting callers, without changing any pre-existing alarm state.
  if sys.platform != "linux" or threading.current_thread() is not threading.main_thread():
    raise MaterialError("DEADLINE_CONTEXT")
  saved_timer = signal.getitimer(signal.ITIMER_REAL)
  if saved_timer != (0.0, 0.0):
    raise MaterialError("DEADLINE_TIMER_CONFLICT")
  saved_handler = signal.getsignal(signal.SIGALRM)

  def expired(signum, frame):
    raise MaterialError("OBJECT_DEADLINE")

  signal.signal(signal.SIGALRM, expired)
  try:
    signal.setitimer(signal.ITIMER_REAL, seconds)
    yield
  finally:
    signal.setitimer(signal.ITIMER_REAL, 0)
    signal.signal(signal.SIGALRM, saved_handler)


def _url(url, policy, logical=None):
  if (not isinstance(url, str) or len(url) > 2048
      or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url)):
    raise MaterialError("URL_IDENTITY")
  try:
    value = urlsplit(url)
  except ValueError:
    raise MaterialError("URL_IDENTITY") from None
  if (value.scheme != "https" or value.netloc not in policy["authorities"]
      or value.fragment or value.query or "?" in url or "#" in url):
    raise MaterialError("URL_AUTHORITY_OR_QUERY")
  if logical is None:
    if value.netloc != policy["authorities"][0]:
      raise MaterialError("LOGICAL_ORIGIN")
    if not any(value.path.startswith(prefix) for prefix in policy["archivePrefixes"]):
      raise MaterialError("ARCHIVE_IDENTITY")
    if re.search(r"(?i)%2f|%5c|%2e", value.path) or "\\" in value.path or ".." in value.path.split("/"):
      raise MaterialError("URL_PATH_IDENTITY")
  elif value.path != urlsplit(logical).path:
    content = re.fullmatch(r"/file/[0-9a-f]{40}(?:/([^/]+))?", value.path)
    if content is None:
      raise MaterialError("REDIRECT_IDENTITY")
    filename = content.group(1)
    if filename is not None and not re.fullmatch(r"[0-9a-f]{64}", filename):
      # Snapshot's optional filename is a label, never a second body digest.
      basename = urlsplit(logical).path.rsplit("/", 1)[-1]
      resource = r"(?:Packages(?:\.xz)?|Release(?:\.gpg)?|[A-Za-z0-9](?:[A-Za-z0-9._+~:-]|%(?:2B|3A))*\.deb)"
      if not re.fullmatch(resource, basename) or filename != quote(basename, safe="%"):
        raise MaterialError("REDIRECT_IDENTITY")
  return value


def _source_url(logical, host):
  value = urlsplit(logical)
  # Keep the original path, including its double slash, and query unchanged.
  return urlunsplit((value.scheme, host, value.path, value.query, ""))


def _piece(response, maximum, requests_module):
  # Read bounded undecoded bytes without abandoning a chunked stream iterator.
  errors = requests_module.packages.urllib3.exceptions
  try:
    return response.raw.read(min(8192, maximum), decode_content=False)
  except errors.SSLError:
    raise requests_module.exceptions.SSLError() from None
  except errors.ReadTimeoutError:
    raise requests_module.exceptions.ReadTimeout() from None
  except errors.HTTPError:
    raise MaterialError("NETWORK_PERMANENT") from None


def _receive(response, destination, policy, consumed, owned, requests_module):
  # A failed raw read keeps its full reservation: unknown partial bytes cannot
  # escape the caps. Successful reads refund the known unused reservation.
  global _CHARGED
  limits = policy["limits"]
  encoding = response.headers.get("Content-Encoding", "").lower()
  if encoding not in ("", "identity"):
    raise MaterialError("CONTENT_ENCODING")
  length = response.headers.get("Content-Length")
  if length is not None:
    if not length.isascii() or not length.isdigit() or len(length) > 20:
      raise MaterialError("CONTENT_LENGTH")
    length = int(length)
    if length > limits["objectBytes"] - consumed[0]:
      raise MaterialError("OBJECT_BYTES")
    if length > limits["creatorProcessBytes"] - _CHARGED:
      raise MaterialError("PROCESS_BYTES")
  temporary = None
  size = 0
  try:
    with tempfile.NamedTemporaryFile(mode="wb", prefix=".polaris-material-",
                     dir=destination.parent, delete=False) as handle:
      temporary = Path(handle.name)
      owned.append(temporary)
      while length is None or size < length:
        available = min(limits["objectBytes"] - consumed[0],
                limits["creatorProcessBytes"] - _CHARGED)
        if available <= 0:
          raise MaterialError("BODY_BUDGET_NO_VERIFIED_EOF")
        if length is not None:
          available = min(available, length - size)
        requested = min(8192, available)
        consumed[0] += requested
        _CHARGED += requested
        chunk = _piece(response, requested, requests_module)
        if len(chunk) > requested:
          raise MaterialError("RESPONSE_CHUNK_CONTRACT")
        consumed[0] -= requested - len(chunk)
        _CHARGED -= requested - len(chunk)
        if not chunk:
          if length is not None and size != length:
            raise MaterialError("SHORT_BODY")
          break
        size += len(chunk)
        handle.write(chunk)
      handle.flush()
      os.fsync(handle.fileno())
    completed = temporary
    temporary = None
    return completed, size
  finally:
    if temporary is not None:
      temporary.unlink(missing_ok=True)


def _manual_session(requests_module):
  # requests otherwise drains redirect bodies to prepare Response.next even
  # with allow_redirects=False. Only this controller may handle redirects.
  class ManualSession(requests_module.Session):
    def resolve_redirects(self, *args, **kwargs):
      return iter(())
  return ManualSession()




# Only complete raw data cross the supplier/consumer boundary. This hook is in
# the source-prepared controller copied beside the pinned original creator.
_CANDIDATES_USED = {}


def _candidate_manifest(root, policy):
  root = Path(root).absolute()
  _directory(root)
  data = read_regular(root / "candidate-manifest.json", 1048576)
  def pairs(items):
    result = {}
    for key, value in items:
      if key in result:
        raise MaterialError("CANDIDATE_DUPLICATE_KEY")
      result[key] = value
    return result
  manifest = json.loads(data, object_pairs_hook=pairs)
  if (type(manifest) is not dict
      or manifest.get("schema") != "polaris-debian-candidate-v1"
      or manifest.get("scope") != "debian-raw"
      or type(manifest.get("objects")) is not list
      or len(manifest["objects"]) > 512):
    raise MaterialError("CANDIDATE_MANIFEST")
  urls, members = {}, {}
  for item in manifest["objects"]:
    if (type(item) is not dict
        or set(item) != {"url", "member", "sha256", "bytes", "profiles", "complete"}
        or type(item["url"]) is not str or item["url"] in urls
        or type(item["sha256"]) is not str
        or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None
        or item["member"] != "objects/" + item["sha256"]
        or type(item["bytes"]) is not int
        or not 0 <= item["bytes"] <= policy["limits"]["objectBytes"]
        or item["complete"] is not True):
      raise MaterialError("CANDIDATE_OBJECT")
    _url(item["url"], policy)
    if item["member"] in members and members[item["member"]] != item["bytes"]:
      raise MaterialError("CANDIDATE_ALIAS")
    members[item["member"]] = item["bytes"]
    urls[item["url"]] = item
  if sum(members.values()) > policy["limits"]["creatorProcessBytes"]:
    raise MaterialError("CANDIDATE_UNION_BYTES")
  return manifest, urls


def _capture_candidate(url, destination, policy):
  name = os.environ.get("POLARIS_CRONET_CAPTURE_DIR")
  if not name:
    return
  profile = os.environ.get("POLARIS_CRONET_CAPTURE_PROFILE")
  root = Path(name).absolute()
  manifest, urls = _candidate_manifest(root, policy)
  if profile not in manifest.get("requiredProfiles", []):
    raise MaterialError("CANDIDATE_CAPTURE_PROFILE")
  data = read_regular(destination, policy["limits"]["objectBytes"])
  sha = digest(data)
  member = "objects/" + sha
  item = {"url": url, "member": member, "sha256": sha,
          "bytes": len(data), "profiles": [profile], "complete": True}
  prior = urls.get(url)
  if prior is not None:
    if any(prior[key] != item[key] for key in ("member", "sha256", "bytes")):
      raise MaterialError("CANDIDATE_URL_CHANGED")
    item["profiles"] = sorted(set(prior["profiles"] + [profile]))
  objects = [value for key, value in urls.items() if key != url] + [item]
  unique = {value["member"]: value["bytes"] for value in objects}
  if len(objects) > 512 or sum(unique.values()) > policy["limits"]["creatorProcessBytes"]:
    raise MaterialError("CANDIDATE_CAPTURE_BUDGET")
  target = root / member
  _directory(target.parent)
  if target.exists() or target.is_symlink():
    if read_regular(target, policy["limits"]["objectBytes"]) != data:
      raise MaterialError("CANDIDATE_CAS_COLLISION")
  else:
    _atomic_bytes(target, data, absent=True)
  manifest["objects"] = sorted(objects, key=lambda value: value["url"])
  encoded = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
  if len(encoded) > 1048576:
    raise MaterialError("CANDIDATE_MANIFEST_BYTES")
  _atomic_bytes(root / "candidate-manifest.json", encoded)
  _CANDIDATES_USED[url] = dict(item)


def _reuse_candidate(url, dest, policy):
  global _CHARGED
  name = os.environ.get("POLARIS_CRONET_RAW_STORE")
  if not name:
    return False
  root = Path(name).absolute()
  manifest, urls = _candidate_manifest(root, policy)
  item = urls.get(url)
  if item is None:
    if os.environ.get("POLARIS_CRONET_CAPTURE_DIR"):
      # Supplier may acquire a missing candidate using the unchanged bounded
      # origin controller. Consumers never set capture mode.
      return False
    raise MaterialError("CANDIDATE_REQUIRED_MISSING")
  size = item["bytes"]
  if size > policy["limits"]["creatorProcessBytes"] - _CHARGED:
    raise MaterialError("PROCESS_BYTES")
  # Reserve before any CAS body read. Errors keep the whole reservation.
  # A raw exact-size read avoids read_regular's extra EOF-probe byte.
  _CHARGED += size
  try:
    fd = os.open(root / item["member"], os.O_RDONLY | os.O_NOFOLLOW)
    try:
      info = os.fstat(fd)
      if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
        raise MaterialError("SOURCE_FILE_KIND_OR_OWNER")
      if info.st_size != size:
        raise MaterialError("CANDIDATE_INTEGRITY")
      data = os.read(fd, size)
      if os.fstat(fd).st_size != size:
        raise MaterialError("CANDIDATE_INTEGRITY")
    finally:
      os.close(fd)
  except OSError:
    raise MaterialError("SOURCE_FILE_READ") from None
  if len(data) != size or digest(data) != item["sha256"]:
    raise MaterialError("CANDIDATE_INTEGRITY")
  destination = Path(dest).absolute()
  _create_parent(destination.parent)
  _atomic_bytes(destination, data, absent=True)
  _CANDIDATES_USED[url] = dict(item)
  _capture_candidate(url, destination, policy)
  _emit(policy, phase="candidate_reuse", logicalURL=url, requests=0,
        bodyBytes=len(data), storageSHA256=item["sha256"],
        manifestSHA256=digest(read_regular(root / "candidate-manifest.json")),
        processBudgetChargedBytes=_CHARGED)
  return True


def download_file(url, dest, requests_module):
  """Actual creator transport. Caller alone verifies GPG and content hashes."""
  policy = load_policy()
  _url(url, policy)
  limits = policy["limits"]
  requests_count = 0
  redirects = 0
  consumed = [0]
  started = time.monotonic()
  last_status = None
  last_host = policy["authorities"][0]
  try:
    with _object_alarm(limits["objectWallSeconds"]), contextlib.ExitStack() as resources:
      if _reuse_candidate(url, dest, policy):
        return
      session = resources.enter_context(_manual_session(requests_module))
      destination = Path(dest).absolute()
      _create_parent(destination.parent)
      destination = _destination(destination)
      for attempt in range(limits["sourceAttempts"]):
        current = _source_url(url, policy["authorities"][attempt % 2])
        try:
          while True:
            if requests_count >= limits["httpRequests"]:
              raise MaterialError("HTTP_REQUEST_BUDGET")
            remaining = limits["objectWallSeconds"] - (time.monotonic() - started)
            if remaining <= 0:
              raise MaterialError("OBJECT_DEADLINE")
            actual = _url(current, policy, logical=url)
            last_host = actual.netloc
            requests_count += 1
            last_status = None
            response = None
            owned = []
            try:
              response = session.get(
                current, stream=True, allow_redirects=False,
                timeout=(min(limits["connectSeconds"], remaining),
                     min(limits["readIdleSeconds"], remaining)),
                headers={"Accept-Encoding": "identity"})
              last_status = response.status_code
              _emit(policy, phase="response", logicalURL=url,
                  host=last_host, status=last_status,
                  request=requests_count, sourceAttempt=attempt + 1,
                  budgetChargedBytes=consumed[0])
              if last_status in (301, 302, 303, 307, 308):
                if redirects >= limits["redirectHops"]:
                  raise MaterialError("REDIRECT_BUDGET")
                location = response.headers.get("Location")
                if not location or len(location) > 2048:
                  raise MaterialError("REDIRECT_IDENTITY")
                try:
                  if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in location):
                    raise MaterialError("URL_IDENTITY")
                  if "?" in location or "#" in location:
                    raise MaterialError("URL_AUTHORITY_OR_QUERY")
                  if ("\\" in location
                      or ("//" in urlsplit(location).path
                        and urlsplit(location).path != urlsplit(url).path)
                      or any(p in (".", "..") for p in urlsplit(location).path.split("/"))):
                    raise MaterialError("REDIRECT_IDENTITY")
                  target = urljoin(current, location)
                  _url(target, policy, logical=url)
                except ValueError:
                  raise MaterialError("REDIRECT_IDENTITY") from None
                redirects += 1
                current = target
                continue
              if last_status in policy["transientHTTP"]:
                raise _Transient()
              if last_status != 200:
                raise MaterialError("HTTP_PERMANENT")
              temporary, size = _receive(response, destination, policy, consumed, owned, requests_module)
              try:
                response.close()
              except Exception:
                raise MaterialError("RESPONSE_CLOSE") from None
              response = None
              _destination(destination)
              os.replace(temporary, destination)
              _capture_candidate(url, destination, policy)
              _emit(policy, phase="complete", logicalURL=url,
                  host=last_host, status=last_status,
                  requests=requests_count, bodyBytes=size,
                  budgetChargedBytes=consumed[0],
                  processBudgetChargedBytes=_CHARGED)
              return
            finally:
              for temporary in owned:
                temporary.unlink(missing_ok=True)
              if response is not None:
                try:
                  response.close()
                except Exception:
                  raise MaterialError("RESPONSE_CLOSE") from None
        except requests_module.exceptions.SSLError:
          raise MaterialError("TLS_FAILURE") from None
        except (requests_module.exceptions.Timeout, _Transient):
          if requests_count >= limits["httpRequests"] or attempt + 1 >= limits["sourceAttempts"]:
            raise MaterialError("HTTP_TRANSIENT_EXHAUSTED") from None
          time.sleep((1, 2, 4)[attempt])
        except requests_module.exceptions.RequestException:
          raise MaterialError("NETWORK_PERMANENT") from None
      raise MaterialError("HTTP_TRANSIENT_EXHAUSTED")
  except MaterialError as error:
    _emit(policy, phase="failure", logicalURL=url, host=last_host,
        status=last_status, requests=requests_count,
        budgetChargedBytes=consumed[0], failureClass=error.code)
    raise
  except OSError:
    _emit(policy, phase="failure", logicalURL=url, host=last_host,
        status=last_status, requests=requests_count,
        budgetChargedBytes=consumed[0], failureClass="ATOMIC_IO")
    raise MaterialError("ATOMIC_IO") from None


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  sub = parser.add_subparsers(dest="command", required=True)
  command = sub.add_parser("prepare")
  command.add_argument("--cronet-root", required=True, type=Path)
  args = parser.parse_args()
  try:
    prepare(args.cronet_root)
  except (MaterialError, OSError, ValueError) as error:
    code = error.code if isinstance(error, MaterialError) else "PREPARE_IO_OR_SHAPE"
    print(json.dumps({"phase": "failure", "failureClass": code}), file=sys.stderr)
    return 1
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
