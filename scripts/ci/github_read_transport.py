"""Bounded read-only gh transport; authentication and redirects remain owned by gh.

Never accepts a method or a token. No raw headers, stderr or signed URLs are logged.
Integrity/schema checks stay with the caller and are never retried here.
"""
import hashlib
import os
import re
import selectors
import subprocess
import sys
import time
from datetime import timezone
from email.utils import parsedate_to_datetime

ATTEMPTS = 3
ATTEMPT_SECONDS = 600
TOTAL_SECONDS = 1320
CLEANUP_SECONDS = 5
MAX_EXTRA_GETS = 8
MAX_RETRY_WAIT = 120
HEADER_LIMIT = 65536
ERROR_LIMIT = 65536
RETRY_STATUS = {500, 502, 503, 504}
SAFE_HEADERS = {'date', 'server', 'content-type', 'content-length', 'retry-after',
                'x-github-request-id', 'x-ms-request-id', 'x-ratelimit-limit',
                'x-ratelimit-remaining', 'x-ratelimit-reset', 'x-ratelimit-resource'}
NETWORK_ERRORS = (b'connection reset by peer', b'connection timed out', b'i/o timeout',
                  b'tls handshake timeout', b'client.timeout exceeded', b'unexpected eof')


class ReadFailure(ValueError):
    def __init__(self, kind, status=None, headers=None, retryable=False):
        self.kind, self.status = kind, status
        self.headers, self.retryable = headers or {}, retryable
        super().__init__('GitHub GET failed: ' + kind + ((' HTTP ' + str(status)) if status else ''))


class RetryBudget:
    def __init__(self):
        self.extra_gets = 0
        self.wait_seconds = 0


PROCESS_BUDGET = RetryBudget()


def retry_delay(value, attempt, now):
    if value is None:
        return min(2 ** (attempt - 1), 8)
    value = value.strip()
    if re.fullmatch(r'[0-9]+', value):
        return int(value)
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            raise ValueError()
        return max(0, parsed.astimezone(timezone.utc).timestamp() - now)
    except (TypeError, ValueError, OverflowError):
        raise ReadFailure('invalid Retry-After') from None


def _headers(raw):
    lines = raw.replace(b'\r\n', b'\n').split(b'\n')
    match = re.fullmatch(rb'HTTP/\S+ ([0-9]{3})(?: .*)?', lines[0])
    if not match:
        raise ReadFailure('invalid response status')
    headers = {}
    for line in lines[1:]:
        if not line:
            continue
        if b':' not in line:
            raise ReadFailure('invalid response header')
        key, value = line.split(b':', 1)
        try:
            key = key.decode('ascii', errors='strict').lower()
        except UnicodeError:
            raise ReadFailure('invalid response header') from None
        if key in SAFE_HEADERS:
            if key in headers:
                raise ReadFailure('duplicate diagnostic header')
            try:
                value = value.decode('ascii', errors='strict').strip()
            except UnicodeError:
                raise ReadFailure('invalid diagnostic header') from None
            if len(value) > 256 or any(ord(c) < 32 or ord(c) == 127 for c in value):
                raise ReadFailure('invalid diagnostic header')
            headers[key] = value
    return int(match[1]), headers


def _attempt(path, sink, max_bytes, timeout):
    # --include emits only the final response headers. gh handles redirect auth policy.
    final_deadline = time.monotonic() + timeout
    end = final_deadline - min(CLEANUP_SECONDS, timeout / 2)
    child = subprocess.Popen(['gh', 'api', '--include', '--method', 'GET', path],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    prefix, errors = bytearray(), bytearray()
    status, headers, count = None, {}, 0
    digest = hashlib.sha256()
    try:
        with selectors.SelectSelector() as ready:
            ready.register(child.stdout, selectors.EVENT_READ, 'out')
            ready.register(child.stderr, selectors.EVENT_READ, 'err')
            while ready.get_map():
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise ReadFailure('read deadline', status, headers, status is None or status == 200 or status in RETRY_STATUS)
                for key, _ in ready.select(min(remaining, 1)):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        ready.unregister(key.fileobj)
                        continue
                    if key.data == 'err':
                        # Drain without unbounded memory; never print the raw bytes.
                        errors.extend(data[:max(0, ERROR_LIMIT - len(errors))])
                        continue
                    if status is None:
                        prefix.extend(data)
                        cuts = [(prefix.find(mark), mark) for mark in (b'\r\n\r\n', b'\n\n')]
                        cuts = [(pos, mark) for pos, mark in cuts if pos >= 0]
                        if not cuts:
                            if len(prefix) > HEADER_LIMIT:
                                raise ReadFailure('response header limit')
                            continue
                        pos, mark = min(cuts, key=lambda x: x[0])
                        if pos > HEADER_LIMIT:
                            raise ReadFailure('response header limit')
                        status, headers = _headers(bytes(prefix[:pos]))
                        data = bytes(prefix[pos + len(mark):])
                        prefix.clear()
                    if status in (200, 204):
                        count += len(data)
                        if count > max_bytes:
                            raise ReadFailure('response size limit', status, headers)
                        sink.write(data)
                        digest.update(data)
                    # Non-200 bodies are drained, not retained or trusted.
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise ReadFailure('read deadline', status, headers, status is None or status == 200 or status in RETRY_STATUS)
            try:
                code = child.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                raise ReadFailure('read deadline', status, headers, status is None or status == 200 or status in RETRY_STATUS) from None
        if status not in (200, 204):
            raise ReadFailure('HTTP response' if status else 'missing response', status, headers,
                              status in RETRY_STATUS or (status is None and any(x in bytes(errors).lower() for x in NETWORK_ERRORS)))
        if code != 0:
            raise ReadFailure('transport exit', status, headers,
                              any(x in bytes(errors).lower() for x in NETWORK_ERRORS))
        return {'bytes': count, 'sha256': digest.hexdigest(), 'status': status, 'headers': headers}
    finally:
        child.stdout.close()
        child.stderr.close()
        if child.poll() is None:
            # Reserve cleanup inside this attempt's deadline, preserving the primary error.
            primary = sys.exc_info()[1]
            try:
                child.kill()
                child.wait(timeout=max(.001, final_deadline - time.monotonic()))
            except (OSError, subprocess.TimeoutExpired):
                if primary is not None:
                    primary.add_note('GitHub GET child cleanup not confirmed')
                    if isinstance(primary, ReadFailure):
                        primary.retryable = False
                else:
                    raise ReadFailure('child cleanup not confirmed') from None


def read_get(path, sink, max_bytes, *, budget=None, record=None):
    if not isinstance(path, str) or not (path in ('rate_limit', 'repos/polaris-arch/sing-box-polaris') or re.fullmatch(r'repos/polaris-arch/sing-box-polaris/[A-Za-z0-9_./?=&%+\-]+', path)):
        raise ReadFailure('unapproved GET path')
    if '..' in path.split('?', 1)[0].split('/'):
        raise ReadFailure('unapproved GET path')
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ReadFailure('invalid byte limit')
    budget = budget or PROCESS_BUDGET
    deadline = time.monotonic() + TOTAL_SECONDS
    for attempt in range(1, ATTEMPTS + 1):
        sink.seek(0)
        sink.truncate(0)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ReadFailure('total read deadline')
        try:
            result = _attempt(path, sink, max_bytes, min(ATTEMPT_SECONDS, remaining))
            if record:
                record(readAttempt=attempt, readStatus=result['status'], readHeaders=result['headers'],
                       readBytes=result['bytes'], readError=None, extraGETs=budget.extra_gets)
            return result
        except ReadFailure as error:
            sink.seek(0)
            sink.truncate(0)
            if record:
                record(readAttempt=attempt, readStatus=error.status, readError=error.kind,
                       readHeaders=error.headers, extraGETs=budget.extra_gets)
            if not error.retryable or attempt == ATTEMPTS or budget.extra_gets >= MAX_EXTRA_GETS:
                raise
            delay = retry_delay(error.headers.get('retry-after'), attempt, time.time())
            if delay >= deadline - time.monotonic() or budget.wait_seconds + delay > MAX_RETRY_WAIT:
                raise ReadFailure('retry budget exhausted', error.status) from None
            budget.extra_gets += 1
            budget.wait_seconds += delay
            time.sleep(delay)
    raise AssertionError('unreachable')
