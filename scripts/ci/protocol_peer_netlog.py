"""Private bounded native certificate evidence. Never returns raw NetLog fields."""
import hashlib
import json
import re
from decimal import Decimal
import os
from pathlib import Path
import ssl
import stat

MAXIMUM_BYTES = 8 * 1024 * 1024
MAXIMUM_EVENTS = 32768
MAXIMUM_VERIFICATIONS = 16


def leaf_hash(pem):
    if not isinstance(pem,str) or len(pem)>131072:
        raise ValueError('native certificate observation invalid')
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


class NativeObservationIdentityError(ValueError):
    pass


class NativeObservationEvidenceError(ValueError):
    def __init__(self,category,evidence):
        super().__init__('native certificate observation rejected')
        self.category=category
        self.evidence=evidence


def failure_category(error):
    if isinstance(error,NativeObservationEvidenceError):return error.category
    if isinstance(error,NativeObservationIdentityError):return 'private_identity_unknown'
    if isinstance(error,json.JSONDecodeError):return 'malformed_json'
    if isinstance(error,UnicodeError):return 'invalid_encoding'
    if isinstance(error,KeyError):return 'missing_field'
    if isinstance(error,TypeError):return 'invalid_shape'
    if isinstance(error,RecursionError):return 'nesting_bound'
    names={
        'native observation size invalid':'size_bound',
        'native observation duplicate key':'duplicate_key',
        'native observation nonstandard JSON constant':'nonstandard_constant',
        'native observation constants invalid':'constants_invalid',
        'native observation constants ambiguous':'constants_ambiguous',
        'native observation event bound exceeded':'event_bound',
        'native observation mutation invalid':'mutation_invalid',
        'native observation event invalid':'event_invalid',
        'native observation event type invalid':'event_type_invalid',
        'native observation source invalid':'source_invalid',
        'native observation time invalid':'time_invalid',
        'native observation duplicate or excessive verification':'verification_bound_or_duplicate',
        'native observation certificate list invalid':'certificate_list_invalid',
        'native observation orphan end':'orphan_end',
        'native observation time reversed':'time_reversed',
        'native observation result invalid':'result_invalid',
        'native observation certificate result differs':'result_mismatch',
        'native observation verification phase invalid':'phase_invalid',
        'native observation incomplete or unrelated verification':'incomplete_or_unrelated',
        'native certificate observation invalid':'certificate_encoding_invalid',
    }
    try:return names.get(str(error),'unknown')
    except Exception:return 'unknown'


def _private_stat(info):
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600 or info.st_uid!=os.geteuid() or info.st_nlink!=1 or info.st_size>MAXIMUM_BYTES:
        raise NativeObservationIdentityError('native private observation identity invalid')
    return (info.st_dev,info.st_ino)


def private_identity(path):
    try:return _private_stat(os.lstat(path))
    except OSError:raise NativeObservationIdentityError('native private observation identity unavailable') from None


def _constant(_):raise ValueError('native observation nonstandard JSON constant')


def _time(value):
    if not isinstance(value,str) or not re.fullmatch(r'[0-9]{1,15}(?:\.[0-9]{1,6})?',value):
        raise ValueError('native observation time invalid')
    return Decimal(value)


def _object(items):
    result={}
    for key,value in items:
        if key in result:raise ValueError('native observation duplicate key')
        result[key]=value
    return result


def certificate_observation(raw, expected_host, expected_leaf, mutation):
    observed={'certificateEvents':0,'begins':0,'ends':0,'hostMatches':0,'leafMatches':0,
              'completePairs':0,'pendingPairs':0,'unrelatedPairs':0,
              'resultPairs':{'healthy':0,'wrong-ca':0,'wrong-sni':0,'other':0}}
    try:
        result=_certificate_observation(raw,expected_host,expected_leaf,mutation,observed)
        result['fixedObservation']=observed
        return result
    except Exception as error:
        # Fixed counters only. Preserve the original rejection type/logic.
        error.native_fixed_observation=observed
        raise


def _certificate_observation(raw, expected_host, expected_leaf, mutation, observed):
    """Parse only after exact child graceful exit. No arbitrary text is returned."""
    if not isinstance(raw,bytes) or not raw or len(raw)>MAXIMUM_BYTES:raise ValueError('native observation size invalid')
    data=json.loads(raw,object_pairs_hook=_object,parse_constant=_constant)
    constants=data['constants'];types=constants['logEventTypes'];phases=constants['logEventPhase']
    event_type=types['CERT_VERIFY_PROC'];begin_phase=phases['PHASE_BEGIN'];end_phase=phases['PHASE_END']
    if any(type(v) is not int or v<0 for v in (event_type,begin_phase,end_phase)) or begin_phase==end_phase:
        raise ValueError('native observation constants invalid')
    if list(types.values()).count(event_type)!=1 or list(phases.values()).count(begin_phase)!=1 or list(phases.values()).count(end_phase)!=1:
        raise ValueError('native observation constants ambiguous')
    events=data['events']
    if not isinstance(events,list) or len(events)>MAXIMUM_EVENTS:raise ValueError('native observation event bound exceeded')
    expected={'healthy':(0,0),'wrong-ca':(-202,4),'wrong-sni':(-200,1)}
    if mutation not in expected:raise ValueError('native observation mutation invalid')
    wanted_error,wanted_status=expected[mutation];pending={};seen=set();verified=[];unrelated=0
    for event in events:
        if not isinstance(event,dict):raise ValueError('native observation event invalid')
        if type(event.get('type')) is not int:raise ValueError('native observation event type invalid')
        if event['type']!=event_type:continue
        observed['certificateEvents']+=1
        source=event['source'];key=(source['type'],source['id'])
        if any(type(v) is not int or v<0 for v in key):raise ValueError('native observation source invalid')
        phase=event['phase'];params=event['params'];stamp=event['time']
        if type(phase) is not int or not isinstance(params,dict):raise ValueError('native observation event invalid')
        stamp=_time(stamp)
        if phase==begin_phase:
            observed['begins']+=1
            if key in seen or len(seen)>=MAXIMUM_VERIFICATIONS:raise ValueError('native observation duplicate or excessive verification')
            seen.add(key)
            certificates=params.get('certificates');host=params.get('host')
            if not isinstance(certificates,list) or not certificates or len(certificates)>16:raise ValueError('native observation certificate list invalid')
            host_matches=host==expected_host;leaf_matches=leaf_hash(certificates[0])==expected_leaf
            observed['hostMatches']+=int(host_matches);observed['leafMatches']+=int(leaf_matches)
            matched=host_matches and leaf_matches
            if not matched:unrelated+=1
            observed['unrelatedPairs']=unrelated
            pending[key]=(stamp,matched);observed['pendingPairs']=len(pending)
        elif phase==end_phase:
            observed['ends']+=1
            if key not in pending:raise ValueError('native observation orphan end')
            started,matched=pending.pop(key);observed['pendingPairs']=len(pending)
            if stamp<started:raise ValueError('native observation time reversed')
            error=params.get('net_error',0);status=params.get('cert_status')
            if type(error) is not int or type(status) is not int:raise ValueError('native observation result invalid')
            observed['completePairs']+=1
            pair_name={(0,0):'healthy',(-202,4):'wrong-ca',(-200,1):'wrong-sni'}.get((error,status),'other')
            observed['resultPairs'][pair_name]+=1
            if matched:
                # Exact pinned result pair, not generic QUIC or an arbitrary bit.
                if (error,status)!=(wanted_error,wanted_status):raise ValueError('native observation certificate result differs')
                verified.append((error,status))
        else:raise ValueError('native observation verification phase invalid')
    if pending or not verified or unrelated:raise ValueError('native observation incomplete or unrelated verification')
    return {'schema':'native-certificate-observation-v1','rawSHA256':hashlib.sha256(raw).hexdigest(),'rawBytes':len(raw),
            'boundedEvents':len(events),'verificationCount':len(verified),'unrelatedVerificationCount':unrelated,
            'hostMatchesPrivateCase':True,'leafMatchesPrivateFixture':True,'allSourcePairsComplete':True,
            'result':mutation,'netError':wanted_error,'certStatus':wanted_status,'rawRetainedPublicly':False}


def collect(process, expected_host, expected_leaf, mutation):
    if not process.cleanup or not process.cleanup.get('gracefulCleanupProven') or process.process.poll()!=0:
        raise ValueError('native observation requires exact graceful process exit')
    path=process.native_netlog_path
    if process.native_netlog_identity is None or private_identity(path)!=process.native_netlog_identity:
        raise NativeObservationIdentityError('native private observation identity changed')
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        with os.fdopen(fd,'rb') as stream:
            if _private_stat(os.fstat(stream.fileno()))!=process.native_netlog_identity:raise NativeObservationIdentityError('native private observation identity changed')
            raw=stream.read(MAXIMUM_BYTES+1)
    except OSError:raise NativeObservationIdentityError('native private observation identity unavailable') from None
    if private_identity(path)!=process.native_netlog_identity:raise NativeObservationIdentityError('native private observation identity changed')
    try:result=certificate_observation(raw,expected_host,expected_leaf,mutation)
    except Exception as error:
        category=failure_category(error)
        evidence={'category':category,'rawSHA256':hashlib.sha256(raw).hexdigest(),'rawBytes':len(raw),
            'process':{'pid':process.pid,'startTicks':process.start_identity['startTicks'],'coreSHA256':process.bound_sha256,'exactProcessExited':True},
            'rawRetainedPublicly':False,'fixedObservation':getattr(error,'native_fixed_observation',None)}
        raise NativeObservationEvidenceError(category,evidence) from None
    result['process']={'pid':process.pid,'startTicks':process.start_identity['startTicks'],'coreSHA256':process.bound_sha256,'exactProcessExited':True}
    return result
