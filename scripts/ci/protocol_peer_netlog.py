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
        'native observation task invalid':'task_invalid',
        'native observation task duplicate or bound':'task_duplicate_or_bound',
        'native observation binding invalid':'binding_invalid',
        'native observation consumption invalid':'consumption_invalid',
        'native observation task closure differs':'task_closure_differs',
        'native observation task ordering invalid':'task_ordering_invalid',
        'native observation consumption closure differs':'consumption_closure_differs',
        'native observation consumption count differs':'consumption_count_differs',
        'native observation consumption ordering invalid':'consumption_ordering_invalid',
        'native observation consumption mask differs':'consumption_mask_differs',

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
              'resultPairs':{'healthy':0,'wrong-ca':0,'wrong-sni':0,'other':0},'nativeResults':[],
              'boundTasks':0,'completedTasks':0,'consumedProofDetails':0,'sessionRelations':[]}
    try:
        result=_certificate_observation(raw,expected_host,expected_leaf,mutation,observed)
        result['fixedObservation']=observed
        return result
    except Exception as error:
        # Fixed counters only. Preserve the original rejection type/logic.
        error.native_fixed_observation=observed
        raise


# Fixed pinned native enums. Values carry no host, certificate or arbitrary text.
CERT_FLAGS={0:'COMMON_NAME_INVALID',1:'DATE_INVALID',2:'AUTHORITY_INVALID',
    4:'NO_REVOCATION_MECHANISM',5:'UNABLE_TO_CHECK_REVOCATION',6:'REVOKED',7:'INVALID',
    8:'WEAK_SIGNATURE_ALGORITHM',10:'NON_UNIQUE_NAME',11:'WEAK_KEY',13:'PINNED_KEY_MISSING',
    14:'NAME_CONSTRAINT_VIOLATION',15:'VALIDITY_TOO_LONG',16:'IS_EV',17:'REV_CHECKING_ENABLED',
    19:'SHA1_SIGNATURE_PRESENT',21:'KNOWN_INTERCEPTION_DETECTED',22:'IS_QWAC',
    24:'CERTIFICATE_TRANSPARENCY_REQUIRED',26:'KNOWN_INTERCEPTION_BLOCKED',28:'SELF_SIGNED_LOCAL_NETWORK'}
CERT_ERROR_MASK=0xFF00FFFF
CERT_KNOWN_MASK=sum(1<<bit for bit in CERT_FLAGS)


def native_result(params,expected_host,mutation):
    # Pinned NetLogParams omits net_error on success, never emits null.
    error=params.get('net_error',0);raw_status=params.get('cert_status');known=params.get('is_issued_by_known_root')
    if type(error) is not int or not -10000<=error<=0 or type(raw_status) is not int or not -(1<<31)<=raw_status<(1<<31):
        raise ValueError('native observation result invalid')
    status=raw_status & 0xFFFFFFFF
    fixed={'netError':error,'netErrorOmitted': 'net_error' not in params,'certStatus':status,
        'knownRoot':known if type(known) is bool else None,
        'knownRootClass':'true' if known is True else 'false' if known is False else 'missing' if 'is_issued_by_known_root' not in params else 'invalid',
        'knownFlags':[label for bit,label in CERT_FLAGS.items() if status & (1<<bit)],
        'officialErrorMask':status & CERT_ERROR_MASK,'unknownBitsPresent':bool(status & ~CERT_KNOWN_MASK)}
    wanted_error,wanted_status={'healthy':(0,0),'wrong-ca':(-202,4),'wrong-sni':(-200,1)}[mutation]
    warning=bool(status & (1<<10))
    # Cronet specifically retains this bit as a warning for known-root nonunique
    # names. This is NOT a general relaxation for low/error or informational bits.
    warning_allowed=warning and known is True and expected_host in ('controlled.invalid','wrong.invalid')
    fixed['conditionalNonUniqueWarning']=warning_allowed
    accepted=type(known) is bool and error==wanted_error and (status & ~(1<<10))==wanted_status and (not warning or warning_allowed)
    return fixed,accepted


def _certificate_observation(raw, expected_host, expected_leaf, mutation, observed):
    if not isinstance(raw,bytes) or not raw or len(raw)>MAXIMUM_BYTES:raise ValueError('native observation size invalid')
    data=json.loads(raw,object_pairs_hook=_object,parse_constant=_constant)
    constants=data['constants'];types=constants['logEventTypes'];phases=constants['logEventPhase'];sources=constants['logSourceType']
    names=('CERT_VERIFY_PROC','CERT_VERIFIER_TASK','CERT_VERIFIER_TASK_BOUND','QUIC_SESSION_CERTIFICATE_VERIFIED','QUIC_SESSION_CERTIFICATE_VERIFY_FAILED')
    ids={n:types[n] for n in names};begin_phase=phases['PHASE_BEGIN'];end_phase=phases['PHASE_END'];none_phase=phases['PHASE_NONE']
    task_type=sources['CERT_VERIFIER_TASK'];session_type=sources['QUIC_SESSION']
    values=list(ids.values())+[begin_phase,end_phase,none_phase,task_type,session_type]
    if any(type(v) is not int or v<0 for v in values) or len({begin_phase,end_phase,none_phase})!=3 or task_type==session_type:
        raise ValueError('native observation constants invalid')
    if any(list(types.values()).count(v)!=1 for v in ids.values()) or any(list(phases.values()).count(v)!=1 for v in (begin_phase,end_phase,none_phase)) or any(list(sources.values()).count(v)!=1 for v in (task_type,session_type)):
        raise ValueError('native observation constants ambiguous')
    events=data['events']
    if not isinstance(events,list) or len(events)>MAXIMUM_EVENTS:raise ValueError('native observation event bound exceeded')
    expected={'healthy':(0,0),'wrong-ca':(-202,4),'wrong-sni':(-200,1)}
    if mutation not in expected:raise ValueError('native observation mutation invalid')
    def source_key(source):
        key=(source['type'],source['id'])
        if any(type(v) is not int or v<0 for v in key):raise ValueError('native observation source invalid')
        return key
    starts={};ends={};bindings={};consumed={};pending={};seen=set();records={};unrelated=0
    for event in events:
        if not isinstance(event,dict):raise ValueError('native observation event invalid')
        if type(event.get('type')) is not int:raise ValueError('native observation event type invalid')
        if event['type'] not in ids.values():continue
        key=source_key(event['source']);phase=event['phase'];params=event.get('params',{});stamp=_time(event['time'])
        if type(phase) is not int or not isinstance(params,dict):raise ValueError('native observation event invalid')
        if event['type']==ids['CERT_VERIFIER_TASK']:
            if key[0]!=task_type or phase not in (begin_phase,end_phase):raise ValueError('native observation task invalid')
            target=starts if phase==begin_phase else ends
            if key in target or len(target)>=MAXIMUM_VERIFICATIONS:raise ValueError('native observation task duplicate or bound')
            target[key]=stamp
            observed['completedTasks']=len(ends)
            continue
        if event['type']==ids['CERT_VERIFIER_TASK_BOUND']:
            dep=source_key(params['source_dependency'])
            if key[0]!=session_type or dep[0]!=task_type or phase!=none_phase or dep in bindings or len(bindings)>=MAXIMUM_VERIFICATIONS:raise ValueError('native observation binding invalid')
            bindings[dep]=(key,stamp);observed['boundTasks']=len(bindings)
            continue
        if event['type'] in (ids['QUIC_SESSION_CERTIFICATE_VERIFIED'],ids['QUIC_SESSION_CERTIFICATE_VERIFY_FAILED']):
            if key[0]!=session_type or phase!=none_phase or observed['consumedProofDetails']>=MAXIMUM_VERIFICATIONS:raise ValueError('native observation consumption invalid')
            label='mask_error' if event['type']==ids['QUIC_SESSION_CERTIFICATE_VERIFY_FAILED'] else 'mask_clear'
            consumed.setdefault(key,[]).append((stamp,label));observed['consumedProofDetails']+=1
            continue
        observed['certificateEvents']+=1
        if key[0]!=task_type:raise ValueError('native observation source invalid')
        if phase==begin_phase:
            observed['begins']+=1
            if key in seen or len(seen)>=MAXIMUM_VERIFICATIONS:raise ValueError('native observation duplicate or excessive verification')
            seen.add(key);certificates=params.get('certificates');host=params.get('host')
            if not isinstance(certificates,list) or not certificates or len(certificates)>16:raise ValueError('native observation certificate list invalid')
            host_matches=host==expected_host;leaf_matches=leaf_hash(certificates[0])==expected_leaf
            observed['hostMatches']+=int(host_matches);observed['leafMatches']+=int(leaf_matches)
            matched=host_matches and leaf_matches
            if not matched:unrelated+=1
            observed['unrelatedPairs']=unrelated;pending[key]=(stamp,matched);observed['pendingPairs']=len(pending)
        elif phase==end_phase:
            observed['ends']+=1
            if key not in pending:raise ValueError('native observation orphan end')
            started,matched=pending.pop(key);observed['pendingPairs']=len(pending)
            if stamp<started:raise ValueError('native observation time reversed')
            fixed,accepted=native_result(params,expected_host,mutation);observed['nativeResults'].append(fixed)
            observed['completePairs']+=1
            pair_name={(0,0):'healthy',(-202,4):'wrong-ca',(-200,1):'wrong-sni'}.get((fixed['netError'],fixed['certStatus']),'other')
            observed['resultPairs'][pair_name]+=1
            records[key]=(started,stamp,matched,accepted,fixed)
        else:raise ValueError('native observation verification phase invalid')
    if pending or not records or unrelated:raise ValueError('native observation incomplete or unrelated verification')
    if not set(records)==set(starts)==set(ends)==set(bindings):raise ValueError('native observation task closure differs')
    sessions={}
    for key,(begin,end,matched,accepted,fixed) in records.items():
        session,bound=bindings[key]
        if not starts[key]<=bound<=begin<=end<=ends[key]:raise ValueError('native observation task ordering invalid')
        sessions.setdefault(session,[]).append((starts[key],ends[key],fixed))
    if set(sessions)!=set(consumed):raise ValueError('native observation consumption closure differs')
    for session,tasks in sessions.items():
        tasks.sort(key=lambda x:x[0]);details=sorted(consumed[session])
        if len(tasks)!=len(details):raise ValueError('native observation consumption count differs')
        for i,((begin,end,fixed),(stamp,label)) in enumerate(zip(tasks,details)):
            if stamp<end or (i+1<len(tasks) and stamp>tasks[i+1][0]):raise ValueError('native observation consumption ordering invalid')
            # The native event label follows the status MASK, not callback rv.
            if label!=('mask_error' if fixed['officialErrorMask'] else 'mask_clear'):raise ValueError('native observation consumption mask differs')
            observed['sessionRelations'].append({'taskSourceBound':True,'taskComplete':True,'proofDetailsConsumed':True,'maskEvent':label})
    if any(not row[3] for row in records.values()):raise ValueError('native observation certificate result differs')
    wanted_error,wanted_status=expected[mutation];statuses={row[4]['certStatus'] for row in records.values()}
    return {'schema':'native-certificate-observation-v2','rawSHA256':hashlib.sha256(raw).hexdigest(),'rawBytes':len(raw),
            'boundedEvents':len(events),'verificationCount':len(records),'unrelatedVerificationCount':unrelated,
            'hostMatchesPrivateCase':True,'leafMatchesPrivateFixture':True,'allSourcePairsComplete':True,
            'result':mutation,'netError':wanted_error,'expectedErrorBits':wanted_status,
            'certStatus':next(iter(statuses)) if len(statuses)==1 else None,'observedCertStatuses':sorted(statuses),'rawRetainedPublicly':False}


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
