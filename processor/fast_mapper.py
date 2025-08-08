# In processor/fast_mapper.py
import uuid
import json
from datetime import datetime
from .schemas import EnrichedUnifiedLog, OS

def normalize_keys(data):
    """
    NEW: Recursively converts dictionary keys to lowercase for case-insensitive mapping.
    This handles variations like 'Agent' vs 'agent' and 'eUser' vs 'euser'.
    """
    if isinstance(data, dict):
        return {k.lower(): normalize_keys(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [normalize_keys(item) for item in data]
    return data

# map_wazuh_log and map_elastic_log functions remain unchanged...
def map_wazuh_log(raw_log: dict) -> EnrichedUnifiedLog:
    """Handles direct field mapping for a Wazuh log."""
    log = EnrichedUnifiedLog(
        logId=raw_log.get('id', str(uuid.uuid4())),
        timestamp=raw_log.get('timestamp', datetime.utcnow().isoformat()),
    )
    log.source.vendor = "Wazuh"
    if agent_data := raw_log.get('agent'):
        log.agent.id = agent_data.get('id'); log.agent.name = agent_data.get('name'); log.endpoint.name = agent_data.get('name')
    if rule_data := raw_log.get('rule'):
        log.rule.id = rule_data.get('id'); log.rule.description = rule_data.get('description'); log.rule.level = rule_data.get('level'); log.rule.groups = rule_data.get('groups'); log.event.description = rule_data.get('description')
    if sca_data := raw_log.get('data', {}).get('sca', {}).get('check'):
        log.event.description = f"SCA Check: {sca_data.get('title')}"; log.additionalData = {'sca_remediation': sca_data.get('remediation')}
    log.event.fullLog = json.dumps(raw_log)
    return log

def map_elastic_log(raw_log: dict) -> EnrichedUnifiedLog:
    """Handles mapping for Wazuh alerts stored in Elasticsearch."""
    source = raw_log.get('_source', {})
    log = EnrichedUnifiedLog(
        logId=raw_log.get('_id'),
        timestamp=source.get('@timestamp', datetime.utcnow().isoformat()),
    )
    log.source.vendor = "Wazuh"; log.source.index = raw_log.get('_index')
    if ecs_data := source.get('ecs'): log.source.version = ecs_data.get('version')
    if agent_data := source.get('agent'): log.agent.id = agent_data.get('id'); log.agent.name = agent_data.get('name')
    if host_data := source.get('host'):
        log.endpoint.name = host_data.get('name'); log.endpoint.ip = host_data.get('ip', []); log.endpoint.mac = host_data.get('mac', [])
        if os_data := host_data.get('os'): log.endpoint.os = OS(**os_data)
    if manager_data := source.get('manager'): log.manager.name = manager_data.get('name')
    if decoder_data := source.get('decoder'): log.decoder.name = decoder_data.get('name'); log.decoder.parent = decoder_data.get('parent')
    if log_data := source.get('log'):
        log.log.offset = log_data.get('offset')
        if file_data := log_data.get('file'): log.log.filePath = file_data.get('path')
    if rule_data := source.get('rule'):
        log.rule.id = rule_data.get('id'); log.rule.firedTimes = rule_data.get('firedtimes'); log.rule.level = rule_data.get('level'); log.rule.groups = rule_data.get('groups', []); log.event.description = rule_data.get('description')
        log.rule.compliance.pci_dss = rule_data.get('pci_dss'); log.rule.compliance.hipaa = rule_data.get('hipaa'); log.rule.compliance.nist_800_53 = rule_data.get('nist_800_53'); log.rule.compliance.gdpr = rule_data.get('gdpr')
        if mitre_data := rule_data.get('mitre'): log.rule.compliance.mitre.tactics = mitre_data.get('tactic'); log.rule.compliance.mitre.techniques = mitre_data.get('technique')
    if not log.event.description: log.event.description = source.get('full_log')
    if data := source.get('data'):
        log.process.name = source.get('predecoder', {}).get('program_name'); log.process.cmdLine = data.get('command'); log.process.eUser.name = data.get('srcuser')
        if dstuser := data.get('dstuser'):
            if not log.additionalData: log.additionalData = {}; log.additionalData['destinationUser'] = dstuser
    log.event.fullLog = json.dumps(source)
    return log

# ==============================================================================
# SentinelOne Modular Mapping Structure
# ==============================================================================

def _map_s1_file_event(log: EnrichedUnifiedLog, norm_log: dict):
    """Expert for File Creation/Modification. Works with lowercase keys."""
    target_data = norm_log.get('target_file') or norm_log.get('target', {}).get('file')
    if target_data:
        log.target.file.path = target_data.get('path')
        log.target.file.name = target_data.get('name')
        log.target.file.size = target_data.get('size')
        log.target.file.creationTime = target_data.get('creation_time')
        log.target.file.isDirectory = target_data.get('is_directory')

def _map_s1_ip_connect(log: EnrichedUnifiedLog, norm_log: dict):
    """Expert for IP Connect. Works with lowercase keys."""
    log.networkConnection.sourceIP = norm_log.get('source_ip')
    log.networkConnection.sourcePort = str(norm_log.get('source_port'))
    log.networkConnection.destinationIP = norm_log.get('destination_ip')
    log.networkConnection.destinationPort = str(norm_log.get('destination_port'))
    log.networkConnection.direction = norm_log.get('network_direction')

def _map_s1_process_creation(log: EnrichedUnifiedLog, norm_log: dict):
    """NEW: Expert for Process Creation. Works with lowercase keys."""
    target_proc = norm_log.get('target_process')
    if target_proc:
        log.target.file.path = target_proc.get('imagepath')
        log.target.file.name = target_proc.get('displayname') or target_proc.get('name')
        log.target.file.sha256 = target_proc.get('sha256')
        log.additionalData = {
            "targetProcessPid": target_proc.get('pid'),
            "targetProcessCmdLine": target_proc.get('cmdline')
        }
    source_proc_name = log.process.name or "unknown process"
    target_proc_name = log.target.file.name or "unknown process"
    log.event.description = f"Process '{source_proc_name}' created process '{target_proc_name}'."

SENTINELONE_MAPPERS = {
    "file modification": _map_s1_file_event,
    "file creation": _map_s1_file_event,
    "ip connect": _map_s1_ip_connect,
    "process creation": _map_s1_process_creation,
}

def map_sentinelone_log(raw_log: dict) -> EnrichedUnifiedLog:
    """REWRITTEN: Final robust dispatcher for SentinelOne logs."""
    norm_log = normalize_keys(raw_log)
    
    event_obj = norm_log.get('event', {})
    event_type = (event_obj.get('type') or norm_log.get('event_type', '')).lower()
        
    event_time_str = event_obj.get('time')
    timestamp = datetime.utcnow().isoformat()
    if event_time_str:
        try:
            dt_object = datetime.strptime(str(event_time_str), '%b %d %Y %H:%M:%S')
            timestamp = dt_object.isoformat()
        except (ValueError, TypeError):
            timestamp = event_time_str
            
    log = EnrichedUnifiedLog(logId=event_obj.get('id', str(uuid.uuid4())), timestamp=timestamp)

    # --- 1. Map Common Fields ---
    source_data = norm_log.get('datasource', norm_log.get('agentinfo'))
    if source_data:
        log.source.vendor = source_data.get('vendor', 'SentinelOne'); log.source.dataCategory = source_data.get('datasourcecategory')
    
    agent_data = norm_log.get('agent', norm_log.get('agentinfo'))
    if agent_data:
        log.agent.uuid = agent_data.get('uuid'); log.agent.version = agent_data.get('version')
    
    endpoint_data = norm_log.get('endpoint', norm_log.get('agentinfo'))
    if endpoint_data:
        log.endpoint.name = endpoint_data.get('name') or endpoint_data.get('endpointname')
        os_info = endpoint_data.get('os')
        if isinstance(os_info, dict): log.endpoint.os = OS(**os_info)
        elif isinstance(os_info, str): log.endpoint.os.name = os_info

    proc_data = norm_log.get('process') or norm_log.get('event') or norm_log.get('source_process')
    if proc_data:
        log.process.pid = proc_data.get('pid'); log.process.name = proc_data.get('displayname') or proc_data.get('name'); log.process.cmdLine = proc_data.get('cmdline'); log.process.imagePath = proc_data.get('imagepath'); log.process.sha256 = proc_data.get('sha256')
        if euser := proc_data.get('euser'):
             log.process.eUser.name = euser.get('name'); log.process.eUser.uid = euser.get('uid')
        if ruser := proc_data.get('ruser'):
             log.process.rUser.name = ruser.get('name'); log.process.rUser.uid = ruser.get('uid')
    
    parent_data = norm_log.get('parentprocess')
    if parent_data:
        log.process.parentCmdLine = parent_data.get('cmdline')

    # --- 2. Call the Specialized "Expert" Mapper ---
    if event_type in SENTINELONE_MAPPERS:
        SENTINELONE_MAPPERS[event_type](log, norm_log)
    else:
        print(f"Warning: No specialized mapper for SentinelOne event type '{event_type}'.")

    # --- 3. Final Touches ---
    log.event.type = event_type
    if not log.event.description:
        proc_name = log.process.name or "an unknown process"
        log.event.description = f"'{event_type}' event involving process '{proc_name}'."
    
    log.event.fullLog = json.dumps(raw_log)
    return log

def fast_path_mapper(raw_log: dict, vendor: str) -> EnrichedUnifiedLog:
    if vendor.lower() in ['wazuh', 'elastic']:
        return map_elastic_log(raw_log)
    elif vendor.lower() == 'sentinelone':
        return map_sentinelone_log(raw_log)
    else:
        return EnrichedUnifiedLog(
            logId=str(uuid.uuid4()),
            timestamp=raw_log.get('timestamp', datetime.utcnow().isoformat()),
            source={'vendor': vendor},
            event={'fullLog': json.dumps(raw_log)}
        )