# In tests/test_mappers.py
import json
from processor.fast_mapper import map_elastic_log, map_sentinelone_log

def test_elastic_wazuh_auth_mapping():
    """
    Tests the mapper for a Wazuh authentication alert from Elastic.
    """
    # 1. Arrange: Define the input log
    raw_log_str = """
    {
        "_id": "g6UKEpgBVr_Gl5n0xxLC",
        "_source": {
            "@timestamp": "2025-07-16T07:02:28.053Z",
            "agent": { "id": "000", "name": "ubuntu" },
            "rule": { "id": "5501", "description": "PAM: Login session opened." }
        }
    }
    """
    raw_log = json.loads(raw_log_str)

    # 2. Act: Call the function we are testing
    result = map_elastic_log(raw_log)

    # 3. Assert: Check if the output is correct
    assert result.logId == "g6UKEpgBVr_Gl5n0xxLC"
    assert result.source.vendor == "Wazuh"
    assert result.agent.id == "000"
    assert result.rule.id == "5501"
    assert result.event.description == "PAM: Login session opened."

def test_sentinelone_process_mapping():
    """
    Tests the mapper for a SentinelOne process creation log.
    """
    # 1. Arrange
    raw_log_str = r"""
    {
        "event": { "id": "s1-event-id-123", "time": "Jul 23 2025 15:56:40" },
        "agent": { "uuid": "agent-uuid-456", "version": "24.1" },
        "sourceProcess": { "pid": 1001, "name": "powershell.exe" },
        "targetProcess": { "pid": 1002, "imagePath": "C:\\Windows\\System32\\calc.exe" }
    }
    """
    raw_log = json.loads(raw_log_str)

    # 2. Act
    result = map_sentinelone_log(raw_log)

    # 3. Assert
    assert result.logId == "s1-event-id-123"
    assert result.agent.uuid == "agent-uuid-456"
    assert result.process.pid == 1001
    assert result.process.name == "powershell.exe"
    assert result.target.file.path == "C:\\Windows\\System32\\calc.exe"
    assert result.additionalData["targetProcessPid"] == 1002