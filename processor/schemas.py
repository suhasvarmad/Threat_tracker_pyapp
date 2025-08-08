# In processor/schemas.py

from __future__ import annotations
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import ConfigDict 

# ==============================================================================
# Define Enums for fields with a controlled vocabulary
# ==============================================================================
class SeverityLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AlertStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"

# ==============================================================================
# Define Nested Models (Bottom-up approach for dependencies)
# ==============================================================================
# These are the deepest nested objects.

class OS(BaseModel):
    name: Optional[str] = None
    version: Optional[str] = None
    family: Optional[str] = None
    type: Optional[str] = None
    kernel: Optional[str] = None
    codename: Optional[str] = None
    platform: Optional[str] = None

class EUser(BaseModel):
    name: Optional[str] = None
    uid: Optional[int] = None
    domain: Optional[str] = None
    id: Optional[str] = None

class RUser(BaseModel):
    name: Optional[str] = None
    uid: Optional[int] = None
    domain: Optional[str] = None
    id: Optional[str] = None

class File(BaseModel):
    path: Optional[str] = None
    name: Optional[str] = None
    creationTime: Optional[str] = None
    isDirectory: Optional[bool] = None
    isSigned: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    size: Optional[int] = None
    type: Optional[str] = None

class Mitre(BaseModel):
    tactics: Optional[List[str]] = None
    techniques: Optional[List[str]] = None
    mitigations: Optional[List[str]] = None

class Compliance(BaseModel):
    pci_dss: Optional[List[str]] = Field(None, alias="pci_dss")
    hipaa: Optional[List[str]] = None
    nist_800_53: Optional[List[str]] = Field(None, alias="nist_800_53")
    gdpr: Optional[List[str]] = None
    soc_2: Optional[List[str]] = Field(None, alias="soc_2")
    iso_27001: Optional[List[str]] = Field(None, alias="iso_27001")
    mitre: Optional[Mitre] = Field(default_factory=Mitre)
    cis: Optional[List[str]] = None

# ==============================================================================
# Define Main Component Models
# ==============================================================================
# These models are the direct properties of the top-level UnifiedLog.

class Source(BaseModel):
    vendor: Optional[str] = None
    version: Optional[str] = None
    dataCategory: Optional[str] = None
    index: Optional[str] = None
    type: Optional[str] = None
    location: Optional[str] = None

class Agent(BaseModel):
    id: Optional[str] = None
    uuid: Optional[str] = None
    name: Optional[str] = None
    version: Optional[str] = None # <-- ADD THIS LINE

class Endpoint(BaseModel):
    name: Optional[str] = None
    os: Optional[OS] = Field(default_factory=OS)
    architecture: Optional[str] = None
    mac: Optional[List[str]] = None
    ip: Optional[List[str]] = None
    containerized: Optional[bool] = None

class Event(BaseModel):
    id: Optional[str] = None
    type: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None
    level: Optional[int] = None
    fullLog: Optional[str] = None

class Process(BaseModel):
    id: Optional[str] = None
    pid: Optional[int] = None
    name: Optional[str] = None
    displayName: Optional[str] = None
    cmdLine: Optional[str] = None
    imagePath: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    size: Optional[int] = None
    type: Optional[str] = None
    uid: Optional[str] = None
    eUser: Optional[EUser] = Field(default_factory=EUser)
    rUser: Optional[RUser] = Field(default_factory=RUser)
    parentCmdLine: Optional[str] = None
    integrityLevel: Optional[str] = None
    startTime: Optional[str] = None
    signedStatus: Optional[str] = None

class Target(BaseModel):
    file: Optional[File] = Field(default_factory=File)

class Rule(BaseModel):
    id: Optional[str] = None
    description: Optional[str] = None
    groups: Optional[List[str]] = None
    level: Optional[int] = None
    firedTimes: Optional[int] = None
    mail: Optional[bool] = None
    compliance: Optional[Compliance] = Field(default_factory=Compliance)

class Metrics(BaseModel):
    processChildCount: Optional[int] = None
    dnsCount: Optional[int] = None
    netConnCount: Optional[int] = None
    registryChangeCount: Optional[int] = None
    targetFileCreationCount: Optional[int] = None

class NetworkConnection(BaseModel):
    sourceIP: Optional[str] = None
    sourcePort: Optional[str] = None
    destinationIP: Optional[str] = None
    destinationPort: Optional[str] = None
    direction: Optional[str] = None
    status: Optional[str] = None
    protocol: Optional[str] = None

class Cloud(BaseModel):
    provider: Optional[str] = None
    account_id: Optional[str] = None
    region: Optional[str] = None
    resource: Optional[str] = None
    api_call: Optional[str] = None

class Email(BaseModel):
    subject: Optional[str] = None
    sender: Optional[str] = None
    recipient: Optional[str] = None
    attachment: Optional[str] = None
    url: Optional[str] = None

class Registry(BaseModel):
    key: Optional[str] = None
    value: Optional[str] = None
    operation: Optional[str] = None

class Manager(BaseModel):
    name: Optional[str] = None

class Decoder(BaseModel):
    name: Optional[str] = None
    parent: Optional[str] = None

class Log(BaseModel):
    offset: Optional[int] = None
    filePath: Optional[str] = None

class AlertMetadata(BaseModel):
    status: Optional[AlertStatus] = None
    analyst: Optional[str] = None
    comments: Optional[str] = None

# ==============================================================================
# Define the Top-Level Unified Log Model
# ==============================================================================
# This is the final, complete object that brings everything together.

class EnrichedUnifiedLog(BaseModel):
    # Required fields (no Optional type hint, no default value)
    logId: str = Field(..., description="Unique identifier of this log entry.")
    timestamp: str = Field(..., description="Event time in ISO8601 format.")
    
    # Required objects (use default_factory to ensure they exist)
    source: Source = Field(default_factory=Source)
    agent: Agent = Field(default_factory=Agent)
    endpoint: Endpoint = Field(default_factory=Endpoint)
    event: Event = Field(default_factory=Event)
    
    # Optional top-level fields
    severity: Optional[SeverityLevel] = Field(None, description="Alert severity level.")
    tactic: Optional[str] = Field(None, description="MITRE ATT&CK tactic name.")
    technique: Optional[str] = Field(None, description="MITRE ATT&CK technique name.")
    
    # Optional objects
    process: Process = Field(default_factory=Process)
    target: Target = Field(default_factory=Target)
    rule: Rule = Field(default_factory=Rule)
    metrics: Metrics = Field(default_factory=Metrics)
    networkConnection: NetworkConnection = Field(default_factory=NetworkConnection)
    cloud: Cloud = Field(default_factory=Cloud)
    email: Email = Field(default_factory=Email)
    registry: Registry = Field(default_factory=Registry)
    manager: Manager = Field(default_factory=Manager)
    decoder: Decoder = Field(default_factory=Decoder)
    log: Log = Field(default_factory=Log)
    tags: Optional[List[str]] = Field(default_factory=list)
    alert_metadata: AlertMetadata = Field(default_factory=AlertMetadata)
    
    # Flexible field for any data not in the schema
    additionalData: Optional[Dict[str, Any]] = Field(None, description="Platform specific data not covered elsewhere.")
    

    # At the bottom of the EnrichedUnifiedLog class
    model_config = ConfigDict(use_enum_values=True)