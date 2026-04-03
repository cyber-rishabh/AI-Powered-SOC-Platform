from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum
import uuid


class EventType(str, Enum):
    LOGIN_FAIL    = "login_fail"
    LOGIN_SUCCESS = "login_success"
    PROCESS_EXEC  = "process_exec"
    NETWORK_CONN  = "network_conn"
    FILE_CREATE   = "file_create"
    UNKNOWN       = "unknown"


class LogSource(str, Enum):
    SYSMON  = "sysmon"
    WINDOWS = "windows"
    NXLOG   = "nxlog"


class NormalizedLog(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    event_type: EventType
    source: LogSource

    user: Optional[str] = None
    host: Optional[str] = None
    process: Optional[str] = None
    process_id: Optional[int] = None
    parent_proc: Optional[str] = None
    ip_src: Optional[str] = None
    ip_dst: Optional[str] = None
    port_dst: Optional[int] = None

    raw: Optional[dict] = None
    tags: list[str] = Field(default_factory=list)
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum
import uuid


class EventType(str, Enum):
    LOGIN_FAIL    = "login_fail"
    LOGIN_SUCCESS = "login_success"
    PROCESS_EXEC  = "process_exec"
    NETWORK_CONN  = "network_conn"
    FILE_CREATE   = "file_create"
    UNKNOWN       = "unknown"


class LogSource(str, Enum):
    SYSMON  = "sysmon"
    WINDOWS = "windows"
    NXLOG   = "nxlog"


class NormalizedLog(BaseModel):
    id:          str      = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:   datetime
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type:  EventType
    source:      LogSource
    user:        Optional[str]  = None
    host:        Optional[str]  = None
    process:     Optional[str]  = None
    process_id:  Optional[int]  = None
    parent_proc: Optional[str]  = None
    ip_src:      Optional[str]  = None
    ip_dst:      Optional[str]  = None
    port_dst:    Optional[int]  = None
    raw:         Optional[dict] = None
    tags:        list[str]      = Field(default_factory=list)


class RawLogIngestion(BaseModel):
    source:  LogSource
    payload: dict


class BulkLogIngestion(BaseModel):
    logs: list[RawLogIngestion] = Field(..., min_length=1, max_length=500)


class LogResponse(NormalizedLog):
    pass


class IngestionResponse(BaseModel):
    success:    bool
    log_id:     str
    event_type: EventType
    message:    str


class BulkIngestionResponse(BaseModel):
    success:  bool
    accepted: int
    rejected: int
    log_ids:  list[str]
    errors:   list[str]
