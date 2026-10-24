from __future__ import annotations
import os
from dataclasses import dataclass,field
from pathlib import Path
from datetime import datetime,timezone
from typing import Literal
from pydantic import BaseModel,Field,ConfigDict

PROVIDERS=('website_auditor','xlogs','vibe_check','mdn_observatory','osv')
TERMINAL={'completed','completed_with_warnings','failed','cancelled','expired'}
PROVIDER_TERMINAL={'completed','cached','stale_result','failed','rate_limited','timed_out','skipped_not_applicable','cancelled','unavailable'}
SCENARIOS=('success','partial_failure','rate_limited','malformed','timeout','osv_skip','ai_failure','stale_cache')
def utcnow():return datetime.now(timezone.utc).isoformat()

@dataclass
class Settings:
    data_dir:Path=field(default_factory=lambda:Path(os.environ.get('LAUNCHSHIELD_DATA_DIR','data')).resolve())
    gemini_key:str=field(default_factory=lambda:os.environ.get('GEMINI_API_KEY',''))
    gemini_model:str=field(default_factory=lambda:os.environ.get('GEMINI_MODEL','gemini-3.5-flash-lite'))
    live_targets:tuple[str,...]=field(default_factory=lambda:tuple(x.strip().rstrip('/') for x in os.environ.get('LAUNCHSHIELD_LIVE_TARGETS','').split(',') if x.strip()))
    retention_seconds:int=86400
    provider_timeout:float=120
    job_timeout:float=240
    poll_interval:float=2.5
    mock_delay:float=.15
    maximum_response:int=2_000_000
    provider_concurrency:int=2
    ai_calls_per_hour:int=10
    max_queue:int=10

class ScanRequest(BaseModel):
    model_config=ConfigDict(extra='forbid')
    target:str=Field(min_length=4,max_length=2048)
    mode:Literal['mock','live']='mock'
    authorized:bool=False
    public_disclosure:bool=False
    ai:bool=True
    scenario:Literal['success','partial_failure','rate_limited','malformed','timeout','osv_skip','ai_failure','stale_cache']='success'

class AnalysisItem(BaseModel):
    model_config=ConfigDict(extra='forbid')
    finding_id:str=Field(max_length=80)
    explanation:str=Field(max_length=3000)
    remediation:str=Field(max_length=3000)
    verification:str=Field(max_length=2000)

class AnalysisOutput(BaseModel):
    model_config=ConfigDict(extra='forbid')
    summary:str=Field(max_length=5000)
    analysis:list[AnalysisItem]=Field(max_length=20)
    limitations:list[str]=Field(max_length=12)
