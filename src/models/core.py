"""
Canonical output schema for the Offensive-Defensive Translator.

This module defines the stable structure returned by the analysis engine using Pydantic models
for runtime validation and type safety. It contains no detection or enrichment logic.
"""
from datetime import datetime
from enum import Enum
from typing import Optional
from models.defensive import DefensiveEnrichment
from models.educational import EducationalContent
from models.metadata import ConfidenceLevel, Severity, TechniqueConfidence
from pydantic import BaseModel, Field, HttpUrl, field_validator # BUG PYDANTIC0001


# Input models
class InputData(BaseModel):
    """Original and normalized command input."""
    original_command: str = Field(..., description="The original command as received")
    normalized_command: str = Field(..., description="Preprocessed command for standardized analysis")
    detected_shell: Optional[str] = Field(None, description="Detected shell type (powershell, bash, cmd, etc.)")
    detected_os: Optional[str] = Field(None, description="Detected or inferred operating system")


class ParsedComponents(BaseModel):
    """Parsed components extracted from the command."""
    executable: Optional[str] = Field(None, description="Main executable or command")
    arguments: list[str] = Field(default_factory=list, description="Command arguments")
    flags: list[str] = Field(default_factory=list, description="Command flags/switches")
    suspicious_patterns: list[str] = Field(default_factory=list, description="Suspicious patterns identified")
    extracted_iocs: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Extracted IOCs (ips, domains, file_paths, registry_keys, etc.)"
    )


class SuspectedTechnique(BaseModel):
    """A suspected MITRE ATT&CK technique identified in the command."""
    technique: str = Field(..., description="Primary technique name")
    subtechnique: Optional[str] = Field(None, description="Subtechnique if applicable")
    indicators_matched: list[str] = Field(..., description="Specific indicators that matched from heuristic engine")
    rationale: str = Field(..., description="Explanation of why this technique was suspected")
    severity: Severity = Field(..., description="Severity/risk level of this technique")
    confidence: TechniqueConfidence = Field(..., description="Confidence in this technique identification")
    attack_phase: Optional[str] = Field(None, description="Attack phase (reconnaissance, execution, persistence, etc.)")

# Optional
class AlternativeInterpretation(BaseModel):
    """Alternative interpretation when command analysis is ambiguous."""
    technique: str = Field(..., description="Alternative technique name")
    likelihood: float = Field(..., ge=0.0, le=1.0, description="Likelihood of this interpretation")
    context_needed: str = Field(..., description="What additional context would disambiguate")


class Classification(BaseModel):
    """Classification of the command's offensive techniques."""
    suspected_techniques: list[SuspectedTechnique] = Field(..., description="Identified techniques")
    alternative_interpretations: list[AlternativeInterpretation] = Field(
        default_factory=list,
        description="Alternative interpretations if ambiguous"
    )
    command_family: Optional[str] = Field(
        None,
        description="High-level command category (credential_access, lateral_movement, etc.)"
    )


# MITRE ATT&CK models
class MitreAttackMapping(BaseModel):
    """Mapping to MITRE ATT&CK framework."""
    technique_id: str = Field(..., description="MITRE ATT&CK technique ID (e.g., T1059)")
    technique_name: str = Field(..., description="Official technique name")
    subtechnique_id: Optional[str] = Field(None, description="Subtechnique ID if applicable (e.g., T1059.001)")
    tactic: str = Field(..., description="Primary tactic (Execution, Defense Evasion, etc.)")
    justification: str = Field(..., description="Explanation of why this mapping applies")
    mitre_url: str = Field(..., description="Direct URL to MITRE ATT&CK page")

    @field_validator('mitre_url')
    @classmethod
    def validate_mitre_url(cls, v: str) -> str:
        """Ensure MITRE URL is properly formatted."""
        if not v.startswith('https://attack.mitre.org/'):
            raise ValueError('MITRE URL must start with https://attack.mitre.org/')
        return v

# Confidence models (optional)
class OverallConfidence(BaseModel):
    """Overall confidence in the entire analysis."""
    score: float = Field(..., ge=0.0, le=1.0, description="Overall confidence score")
    level: ConfidenceLevel = Field(..., description="Categorical confidence level")
    notes: str = Field(..., description="Explanation of confidence factors")
    limitations: list[str] = Field(default_factory=list, description="Known limitations of this analysis")
    assumptions: list[str] = Field(default_factory=list, description="Assumptions made during analysis")
    manual_review_recommended: bool = Field(False, description="Whether manual review is recommended")
    manual_review_reason: Optional[str] = Field(None, description="Why manual review is recommended")


# Metadata models (optional)
class AnalysisMetadata(BaseModel):
    """Metadata about the analysis execution."""
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="When analysis was performed")
    tool_version: str = Field(..., description="Version of the OD-Translator tool")
    schema_version: str = Field(default="2.0.0", description="Version of this output schema")
    processing_time_ms: Optional[float] = Field(None, description="Processing time in milliseconds")
    engine_components: dict[str, str] = Field(
        default_factory=dict,
        description="Versions of individual engine components used"
    )


# Main result model
class AnalysisResult(BaseModel):
    """
    Complete analysis result from the Offensive-Defensive Translator.
    
    This is the canonical output structure with runtime validation via Pydantic.
    """
    metadata: AnalysisMetadata = Field(..., description="Analysis execution metadata")
    input: InputData = Field(..., description="Input command data")
    parsed_components: ParsedComponents = Field(..., description="Parsed command components")
    classification: Classification = Field(..., description="Technique classification")
    mitre_attack: list[MitreAttackMapping] = Field(..., description="MITRE ATT&CK framework mappings")
    defensive_enrichment: DefensiveEnrichment = Field(..., description="Defensive intelligence and guidance")
    confidence: OverallConfidence = Field(..., description="Overall analysis confidence")
    educational_content: EducationalContent = Field(
        default_factory=EducationalContent,
        description="Educational resources and context"
    )

    class Config:
        """Pydantic model configuration."""
        json_schema_extra = {
            "example": {
                "metadata": {
                    "timestamp": "2026-01-20T10:30:00Z",
                    "tool_version": "1.0.0",
                    "schema_version": "2.0.0",
                    "processing_time_ms": 45.2
                },
                "input": {
                    "original_command": "powershell -enc <base64>",
                    "normalized_command": "powershell -encodedcommand <base64>",
                    "detected_shell": "powershell",
                    "detected_os": "windows"
                }
            }
        }
