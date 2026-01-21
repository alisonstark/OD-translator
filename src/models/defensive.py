from typing import Optional
from models.metadata import FalsePositiveLikelihood, ImplementationDifficulty
from pydantic import BaseModel, Field, HttpUrl, field_validator

# Defensive Enrichment models
class DetectionMethod(BaseModel):
    """A specific detection method for the identified behavior."""
    description: str = Field(..., description="Detection method description")
    priority: int = Field(..., ge=1, le=5, description="Priority level (1=highest, 5=lowest)")
    implementation_difficulty: ImplementationDifficulty = Field(..., description="Difficulty to implement")
    data_sources_required: list[str] = Field(..., description="Required data sources or log types")
    false_positive_likelihood: FalsePositiveLikelihood = Field(..., description="Expected false positive rate")
    sample_query: Optional[str] = Field(None, description="Sample detection query (SIEM/EDR)")


class PreventionMeasure(BaseModel):
    """A preventive control to mitigate the threat."""
    description: str = Field(..., description="Prevention measure description")
    implementation_difficulty: ImplementationDifficulty = Field(..., description="Difficulty to implement")
    effectiveness: float = Field(..., ge=0.0, le=1.0, description="Effectiveness score (0.0-1.0)")
    potential_impact: str = Field(..., description="Potential impact on legitimate operations")

class TelemetrySource(BaseModel):
    """A telemetry source for monitoring this activity."""
    source_name: str = Field(..., description="Name of the telemetry source")
    log_type: str = Field(..., description="Type of log (process, network, file, registry, etc.)")
    required_configuration: Optional[str] = Field(None, description="Configuration needed to enable this telemetry")
    coverage_notes: str = Field(..., description="What this source does and doesn't capture")

class ResponseRecommendation(BaseModel):
    """Immediate response actions for SOC analysts."""
    action: str = Field(..., description="Recommended action")
    priority: int = Field(..., ge=1, le=5, description="Priority level (1=immediate, 5=low)")
    timeframe: str = Field(..., description="Recommended timeframe for action")

class InvestigationGuidance(BaseModel):
    """Guidance for investigating this activity."""
    key_questions: list[str] = Field(..., description="Key questions analysts should ask")
    related_artifacts: list[str] = Field(..., description="Related artifacts to examine")
    escalation_criteria: list[str] = Field(..., description="When to escalate")

class DefensiveEnrichment(BaseModel):
    """Comprehensive defensive enrichment and guidance."""
    detection_methods: list[DetectionMethod] = Field(..., description="Detection strategies")
    prevention_measures: list[PreventionMeasure] = Field(..., description="Prevention controls")
    telemetry_sources: list[TelemetrySource] = Field(..., description="Relevant telemetry sources")
    response_recommendations: list[ResponseRecommendation] = Field(..., description="Immediate response actions")
    investigation_guidance: InvestigationGuidance = Field(..., description="Investigation guidance for analysts")




