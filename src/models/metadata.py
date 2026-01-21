from enum import Enum
from pydantic import BaseModel, Field, HttpUrl, field_validator

class ImplementationDifficulty(str, Enum):
    """Implementation difficulty for defensive measures."""
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"


class FalsePositiveLikelihood(str, Enum):
    """Likelihood of false positives for detection methods."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class Severity(str, Enum):
    """Severity levels for detected techniques."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# Enumerations for controlled vocabularies
class ConfidenceLevel(str, Enum):
    """Confidence levels for analysis results."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

# Classification models
class TechniqueConfidence(BaseModel):
    """Confidence metrics for individual technique identification."""
    score: float = Field(..., ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    level: ConfidenceLevel = Field(..., description="Categorical confidence level")
    reasoning: str = Field(..., description="Explanation of confidence assessment")