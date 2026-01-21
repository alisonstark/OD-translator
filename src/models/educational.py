# Educational content models
from dataclasses import Field
from pydantic import BaseModel, Field, HttpUrl, field_validator


class EducationalContent(BaseModel):
    """Educational resources and context."""
    analyst_notes: list[str] = Field(default_factory=list, description="Notes for junior analysts")
    reference_links: list[str] = Field(default_factory=list, description="Reference documentation links")
    similar_examples: list[str] = Field(default_factory=list, description="Similar command examples")
    learning_resources: list[str] = Field(default_factory=list, description="Learning resources for this technique")