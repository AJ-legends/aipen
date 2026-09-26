"""Shared AI role definitions (kept separate to avoid import cycles)."""
from enum import StrEnum


class AIRole(StrEnum):
    PLANNER = "planner"
    ANALYST = "analyst"
    VERIFIER = "verifier"
    REPORTER = "reporter"
    CLASSIFIER = "classifier"
