"""Narrow attended application lanes for the M4 operator shell."""

from .capture_research import CaptureResearchLane
from .cognition_knowledge import CognitionKnowledgeLane
from .lifecycle import SettingsLifecycleLane
from .workflow_agents import WorkflowAgentsLane

__all__ = [
    "CaptureResearchLane",
    "CognitionKnowledgeLane",
    "SettingsLifecycleLane",
    "WorkflowAgentsLane",
]
