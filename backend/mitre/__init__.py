"""MITRE ATT&CK mapping module."""

from .attack_data import ATTACK_TECHNIQUES, get_technique
from .technique_mapper import TechniqueMapper

__all__ = ["ATTACK_TECHNIQUES", "get_technique", "TechniqueMapper"]
