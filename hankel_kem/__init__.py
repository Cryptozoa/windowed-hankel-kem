"""Windowed Hankel research implementation with a frozen canonical profile.

Backend and code organization changes do not establish cryptographic security
or constant-time behavior of the complete Python protocol.
"""

from .params import CANONICAL, HankelParameters

__all__ = ["CANONICAL", "HankelParameters"]
