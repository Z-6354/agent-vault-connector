"""Compatibility import for the next-generation lifecycle engine.

The former prefix-only verifier and raw decrypt API have been retired.
Use instance methods with explicit paths and consent; secrets stay in card submits.
"""
from lifecycle_core import LifecycleEngine, LifecycleError

VaultLifecycleEngine = LifecycleEngine

