"""
Compatibility shim for randomizer imports
Redirects to new location: core.utils.randomizer
"""

from core.utils.randomizer import *

__all__ = ['HeaderFactory', 'IPRandomizer', 'get_default_factory']
