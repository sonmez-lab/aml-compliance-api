"""AML Compliance API - Unified REST API for crypto AML/sanctions compliance."""

__version__ = "0.1.0"
__author__ = "NIW Project"

from .config import get_settings
from .api import app, create_app

__all__ = ["get_settings", "app", "create_app", "__version__"]
