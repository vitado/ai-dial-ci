"""pytest configuration of the SCA action tests."""

import sys
from pathlib import Path

# resolve_targets.py imports its sibling module sca_config, as it does when it runs
# from its action directory
sys.path.insert(
    0, str(Path(__file__).resolve().parents[2] / "actions" / "sca_resolve_targets")
)
