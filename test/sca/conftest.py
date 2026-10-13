"""pytest configuration of the SCA action tests."""

import sys
from pathlib import Path

# resolve_targets.py and merge_results.py import their sibling modules (sca_config,
# sca_diff), as they do when they run from their action directories
for action in ("sca_resolve_targets", "sca_merge_results"):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "actions" / action))
