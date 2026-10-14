"""pytest configuration of the SCA action tests."""

import sys
from pathlib import Path

ACTIONS = Path(__file__).resolve().parents[2] / "actions"

# the actions import the shared package as ``_sca_lib``, which their action.yml put
# on PYTHONPATH (the ``actions`` directory)
sys.path.insert(0, str(ACTIONS))
# the action scripts import their sibling modules as they do when they run from
# their action directory
sys.path.insert(0, str(ACTIONS / "sca_resolve_targets"))
sys.path.insert(0, str(ACTIONS / "sca_merge_results"))
