"""pytest configuration of the SCA action tests."""

import sys
from pathlib import Path

ACTIONS = Path(__file__).resolve().parents[2] / "actions"

# the actions import the shared package as ``_sca_lib``, which their action.yml put
# on PYTHONPATH (the ``actions`` directory)
sys.path.insert(0, str(ACTIONS))
# resolve_targets.py imports its sibling module sca_config, as it does when it runs
# from its action directory
sys.path.insert(0, str(ACTIONS / "sca_resolve_targets"))
# merge_results.py imports its sibling modules the same way
sys.path.insert(0, str(ACTIONS / "sca_merge_results"))
