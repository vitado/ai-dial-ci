"""Code shared by the SCA actions (``actions/sca_*``).

The actions are composite actions that run a script of their own directory. This
package is the code that more than one of them needs: the workflow commands and the
files of a step (``gha``), JSON files (``jsonio``), HTTP (``http``), version
comparison (``versions``), package URLs (``purl``) and time (``times``). Python
standard library only.

An action that needs it puts the ``actions`` directory on ``PYTHONPATH``
(``${{ github.action_path }}/..``) and imports ``from _sca_lib import gha``. A
package and not loose modules: ``_sca_lib.http`` cannot shadow the ``http`` of the
standard library the way a module ``http.py`` on ``PYTHONPATH`` would.
"""
