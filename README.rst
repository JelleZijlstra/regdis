******
regdis
******

regdis is a module for inspecting the compiled code of Python regex patterns.

Released versions of CPython do not expose regex patterns' code, so this module relies on a custom
patch to the interpreter that may end up being included in Python 3.6 (see link below).

Links
-----

* `issue 26336 <https://bugs.python.org/issue26336>`_ (proposes the ``__pattern_code__`` attribute)
