******
regdis
******

regdis is a module for inspecting the compiled code of Python regex patterns.

Released versions of CPython do not expose regex patterns' code, so this module relies on a custom
patch to the interpreter that may end up being included in Python 3.6 (see link below).

Example usage::

    >>> import regdis
    >>> regdis.dis('fo[ob]')
    [(INFO,
      {'flags': 1,
       'max': 3,
       'min': 3,
       'prefix': {'chars': 'fo',
                  'ignored': 2,
                  'overlap_table': (0, 0),
                  'prefix_len': 2},
       'skip': 10}),
     (LITERAL, 102),
     (LITERAL, 111),
     (IN, (6, [(LITERAL, 'o'), (LITERAL, 'b'), (FAILURE, None)])),
     (SUCCESS, None)]


Links
-----

* `issue 26336 <https://bugs.python.org/issue26336>`_ (proposes the ``__pattern_code__`` attribute)
