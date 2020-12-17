Portier authentication Python helpers that are asyncio-aware
============================================================

|coverage|

.. |coverage| image:: https://github.com/vr2262/asyncio-portier/workflows/Python%20tests%20and%20coverage/badge.svg

*asyncio-portier* is a set of helpers for `the Portier Identity Provider
<https://portier.github.io/>`_. It is based on `the portier-python package
<https://pypi.python.org/pypi/portier-python>`_ but modified to work with
:code:`asyncio`.

Usage
------------

The helpers work in much the same way as the ones in *portier-python*. Check
`the demos directory
<https://github.com/vr2262/asyncio-portier/tree/master/demos>`_ for usage
examples.

Notes
------------

* *portier-python* doesn't seem to work quite right with Redis as the cache
  backend, so there are a few Redis-specific modifications. This may change in
  the future.
* I expected the calls to cryptographic libraries to be blocking, but I saw no
  improvement from running those calls in an :code:`Executor` as per
  https://docs.python.org/3/library/asyncio-eventloop.html#executor.
