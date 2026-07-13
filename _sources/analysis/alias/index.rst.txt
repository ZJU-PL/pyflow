Alias Analysis
==============

PyFlow provides two alias-analysis implementations for different precision
and integration requirements:

* :doc:`flow_sensitive` models order-aware heap effects, escape state, and
  strong versus weak updates over PyFlow IR.
* :doc:`kcfa` computes a context-sensitive, monotone points-to solution from
  Python source using the migrated PythonStAn solver.

.. toctree::
   :maxdepth: 2

   flow_sensitive
   kcfa
