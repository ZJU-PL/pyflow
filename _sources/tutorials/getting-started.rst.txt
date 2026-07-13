.. _tutorial-getting-started:

==================
Getting Started
==================

Welcome to PyFlow! This tutorial will guide you through the basics of installing,
configuring, and running your first static analysis on Python code.

What You'll Learn
=================

- How to install PyFlow from source
- Basic command-line interface usage
- Running your first analysis on a Python file
- Understanding the output and results

Prerequisites
=============

Before installing PyFlow, ensure you have the following prerequisites:

- **Python 3.8 or newer**: PyFlow requires Python 3.8 or a newer version. You can
  check your Python version by running:

  .. code-block:: bash

     python --version

- **Git**: Required for cloning the repository
- **Graphviz** (optional): Required for visualization features such as generating
  control flow graph diagrams. Install via:

  .. code-block:: bash

     # On macOS
     brew install graphviz

     # On Ubuntu/Debian
     apt-get install graphviz

     # On Windows
     choco install graphviz

Installation
============

Install PyFlow from source by following these steps:

1. **Clone the Repository**

   .. code-block:: bash

      git clone https://github.com/ZJU-PL/pyflow.git
      cd pyflow

2. **Create a Virtual Environment** (recommended)

   .. code-block:: bash

      python -m venv venv
      source venv/bin/activate  # On Windows: venv\Scripts\activate

3. **Install PyFlow in Development Mode**

   .. code-block:: bash

      pip install -e .

   The ``-e`` flag installs PyFlow in "editable" mode, meaning changes to the
   source code will be reflected immediately without reinstallation.

Installation Verification
=========================

Verify that PyFlow was installed correctly by checking its version:

.. code-block:: bash

   pyflow --version

You should see output similar to:

.. code-block:: text

   PyFlow version: 1.0.0

Basic Usage
===========

PyFlow provides a command-line interface with several commands for different
tasks. The main commands are:

- ``optimize``: Run static analysis and optimization on Python code
- ``callgraph``: Build and visualize call graphs from Python code
- ``ir``: Dump AST, CFG, and SSA forms for specific functions
- ``security``: Check for security vulnerabilities

Running Your First Analysis
============================

Let's start with a simple Python file to analyze. Create a file called
``example.py``:

.. code-block:: python
   :caption: example.py

   def fibonacci(n):
       """Calculate the nth Fibonacci number."""
       if n <= 1:
           return n
       return fibonacci(n - 1) + fibonacci(n - 2)

   def factorial(n):
       """Calculate the factorial of n."""
       if n <= 1:
           return 1
       return n * factorial(n - 1)

   def main():
       """Main function to demonstrate analysis."""
       print("Fibonacci(10):", fibonacci(10))
       print("Factorial(5):", factorial(5))

   if __name__ == "__main__":
       main()

Now run a basic analysis:

.. code-block:: bash

   pyflow callgraph example.py

This will output the call graph, showing which functions call which other
functions. You should see output similar to:

.. code-block:: text

   Call Graph for example.py:
   ───────────────────────────────

   fibonacci → fibonacci (recursive)
   factorial → factorial (recursive)
   main → fibonacci
   main → factorial
   main → print

Analyzing Control Flow
======================

You can also analyze the control flow of a specific function:

.. code-block:: bash

   pyflow ir example.py --dump-cfg fibonacci --dump-format text

This will output the Control Flow Graph (CFG) for the ``fibonacci`` function,
showing the basic blocks and their relationships:

.. code-block:: text

   CFG for fibonacci:
   ──────────────────────

   Block 0 (Entry):
     if n <= 1
   Block 1 (True):
     return n
   Block 2 (False):
     return fibonacci(n-1) + fibonacci(n-2)

Visualizing Results
===================

For more visual output, generate the CFG in DOT format:

.. code-block:: bash

   pyflow ir example.py --dump-cfg fibonacci --dump-format dot --output fibonacci.dot

Then convert it to an image:

.. code-block:: bash

   dot -Tpng fibonacci.dot -o fibonacci.png

This creates a visual representation of the control flow graph.

Optimizing Code
===============

PyFlow can also optimize your Python code. Run the optimizer:

.. code-block:: bash

   pyflow optimize example.py --opt-passes simplify

This runs the selected optimization passes over PyFlow's IR and prints the
analysis/optimization progress in the console. Use ``--dump`` and ``--output``
if you want a report written to disk.

Getting Help
============

To see all available commands and options:

.. code-block:: bash

   pyflow --help

To get help for a specific command:

.. code-block:: bash

   pyflow callgraph --help

Next Steps
==========

Now that you've completed the getting started tutorial, you can:

- Learn more about :ref:`analyzing-python-code`
- Explore :ref:`optimizing-python-programs`
- Dive deeper into :ref:`understanding-analysis-results`

For a complete reference of all commands and options, see the :doc:`../cli` documentation.
