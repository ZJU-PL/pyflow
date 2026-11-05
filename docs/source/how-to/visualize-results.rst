.. _how-to-visualize-results:

========================================
How to Visualize Results
========================================

This guide explains how to create professional visualizations of PyFlow's
analysis results.

Visualization Formats
=====================

PyFlow supports multiple visualization formats:

Call Graph Text Output
----------------------

For quick inspection in terminal:

.. code-block:: bash

   pyflow callgraph input.py

IR Dumps with DOT
------------------

For professional vector graphics, use the IR dump command:

.. code-block:: bash

   pyflow ir input.py --dump-cfg main --dump-format dot --dump-output out
   dot -Tpng out/main_cfg.dot -o cfg.png

Visualizing Call Graphs
=======================

Basic call graph
----------------

The callgraph command writes text or JSON. To get DOT, export it through the
Python API:

.. code-block:: python

   from pathlib import Path

   from pyflow.analysis.callgraph import extract_call_graph_constraint
   from pyflow.analysis.callgraph.formats import generate_dot_output

   source = Path("input.py").read_text(encoding="utf-8")
   dot = generate_dot_output(extract_call_graph_constraint(source), None)
   Path("callgraph.dot").write_text(dot, encoding="utf-8")

Then render it:

.. code-block:: bash

   dot -Tpng callgraph.dot -o callgraph.png

Custom styling
--------------

Graphviz attributes are part of the DOT text, so style the exported graph before
writing it:

.. code-block:: python

   styled = dot.replace(
       "node [shape=box, style=filled, fillcolor=lightblue];",
       'node [shape=box, style="rounded,filled", fillcolor=lightblue, fontname="Arial"];',
   )
   # Highlight one node by editing its attribute list.
   styled = styled.replace(
       '"main" [label="main"];',
       '"main" [label="main", fillcolor=lightgreen, penwidth=2];',
   )
   Path("callgraph_styled.dot").write_text(styled, encoding="utf-8")

Render the styled file the same way:

.. code-block:: bash

   dot -Tpng callgraph_styled.dot -o callgraph_styled.png

Interactive visualization
-------------------------

Use pygraphviz to lay out and render the DOT file:

.. code-block:: python

   import pygraphviz as pgv

   G = pgv.AGraph("callgraph.dot")
   G.graph_attr["rankdir"] = "TB"
   G.node_attr["shape"] = "box"
   G.node_attr["style"] = "rounded,filled"
   G.get_node("main").attr["fillcolor"] = "lightgreen"

   G.layout(prog="dot")
   G.draw("callgraph.png")

Visualizing Control Flow Graphs
================================

Basic CFG visualization
-----------------------

.. code-block:: bash

   pyflow ir input.py --dump-cfg function_name --dump-format dot --dump-output out
   dot -Tpng out/function_name_cfg.dot -o cfg.png

Complex CFG visualization
-------------------------

For complex functions with many blocks:

.. code-block:: bash

   pyflow ir input.py --dump-cfg function_name --dump-format json --dump-output out

.. code-block:: python

   import json

   import pygraphviz as pgv

   with open("out/function_name_cfg.json", encoding="utf-8") as f:
       cfg = json.load(f)["cfg"]

   G = pgv.AGraph(directed=True)

   # Add blocks as nodes
   for block in cfg["blocks"]:
       label = f"Block {block['id']}\n" + "\n".join(block["ops"])
       G.add_node(block["id"], label=label, shape="box")

   # Add edges, labelled with the exit kind
   for block in cfg["blocks"]:
       for succ in block["successors"]:
           G.add_edge(block["id"], succ["target"], label=succ["exit"])

   G.layout(prog="dot")
   G.draw("cfg.png")

Visualizing Analysis Results
=============================

Heatmaps for complexity
-----------------------

Create heatmaps showing analysis metrics:

.. code-block:: python

   import matplotlib.pyplot as plt
   import numpy as np

   # Function complexity data
   functions = ["func1", "func2", "func3", "func4"]
   complexity = [5, 12, 8, 15]

   # Create heatmap
   fig, ax = plt.subplots()
   im = ax.imshow([complexity], cmap="YlOrRd")

   # Add labels
   ax.set_xticks(range(len(functions)))
   ax.set_xticklabels(functions)
   ax.set_yticks([])
   ax.set_title("Function Complexity")

   # Add colorbar
   plt.colorbar(im)

   plt.savefig("complexity_heatmap.png")

Dependency graphs
-----------------

Visualize module dependencies:

.. code-block:: python

   import pygraphviz as pgv

   G = pgv.AGraph(directed=True)

   # Add module nodes
   for module in modules:
       G.add_node(module.name, label=module.name)

   # Add dependency edges
   for dep in dependencies:
       G.add_edge(dep.from_module, dep.to_module)

   # Style
   G.graph_attr["rankdir"] = "LR"
   G.edge_attr["arrowsize"] = 0.8

   G.layout(prog="dot")
   G.draw("dependencies.png")

Exporting for Documentation
===========================

Export for Sphinx documentation:

.. code-block:: rst

   .. image:: callgraph.png
      :alt: Call graph visualization

   .. graphviz::

      digraph callgraph {
          main -> func_a;
          main -> func_b;
          func_a -> func_c;
      }

Export for Jupyter notebooks or image generation:

.. code-block:: bash

   pyflow ir input.py --dump-cfg main --dump-format dot --dump-output ./out
   dot -Tpng out/main_cfg.dot -o temp.png

Advanced Visualization Techniques
==================================

Animated visualizations
-----------------------

Create animated call graphs showing analysis evolution:

.. code-block:: python

   import imageio
   import os

   # Generate frames
   frames = []
   for step in analysis_steps:
       generate_visualization(step, f"frame_{step}.png")
       frames.append(imageio.imread(f"frame_{step}.png"))

   # Create animation
   imageio.mimsave("analysis_evolution.gif", frames, fps=1)

Interactive web visualizations
-------------------------------

Use D3.js for interactive web visualizations:

.. code-block:: javascript
   :caption: visualize.js

   // Export PyFlow results to D3.js format
   const data = {
       nodes: callgraph.nodes.map(n => ({
           id: n.name,
           group: n.type
       })),
       links: callgraph.edges.map(e => ({
           source: e.from,
           target: e.to
       }))
   };

   // Create D3 visualization
   const svg = d3.select("#visualization");
   const simulation = d3.forceSimulation(data.nodes)
       .force("link", d3.forceLink(data.links).id(d => d.id))
       .force("charge", d3.forceManyBody().strength(-400))
       .on("tick", ticked);

Troubleshooting
===============

Issue: Graph too large
----------------------

- Reduce information displayed
- Use clustering
- Increase image resolution
- Use hierarchical layout

Issue: Overlapping nodes
-------------------------

- Adjust node spacing
- Use different layout algorithm
- Increase image size
- Reduce label length

Issue: Missing edges
--------------------

- Check if edges exist in data
- Verify DOT generation
- Check for filtered edges
