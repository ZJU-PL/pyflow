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

   pyflow ir input.py --dump-cfg main --dump-format dot --dump-output cfg.dot
   dot -Tpng cfg.dot -o cfg.png

Visualizing Call Graphs
=======================

Basic call graph
----------------

.. code-block:: bash

   pyflow callgraph input.py --output callgraph.txt

Custom styling
--------------

Create a custom style file:

.. code-block:: css
   :caption: callgraph_style.css

   .node {
       shape: box;
       style: "rounded,filled";
       fillcolor: lightblue;
       fontname: "Arial";
   }

   .recursive {
       fillcolor: lightyellow;
   }

   .entry {
       fillcolor: lightgreen;
   }

   .edge {
       fontname: "Arial";
       fontsize: 10;
   }

Apply custom style:

.. code-block:: bash

   dot -Tpng callgraph.dot -o callgraph.png -C

Interactive visualization
-------------------------

Use pygraphviz for interactive graphs:

.. code-block:: bash

   import pygraphviz as pgv

   # Load DOT file
   G = pgv.AGraph("callgraph.dot")

   # Add layout options
   G.graph_attr["rankdir"] = "TB"
   G.node_attr["shape"] = "box"
   G.node_attr["style"] = "rounded,filled"

   # Highlight specific nodes
   G.get_node("main").attr["fillcolor"] = "lightgreen"
   G.get_node("recursive_func").attr["fillcolor"] = "lightyellow"

   # Render
   G.layout(prog="dot")
   G.draw("callgraph.png")

Visualizing Control Flow Graphs
================================

Basic CFG visualization
-----------------------

.. code-block:: bash

   pyflow ir input.py --dump-cfg function_name --dump-format dot --dump-output cfg.dot

Complex CFG visualization
-------------------------

For complex functions with many blocks:

.. code-block:: python

   import pygraphviz as pgv

   G = pgv.AGraph(directed=True)

   # Add blocks as nodes
   for block in cfg.blocks:
       label = f"Block {block.id}\n"
       for stmt in block.statements:
           label += f"{stmt}\n"

       G.add_node(block.id, label=label, shape="box")

   # Add edges
   for edge in cfg.edges:
       G.add_edge(edge.from_block, edge.to_block)

   # Add cluster for loops
   if loop_blocks:
       with G.subgraph() as s:
           s.add_nodes_from(loop_blocks)
           s.attr("color", "blue")
           s.attr("style", "dashed")

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

Export for Jupyter notebooks:

.. code-block:: python

   pyflow callgraph input.py --output temp.dot
   dot -Tpng temp.dot -o temp.png

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
