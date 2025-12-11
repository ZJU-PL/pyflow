Store Graph Analysis
====================

Store graphs represent object relationships and memory layouts, providing the foundation for constraint-based analysis.

Core Concepts
-------------

Object Representation
~~~~~~~~~~~~~~~~~~~~~

- **Nodes**: Represent abstract objects and memory locations
- **Edges**: Represent relationships between objects
- **Attributes**: Object properties and field information
- **Types**: Extended type information for objects

Graph Construction
~~~~~~~~~~~~~~~~~~

- **Allocation Tracking**: Records object creation points
- **Reference Tracking**: Maintains object reference relationships
- **Field Access**: Models attribute and field operations
- **Type Propagation**: Infers and propagates type information

Analysis Integration
--------------------

- **CPA Foundation**: Provides base representation for constraint analysis
- **Points-to Information**: Tracks which variables point to which objects
- **Alias Analysis**: Determines when objects may alias
- **Heap Analysis**: Models complex heap-allocated structures

Canonical Objects
~~~~~~~~~~~~~~~~~

- **Object Canonicalization**: Reduces analysis complexity
- **Set Management**: Efficient handling of object sets
- **Extended Types**: Rich type representation
- **Annotation System**: Attaches analysis results to objects
