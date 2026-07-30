"""Data processing pipeline with generators, itertools, and multiple inheritance."""

from .pipeline import Pipeline
from .base import Source, Transform, Sink
from .sources import ListSource, FileSource, GeneratorSource
from .transforms import Map, Filter, FlatMap, GroupBy, Sort
from .sinks import ListSink, FileSink, CounterSink

__all__ = [
    "Pipeline",
    "Source",
    "Transform",
    "Sink",
    "ListSource",
    "FileSource",
    "GeneratorSource",
    "Map",
    "Filter",
    "FlatMap",
    "GroupBy",
    "Sort",
    "ListSink",
    "FileSink",
    "CounterSink",
]
