"""Configuration for pointer analysis.

This module defines the configuration options for k-CFA pointer analysis.
"""

from dataclasses import dataclass
from re import S
import json
from typing import Optional, List, Dict

__all__ = ["Config"]


@dataclass(frozen=True)
class Config:
    """Analysis configuration.
    
    Attributes:
        context_policy: Context sensitivity policy string
        max_iterations: Maximum solver iterations
        max_points_to_size: Widening threshold for points-to sets
        verbose: Enable verbose logging
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        enable_instrumentation: Enable performance instrumentation
        entry_points: Entry point functions
        build_class_hierarchy: Build class hierarchy and compute MRO
        use_mro_resolution: Use MRO for attribute resolution
        project_path: Project root path for module resolution
        library_paths: External library paths for import resolution
        max_import_depth: Maximum depth for transitive import analysis (0 = no imports, -1 = unlimited)
        track_unknowns: Enable tracking of unknown/unresolved calls and allocations
        log_unknown_details: If True, logs each unknown immediately (verbose mode required)
        enable_debug_monitor: Enable comprehensive debug monitoring
        debug_log_interval: Log snapshot every N iterations
        track_object_flow: Track object creation and propagation
        track_pfg_activation: Track PFG edge activation
        export_debug_data: Export debug data to files
        debug_output_dir: Directory for debug output files
    """
    
    context_policy: str = "2-cfa"
    max_iterations: int = 10000
    max_points_to_size: Optional[int] = None
    verbose: bool = False
    log_level: str = "INFO"
    enable_instrumentation: bool = False
    entry_points: Optional[List[str]] = None
    build_class_hierarchy: bool = True
    use_mro_resolution: bool = True
    project_path: Optional[str] = None
    library_paths: Optional[List[str]] = None
    max_import_depth: int = 2
    track_unknowns: bool = True
    log_unknown_details: bool = False
    type: str = "pointer analysis"
    index_sensitive: bool = False
    
    # Debug monitoring options
    enable_debug_monitor: bool = False
    debug_log_interval: int = 1000
    track_object_flow: bool = False
    track_pfg_activation: bool = False
    export_debug_data: bool = False
    debug_output_dir: str = "debug_output"
    debug_inheritance: bool = False  # Debug class field inheritance
    
    @classmethod
    def from_dict(cls, config_dict: Dict):
        return cls(
            context_policy=config_dict.get("context_policy", "2-cfa"),
            max_iterations=config_dict.get("max_iterations", 10000),
            max_points_to_size=config_dict.get("max_points_to_size", None),
            verbose=config_dict.get("verbose", False),
            log_level=config_dict.get("log_level", "INFO"),
            enable_instrumentation=config_dict.get("enable_instrumentation", False),
            entry_points=config_dict.get("entry_points", None),
            build_class_hierarchy=config_dict.get("build_class_hierarchy", True),
            use_mro_resolution=config_dict.get("use_mro_resolution", True),
            project_path=config_dict.get("project_path", None),
            library_paths=config_dict.get("library_paths", None),
            max_import_depth=config_dict.get("max_import_depth", 2),
            track_unknowns=config_dict.get("track_unknowns", True),
            log_unknown_details=config_dict.get("log_unknown_details", False),
            index_sensitive=config_dict.get("index_sensitive", True),
            enable_debug_monitor=config_dict.get("enable_debug_monitor", False),
            debug_log_interval=config_dict.get("debug_log_interval", 1000),
            track_object_flow=config_dict.get("track_object_flow", False),
            track_pfg_activation=config_dict.get("track_pfg_activation", False),
            export_debug_data=config_dict.get("export_debug_data", False),
            debug_output_dir=config_dict.get("debug_output_dir", "debug_output"),
            debug_inheritance=config_dict.get("debug_inheritance", False),
            type="pointer analysis")
    
    def to_dict(self) -> Dict:
        return {
            "context_policy": self.context_policy,
            "max_iterations": self.max_iterations,
            "max_points_to_size": self.max_points_to_size,
            "verbose": self.verbose,
            "log_level": self.log_level,
            "enable_instrumentation": self.enable_instrumentation,
            "entry_points": self.entry_points,
            "build_class_hierarchy": self.build_class_hierarchy,
            "use_mro_resolution": self.use_mro_resolution,
            "project_path": self.project_path,
            "library_paths": self.library_paths,
            "max_import_depth": self.max_import_depth,
            "track_unknowns": self.track_unknowns,
            "log_unknown_details": self.log_unknown_details,
            "index_sensitive": self.index_sensitive,
            "enable_debug_monitor": self.enable_debug_monitor,
            "debug_log_interval": self.debug_log_interval,
            "track_object_flow": self.track_object_flow,
            "track_pfg_activation": self.track_pfg_activation,
            "export_debug_data": self.export_debug_data,
            "debug_output_dir": self.debug_output_dir,
            "debug_inheritance": self.debug_inheritance,
            "type": self.type
        }
    
    def __post_init__(self):
        """Validate configuration."""
        if self.max_iterations <= 0:
            raise ValueError("max_iterations must be positive")
        
        if self.log_level not in ("DEBUG", "INFO", "WARNING", "ERROR"):
            raise ValueError(f"Invalid log level: {self.log_level}")
        
        if self.max_points_to_size is not None and self.max_points_to_size <= 0:
            raise ValueError("max_points_to_size must be positive if set")
        
        if self.max_import_depth < -1:
            raise ValueError("max_import_depth must be >= -1 (-1 = unlimited, 0 = no imports)")
    
    def __str__(self):
        return f"""Pointer Analysis Config: {json.dumps(self.to_dict(), indent=4)}"""
    
    def __repr__(self):
        return self.__str__()
