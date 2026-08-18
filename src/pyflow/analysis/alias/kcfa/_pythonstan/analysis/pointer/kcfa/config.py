"""Configuration for pointer analysis.

This module defines the configuration options for k-CFA pointer analysis.
"""

from dataclasses import dataclass, fields
import json
import re
from typing import Optional, List, Dict

DEFAULT_MAX_ITERATIONS = 50_000

__all__ = ["Config", "DEFAULT_MAX_ITERATIONS"]


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
    max_iterations: int = DEFAULT_MAX_ITERATIONS
    max_points_to_size: Optional[int] = None
    verbose: bool = False
    log_level: str = "INFO"
    enable_instrumentation: bool = False
    entry_points: Optional[List[str]] = None
    build_class_hierarchy: bool = True
    use_mro_resolution: bool = True
    project_path: Optional[str] = None
    library_paths: Optional[List[str]] = None
    max_import_depth: int = -1
    track_unknowns: bool = True
    log_unknown_details: bool = False
    type: str = "pointer analysis"
    index_sensitive: bool = False
    native_effects: Optional[List[Dict]] = None
    worklist_policy: str = "fifo"
    worklist_seed: int = 0
    
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
        defaults = cls()
        values = {
            field.name: config_dict.get(field.name, getattr(defaults, field.name))
            for field in fields(cls)
        }
        if "k" in config_dict:
            k = config_dict["k"]
            if not isinstance(k, int) or isinstance(k, bool) or k < 0:
                raise ValueError("k must be a non-negative integer")
            if "context_policy" not in config_dict:
                values["context_policy"] = f"{k}-cfa"
            else:
                match = re.fullmatch(r"(\d+)-cfa", str(values["context_policy"]))
                if match is not None and int(match.group(1)) != k:
                    raise ValueError(
                        "conflicting context depth: "
                        f"k={k} but context_policy={values['context_policy']!r}"
                    )
        return cls(**values)
    
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
            "native_effects": self.native_effects,
            "worklist_policy": self.worklist_policy,
            "worklist_seed": self.worklist_seed,
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

        if self.worklist_policy not in ("fifo", "lifo", "random"):
            raise ValueError(
                "worklist_policy must be one of: fifo, lifo, random"
            )
    
    def __str__(self):
        return f"""Pointer Analysis Config: {json.dumps(self.to_dict(), indent=4)}"""
    
    def __repr__(self):
        return self.__str__()
