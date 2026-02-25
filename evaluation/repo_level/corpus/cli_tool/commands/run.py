from __future__ import annotations

import os
import subprocess
import sys
from argparse import Namespace
from pathlib import Path
from typing import Any

from ..config import Config
from ..logger import get_logger

logger = get_logger(__name__)


def run(args: Namespace, config: Config) -> int:
    logger.info(f"Running project: {config.name}")
    
    env = dict(os.environ)
    for env_var in args.env:
        if "=" in env_var:
            key, value = env_var.split("=", 1)
            env[key] = value
            logger.debug(f"Setting environment: {key}={value}")
    
    env.update(config.env)
    
    cmd = _build_command(args, config)
    logger.debug(f"Command: {' '.join(cmd)}")
    
    if args.dry_run:
        logger.info("Would execute:")
        logger.info(f"  {' '.join(cmd)}")
        return 0
    
    try:
        result = subprocess.run(
            cmd,
            env=env,
            cwd=Path.cwd(),
        )
        return result.returncode
    except KeyboardInterrupt:
        logger.info("Process interrupted")
        return 130


def _build_command(args: Namespace, config: Config) -> list[str]:
    cmd = [sys.executable, "-m", config.name]
    
    if args.host != "localhost":
        cmd.extend(["--host", args.host])
    
    cmd.extend(["--port", str(args.port)])
    
    if args.workers > 1:
        cmd.extend(["--workers", str(args.workers)])
    
    if args.passthrough:
        cmd.extend(args.passthrough)
    
    return cmd


class Runner:
    def __init__(self, config: Config):
        self.config = config
        self._pre_hooks: list[Any] = []
        self._post_hooks: list[Any] = []
    
    def add_pre_hook(self, hook: Any) -> None:
        self._pre_hooks.append(hook)
    
    def add_post_hook(self, hook: Any) -> None:
        self._post_hooks.append(hook)
    
    def run(
        self,
        command: list[str],
        env: dict[str, str] | None = None,
        cwd: Path | None = None,
    ) -> int:
        full_env = dict(os.environ)
        if env:
            full_env.update(env)
        
        for hook in self._pre_hooks:
            try:
                hook()
            except Exception as e:
                logger.warning(f"Pre-hook failed: {e}")
        
        try:
            result = subprocess.run(
                command,
                env=full_env,
                cwd=cwd or Path.cwd(),
            )
            returncode = result.returncode
        except Exception as e:
            logger.error(f"Command failed: {e}")
            returncode = 1
        finally:
            for hook in self._post_hooks:
                try:
                    hook()
                except Exception as e:
                    logger.warning(f"Post-hook failed: {e}")
        
        return returncode


class Process:
    def __init__(self, command: list[str], env: dict[str, str] | None = None):
        self.command = command
        self.env = env or {}
        self._process: subprocess.Popen | None = None
    
    def start(self) -> None:
        full_env = dict(os.environ)
        full_env.update(self.env)
        
        self._process = subprocess.Popen(
            self.command,
            env=full_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        logger.info(f"Started process: PID {self._process.pid}")
    
    def stop(self, timeout: float = 5.0) -> None:
        if self._process is None:
            return
        
        self._process.terminate()
        try:
            self._process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait()
        
        logger.info(f"Stopped process: PID {self._process.pid}")
    
    @property
    def pid(self) -> int | None:
        return self._process.pid if self._process else None
    
    @property
    def running(self) -> bool:
        if self._process is None:
            return False
        return self._process.poll() is None
