#!/usr/bin/env python3

"""
@description
---------------------
This module helps to build the codeql database on the codebase.

@usage
---------------------
1/ Build the codeql database given the codebase path.
   It will generate the codeql database named `codeql-db` in the same codebase path.

```python build.py --codebase-path <path-to-codebase>```

If you omit `--codebase-path`, you will be prompted to enter it.
"""
import os
import subprocess
import argparse
import logging

logging.basicConfig(level=logging.INFO)

def build_codeql_database(codebase_path, codeql_db_path="codeql-db"):
    """
    Builds the CodeQL database for the given codebase path.

    Args:
        codebase_path (str): Path to the codebase.
        codeql_db_path (str): Path where the generated CodeQL database should be stored.
    """
    if not os.path.exists(codebase_path):
        raise FileNotFoundError(f"The specified codebase path does not exist: {codebase_path}")

    try:
        print(f"Building CodeQL database at: {codeql_db_path}")
        subprocess.run(
            [
                "codeql", "database", "create", codeql_db_path, 
                "--source-root", codebase_path,
                "--language", "python"
            ],
            check=True
        )
        print(f"CodeQL database created successfully at {codeql_db_path}")
    except subprocess.CalledProcessError as e:
        raise Exception(f"Failed to create CodeQL database: {e}")
    except Exception as e:
        raise Exception(f"Unexpected error: {e}")


def main():
  """
  Usage examples:
  ---------------
  1) Specify the codebase path using --codebase-path:
      ./build.py --codebase-path /path/to/codebase

  2) Omit --codebase-path and just pass the path as the first positional argument:
      ./build.py /path/to/codebase
  """

  parser = argparse.ArgumentParser(description="Build CodeQL database on a codebase.")
  parser.add_argument(
      "--codebase-path", 
      type=str, 
      required=False, 
      help="Path to the codebase."
  )
  parser.add_argument(
      "--database-path", 
      type=str, 
      required=False, 
      help="Path to store the generated CodeQL database. Defaults to ../codeql-db if not provided."
  )
  
  # parse_known_args returns two items: the namespace of known args, and a list of leftover args
  args, leftover_args = parser.parse_known_args()

  # If --codebase-path was not provided but we have leftover_args, 
  # treat leftover_args[0] as the codebase path
  if not args.codebase_path and leftover_args:
      args.codebase_path = leftover_args[0]

  # If we *still* have no codebase path, either prompt or raise an error
  if not args.codebase_path:
      raise ValueError("No codebase path provided via --codebase-path or as a positional argument.")

  # If database-path wasn't provided, default it to ../codeql-db relative to the codebase-path
  if not args.database_path:
      args.database_path = os.path.join(args.codebase_path, "../codeql-db")

  build_codeql_database(args.codebase_path, args.database_path)

if __name__ == "__main__":
    main()