import os
import sys
import subprocess
import argparse
from datetime import datetime

class FileManager:
    def __init__(self, base_dir):
        self.base_dir = os.path.abspath(base_dir)
        if not os.path.exists(self.base_dir):
            os.makedirs(self.base_dir)
    
    def list_files(self, pattern="*"):
        try:
            files = os.listdir(self.base_dir)
            if pattern != "*":
                files = [f for f in files if pattern in f]
            return files
        except Exception as e:
            print(f"Error listing files: {e}")
            return []
    
    def search_files(self, keyword):
        # Fixed: No longer vulnerable to command injection
        try:
            # Use subprocess.run with a list of arguments instead of shell=True
            result = subprocess.run(
                ["grep", "-l", keyword, "--", f"{self.base_dir}/*"],
                capture_output=True,
                text=True
            )
            return result.stdout.splitlines()
        except Exception as e:
            print(f"Search failed: {e}")
            return []
    
    def create_backup(self, filename):
        try:
            if not os.path.exists(os.path.join(self.base_dir, filename)):
                return False
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{filename}.bak_{timestamp}"
            
            subprocess.run(
                ["cp", 
                 os.path.join(self.base_dir, filename),
                 os.path.join(self.base_dir, backup_name)],
                check=True
            )
            return True
        except Exception as e:
            print(f"Backup failed: {e}")
            return False
    
    def get_file_stats(self, filename):
        try:
            path = os.path.join(self.base_dir, filename)
            stat = os.stat(path)
            return {
                'size': stat.st_size,
                'modified': datetime.fromtimestamp(stat.st_mtime),
                'created': datetime.fromtimestamp(stat.st_ctime)
            }
        except Exception as e:
            print(f"Error getting stats: {e}")
            return None

def main():
    parser = argparse.ArgumentParser(description="File Management Utility")
    parser.add_argument("--dir", required=True, help="Base directory")
    subparsers = parser.add_subparsers(dest="command")
    
    # List command
    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--pattern", default="*", help="File pattern")
    
    # Search command
    search_parser = subparsers.add_parser("search")
    search_parser.add_argument("keyword", help="Search keyword")
    
    # Backup command
    backup_parser = subparsers.add_parser("backup")
    backup_parser.add_argument("filename", help="File to backup")
    
    # Stats command
    stats_parser = subparsers.add_parser("stats")
    stats_parser.add_argument("filename", help="File to check")
    
    args = parser.parse_args()
    fm = FileManager(args.dir)
    
    if args.command == "list":
        files = fm.list_files(args.pattern)
        print("\n".join(files))
    elif args.command == "search":
        results = fm.search_files(args.keyword)
        print("Found in files:\n" + "\n".join(results))
    elif args.command == "backup":
        success = fm.create_backup(args.filename)
        print("Backup created" if success else "Backup failed")
    elif args.command == "stats":
        stats = fm.get_file_stats(args.filename)
        if stats:
            print(f"Size: {stats['size']} bytes")
            print(f"Created: {stats['created']}")
            print(f"Modified: {stats['modified']}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()