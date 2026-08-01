import os
import subprocess
import sys
import time
from datetime import datetime

class DatabaseBackupTool:
    def __init__(self, backup_dir="backups"):
        self.backup_dir = backup_dir
        self.supported_dbs = ['mysql', 'postgresql', 'mongodb']
        self.create_backup_dir()

    def create_backup_dir(self):
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir)

    def validate_db_type(self, db_type):
        if db_type.lower() not in self.supported_dbs:
            raise ValueError(f"Unsupported database type: {db_type}")

    def generate_backup_name(self, db_type):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{db_type}_backup_{timestamp}.sql"

    def create_backup(self, db_type, db_name, db_user, db_password, host="localhost"):
        self.validate_db_type(db_type)
        backup_file = os.path.join(self.backup_dir, self.generate_backup_name(db_type))

        try:
            if db_type == 'mysql':
                # Secure MySQL backup without command injection
                with open(backup_file, 'w') as f:
                    subprocess.run(
                        ['mysqldump', '-u', db_user, 
                         f'-p{db_password}', '-h', host, db_name],
                        stdout=f,
                        stderr=subprocess.PIPE,
                        check=True
                    )
            elif db_type == 'postgresql':
                # Secure PostgreSQL backup
                env = os.environ.copy()
                env['PGPASSWORD'] = db_password
                with open(backup_file, 'w') as f:
                    subprocess.run(
                        ['pg_dump', '-U', db_user, '-h', host, db_name],
                        stdout=f,
                        stderr=subprocess.PIPE,
                        check=True,
                        env=env
                    )
            else:  # mongodb
                # Secure MongoDB backup
                subprocess.run(
                    ['mongodump', '--host', host,
                     '--username', db_user, '--password', db_password,
                     '--db', db_name, '--out', backup_file],
                    stderr=subprocess.PIPE,
                    check=True
                )
            
            print(f"Backup created at {backup_file}")
            return backup_file
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.decode().strip() if e.stderr else str(e)
            raise RuntimeError(f"Backup failed: {error_msg}")
        except Exception as e:
            raise RuntimeError(f"Error during backup: {str(e)}")

    def list_backups(self):
        return sorted([f for f in os.listdir(self.backup_dir) 
                      if f.endswith('.sql') or f.endswith('.gz')])

    def cleanup_old_backups(self, days_to_keep=30):
        cutoff = time.time() - days_to_keep * 86400
        for filename in os.listdir(self.backup_dir):
            filepath = os.path.join(self.backup_dir, filename)
            if os.path.getmtime(filepath) < cutoff:
                os.remove(filepath)
                print(f"Removed old backup: {filename}")

def print_menu():
    print("\nDatabase Backup Tool:")
    print("1. Create new backup")
    print("2. List existing backups")
    print("3. Cleanup old backups")
    print("4. Exit")

def main():
    backup_tool = DatabaseBackupTool()
    
    while True:
        print_menu()
        choice = input("Enter your choice: ")
        
        if choice == "1":
            db_type = input("Database type (mysql/postgresql/mongodb): ")
            db_name = input("Database name: ")
            db_user = input("Database user: ")
            db_password = input("Database password: ")
            host = input("Host (default localhost): ") or "localhost"
            try:
                backup_tool.create_backup(db_type, db_name, db_user, db_password, host)
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == "2":
            backups = backup_tool.list_backups()
            print("Available backups:")
            for backup in backups:
                print(f"- {backup}")
        
        elif choice == "3":
            days = input("Days to keep (default 30): ") or "30"
            backup_tool.cleanup_old_backups(int(days))
        
        elif choice == "4":
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()