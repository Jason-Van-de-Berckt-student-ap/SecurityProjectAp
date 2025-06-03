"""
Database Migration Scripts for EASM Application

This module provides comprehensive database migration capabilities to handle
schema changes and data transformations while maintaining data integrity.

Features:
- Schema migrations with rollback capability
- Data transformation utilities
- Migration versioning and tracking
- Backup and restore functionality
- Performance optimization during migrations

Author: EASM Development Team
"""

import os
import json
import logging
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from pathlib import Path

# Optional PostgreSQL imports
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False
    logging.warning("psycopg2 not found. Database migration and data helper features will be disabled.")

try:
    import sqlparse
    HAS_SQLPARSE = True
except ImportError:
    HAS_SQLPARSE = False
    logging.warning("sqlparse not found. SQL formatting in migration files might be basic.")


logger = logging.getLogger(__name__)

class DatabaseMigration:
    """Handles database schema and data migrations."""

    def __init__(self, db_config: Dict[str, Any]):
        self.db_config = db_config
        self.migration_dir = Path(__file__).parent.parent / 'migrations'
        self.migration_dir.mkdir(exist_ok=True)

        # Determine if the migration service is enabled
        self.enabled = True
        if db_config.get('type') == 'sqlite':
            logger.info("SQLite detected - migration service not needed/supported for schema management via this module.")
            self.enabled = False
        elif not HAS_PSYCOPG2:
            logger.warning("psycopg2 not available - migration service disabled.")
            self.enabled = False

        if self.enabled:
            # Ensure migration tracking table exists only if enabled
            self._create_migration_table()
        else:
            logger.info("DatabaseMigration service is disabled.")

    def _get_connection(self):
        """Get database connection."""
        if not self.enabled:
            raise RuntimeError("Database Migration service is disabled. Cannot establish database connection.")
        if not HAS_PSYCOPG2: # This check is redundant if enabled is already False, but good for clarity
            raise RuntimeError("psycopg2 not available. Cannot establish database connection.")

        return psycopg2.connect(
            host=self.db_config['host'],
            port=self.db_config['port'],
            database=self.db_config['database'],
            user=self.db_config['user'],
            password=self.db_config['password']
        )

    def _create_migration_table(self):
        """Create migration tracking table if it doesn't exist."""
        # Already checked in __init__, but safe to check again
        if not self.enabled:
            return

        try:
            with self._get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS schema_migrations (
                            id SERIAL PRIMARY KEY,
                            version VARCHAR(255) UNIQUE NOT NULL,
                            name VARCHAR(255) NOT NULL,
                            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            checksum VARCHAR(64),
                            execution_time_ms INTEGER,
                            success BOOLEAN DEFAULT TRUE
                        )
                    """)
                    conn.commit()
                    logger.info("Migration tracking table ready.")
        except Exception as e:
            logger.error(f"Error creating migration table: {e}")
            raise # Re-raise to indicate a critical setup failure

    def create_migration(self, name: str, up_sql: str, down_sql: str = "") -> str:
        """
        Create a new migration file.
        This function creates the file even if the DB service is disabled,
        as migration files can be prepared offline.
        """
        try:
            # Generate version number (timestamp)
            version = datetime.now().strftime("%Y%m%d%H%M%S")
            filename = f"{version}_{name.lower().replace(' ', '_')}.py"
            filepath = self.migration_dir / filename

            # Migration template
            migration_content = f'''"""
Migration: {name}
Version: {version}
Created: {datetime.now().isoformat()}
"""

def up(cursor, conn):
    """Apply migration."""
    {self._format_sql_for_python(up_sql)}

def down(cursor, conn):
    """Rollback migration."""
    {self._format_sql_for_python(down_sql) if down_sql else '    pass  # No rollback defined'}

# Migration metadata
MIGRATION_VERSION = "{version}"
MIGRATION_NAME = "{name}"
MIGRATION_DEPENDENCIES = []  # List of required migrations
'''

            # Write migration file
            with open(filepath, 'w') as f:
                f.write(migration_content)

            logger.info(f"Created migration: {filename}")
            return filename

        except Exception as e:
            logger.error(f"Error creating migration file: {e}")
            raise

    def _format_sql_for_python(self, sql: str) -> str:
        """Format SQL for Python migration file."""
        if not sql.strip():
            return "    pass" # Indented for the function body

        python_code = []
        if HAS_SQLPARSE:
            statements = sqlparse.split(sql)
            for stmt in statements:
                if stmt.strip():
                    python_code.append(f'    cursor.execute("""\n{stmt.strip()}\n    """)')
        else:
            # Fallback if sqlparse is not available
            python_code.append(f'    cursor.execute("""\n{sql.strip()}\n    """)')

        return '\n'.join(python_code) if python_code else "    pass"


    def get_pending_migrations(self) -> List[Dict[str, Any]]:
        """Get list of pending migrations."""
        # Can still list files even if DB is disabled, but won't check against applied
        if not self.enabled:
            logger.info("Migration service disabled. Cannot check applied migrations from DB.")
            # Just return all files as "pending" or an empty list if that's preferred
            # For this scenario, returning all files is more informative for a user
            # who might then re-enable the service.
            all_files = []
            for file_path in self.migration_dir.glob("*.py"):
                if file_path.name.startswith("__"):
                    continue
                version = file_path.stem.split("_")[0]
                all_files.append({
                    'version': version,
                    'name': file_path.stem,
                    'file_path': str(file_path),
                    'status': 'pending (DB disabled)'
                })
            all_files.sort(key=lambda x: x['version'])
            return all_files


        try:
            # Get applied migrations
            with self._get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                    cursor.execute("SELECT version FROM schema_migrations ORDER BY version")
                    applied_versions = {row['version'] for row in cursor.fetchall()}

            # Get all migration files
            migration_files = []
            for file_path in self.migration_dir.glob("*.py"):
                if file_path.name.startswith("__"):
                    continue  # Skip __init__.py etc.

                version = file_path.stem.split("_")[0]
                if version not in applied_versions:
                    migration_files.append({
                        'version': version,
                        'name': file_path.stem,
                        'file_path': str(file_path)
                    })

            # Sort by version
            migration_files.sort(key=lambda x: x['version'])
            return migration_files

        except Exception as e:
            logger.error(f"Error getting pending migrations: {e}")
            return []

    def apply_migration(self, migration_file: str) -> bool:
        """Apply a single migration."""
        if not self.enabled:
            logger.warning(f"Migration service disabled. Skipping application of {migration_file}.")
            return False

        try:
            start_time = datetime.now()

            # Import migration module
            import importlib.util
            spec = importlib.util.spec_from_file_location("migration", migration_file)
            migration_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(migration_module)

            version = migration_module.MIGRATION_VERSION
            name = migration_module.MIGRATION_NAME

            logger.info(f"Applying migration {version}: {name}")

            # Calculate checksum of migration file
            with open(migration_file, 'rb') as f:
                checksum = hashlib.sha256(f.read()).hexdigest()

            # Apply migration in transaction
            with self._get_connection() as conn:
                conn.autocommit = False # Ensure transaction
                try:
                    with conn.cursor() as cursor:
                        # Run the migration
                        migration_module.up(cursor, conn)

                        # Record successful migration
                        execution_time = (datetime.now() - start_time).total_seconds() * 1000
                        cursor.execute("""
                            INSERT INTO schema_migrations
                            (version, name, checksum, execution_time_ms, success)
                            VALUES (%s, %s, %s, %s, %s)
                        """, (version, name, checksum, int(execution_time), True))

                        conn.commit()

                    logger.info(f"Successfully applied migration {version} in {execution_time:.0f}ms")
                    return True

                except Exception as e:
                    conn.rollback()
                    logger.error(f"Error applying migration {version}: {e}")

                    # Record failed migration (best effort)
                    try:
                        with conn.cursor() as cursor:
                            execution_time_fail = (datetime.now() - start_time).total_seconds() * 1000
                            cursor.execute("""
                                INSERT INTO schema_migrations
                                (version, name, checksum, execution_time_ms, success)
                                VALUES (%s, %s, %s, %s, %s)
                            """, (version, name, checksum, int(execution_time_fail), False))
                            conn.commit()
                    except Exception as record_e:
                        logger.error(f"Failed to record migration failure for {version}: {record_e}")

                    raise # Re-raise the original exception after rollback and logging

        except Exception as e:
            logger.error(f"Overall error in apply_migration for {migration_file}: {e}")
            return False

    def rollback_migration(self, version: str) -> bool:
        """Rollback a specific migration."""
        if not self.enabled:
            logger.warning(f"Migration service disabled. Skipping rollback of {version}.")
            return False

        try:
            # Find migration file
            migration_files = list(self.migration_dir.glob(f"{version}_*.py"))
            if not migration_files:
                logger.error(f"Migration file not found for version {version}")
                return False

            migration_file = migration_files[0]

            # Import migration module
            import importlib.util
            spec = importlib.util.spec_from_file_location("migration", str(migration_file))
            migration_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(migration_module)

            name = migration_module.MIGRATION_NAME

            logger.info(f"Rolling back migration {version}: {name}")

            # Rollback in transaction
            with self._get_connection() as conn:
                conn.autocommit = False # Ensure transaction
                try:
                    with conn.cursor() as cursor:
                        # Run the rollback
                        migration_module.down(cursor, conn)

                        # Remove migration record
                        cursor.execute(
                            "DELETE FROM schema_migrations WHERE version = %s",
                            (version,)
                        )

                        conn.commit()

                    logger.info(f"Successfully rolled back migration {version}")
                    return True

                except Exception as e:
                    conn.rollback()
                    logger.error(f"Error rolling back migration {version}: {e}")
                    raise # Re-raise the exception after rollback

        except Exception as e:
            logger.error(f"Overall error in rollback_migration for {version}: {e}")
            return False

    def migrate_up(self, target_version: Optional[str] = None) -> bool:
        """Apply all pending migrations up to target version."""
        if not self.enabled:
            logger.info("Migration service disabled - skipping migrations application.")
            return True

        try:
            pending = self.get_pending_migrations() # This will get pending relative to applied in DB

            if target_version:
                pending = [m for m in pending if m['version'] <= target_version]

            if not pending:
                logger.info("No pending migrations to apply.")
                return True

            logger.info(f"Applying {len(pending)} migrations...")

            for migration in pending:
                try:
                    success = self.apply_migration(migration['file_path'])
                    if not success:
                        logger.error(f"Migration failed at {migration['version']}. Halting further migrations.")
                        return False
                except Exception as e:
                    logger.error(f"Unhandled exception during migration {migration['version']}: {e}. Halting.")
                    return False

            logger.info("All selected migrations applied successfully.")
            return True

        except Exception as e:
            logger.error(f"Error in migrate_up process: {e}")
            return False

    def get_migration_status(self) -> Dict[str, Any]:
        """Get current migration status."""
        if not self.enabled:
            logger.info("Migration service disabled. Cannot fetch detailed migration status from DB.")
            return {
                'enabled': False,
                'status': 'disabled',
                'message': 'Migration service is disabled due to missing psycopg2 or SQLite usage.'
            }
        try:
            with self._get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                    # Get applied migrations
                    cursor.execute("""
                        SELECT version, name, applied_at, execution_time_ms, success
                        FROM schema_migrations
                        ORDER BY version DESC
                    """)
                    applied = cursor.fetchall()

            pending = self.get_pending_migrations() # This will accurately list pending based on DB records

            return {
                'enabled': True,
                'applied_count': len(applied),
                'pending_count': len(pending),
                'latest_applied': applied[0] if applied else None,
                'pending_migrations': pending,
                'failed_migrations': [m for m in applied if not m['success']]
            }

        except Exception as e:
            logger.error(f"Error getting migration status: {e}")
            return {'enabled': True, 'error': str(e)}

class DataMigrationHelper:
    """Helper class for data transformations during migrations."""

    def __init__(self, db_config: Dict[str, Any]):
        self.db_config = db_config
        self.enabled = True
        if db_config.get('type') == 'sqlite':
            logger.info("SQLite detected - data migration helper not needed/supported for complex transformations via this module.")
            self.enabled = False
        elif not HAS_PSYCOPG2:
            logger.warning("psycopg2 not available - data migration helper disabled.")
            self.enabled = False

        if not self.enabled:
            logger.info("DataMigrationHelper service is disabled.")

    def _get_connection(self):
        """Get database connection."""
        if not self.enabled:
            raise RuntimeError("Data Migration Helper is disabled. Cannot establish database connection.")
        if not HAS_PSYCOPG2: # Redundant but clear
            raise RuntimeError("psycopg2 not available. Cannot establish database connection.")

        return psycopg2.connect(
            host=self.db_config['host'],
            port=self.db_config['port'],
            database=self.db_config['database'],
            user=self.db_config['user'],
            password=self.db_config['password']
        )

    def batch_update(self, table: str, updates: List[Dict[str, Any]],
                    batch_size: int = 1000, where_clause: str = "id = %(id)s") -> int:
        """Perform batch updates on a table."""
        if not self.enabled:
            logger.warning("DataMigrationHelper disabled. Skipping batch update.")
            return 0
        if not updates:
            return 0

        total_updated = 0
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cursor:
                    for i in range(0, len(updates), batch_size):
                        batch = updates[i:i + batch_size]

                        for update in batch:
                            # Build SET clause
                            set_clauses = []
                            values = {}

                            for key, value in update.items():
                                # Assuming 'id' is used in where_clause and not part of SET
                                if key not in [part.split(' ')[0] for part in where_clause.split(' ')]:
                                    set_clauses.append(f"{key} = %({key})s")
                                values[key] = value

                            if set_clauses: # Only execute if there are actual fields to update
                                sql = f"UPDATE {table} SET {', '.join(set_clauses)} WHERE {where_clause}"
                                cursor.execute(sql, values)
                                total_updated += cursor.rowcount

                        conn.commit()
                        logger.info(f"Updated batch {i//batch_size + 1}: {len(batch)} records.")

            logger.info(f"Total records updated: {total_updated}")
            return total_updated

        except Exception as e:
            logger.error(f"Error in batch_update for table '{table}': {e}")
            raise

    def transform_column_data(self, table: str, column: str,
                            transform_func: Callable[[Any], Any],
                            batch_size: int = 1000) -> int:
        """Transform data in a specific column."""
        if not self.enabled:
            logger.warning("DataMigrationHelper disabled. Skipping column data transformation.")
            return 0

        total_transformed = 0
        try:
            with self._get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                    # Get total count
                    cursor.execute(f"SELECT COUNT(*) as count FROM {table}")
                    total_rows = cursor.fetchone()['count']

                    # Process in batches
                    for offset in range(0, total_rows, batch_size):
                        cursor.execute(f"""
                            SELECT id, {column}
                            FROM {table}
                            ORDER BY id
                            LIMIT %s OFFSET %s
                        """, (batch_size, offset))

                        rows = cursor.fetchall()
                        updates = []

                        for row in rows:
                            try:
                                old_value = row[column]
                                new_value = transform_func(old_value)

                                if new_value != old_value:
                                    updates.append({
                                        'id': row['id'],
                                        column: new_value
                                    })
                            except Exception as e:
                                logger.warning(f"Transform failed for row ID {row.get('id', 'N/A')} in column '{column}': {e}")

                        # Apply updates using batch_update
                        if updates:
                            # Recurse to self.batch_update, which handles its own enabled check
                            transformed_in_batch = self.batch_update(table, updates, where_clause="id = %(id)s")
                            total_transformed += transformed_in_batch

                        logger.info(f"Processed batch: {offset + len(rows)}/{total_rows} for column '{column}'.")

            logger.info(f"Total records transformed in column '{column}': {total_transformed}")
            return total_transformed

        except Exception as e:
            logger.error(f"Error in transform_column_data for table '{table}', column '{column}': {e}")
            raise

    def migrate_table_structure(self, old_table: str, new_table: str,
                              column_mapping: Dict[str, str]) -> int:
        """Migrate data from old table structure to new table structure."""
        if not self.enabled:
            logger.warning("DataMigrationHelper disabled. Skipping table structure migration.")
            return 0

        try:
            with self._get_connection() as conn:
                with conn.cursor() as cursor:
                    # Build column lists
                    old_columns = list(column_mapping.keys())
                    new_columns = list(column_mapping.values())

                    # Copy data
                    sql = f"""
                        INSERT INTO {new_table} ({', '.join(new_columns)})
                        SELECT {', '.join(old_columns)}
                        FROM {old_table}
                    """

                    cursor.execute(sql)
                    rows_migrated = cursor.rowcount
                    conn.commit()

                    logger.info(f"Migrated {rows_migrated} rows from {old_table} to {new_table}")
                    return rows_migrated

        except Exception as e:
            logger.error(f"Error migrating table structure from '{old_table}' to '{new_table}': {e}")
            raise

def create_initial_optimization_migrations():
    """Create initial migrations for optimization features."""

    # Note: This function will still create the .py files even if psycopg2 is not present,
    # because it only instantiates DatabaseMigration to use its create_migration method,
    # which only writes files and does not interact with the DB directly.
    # The actual application of these migrations will fail if psycopg2 is missing,
    # as checked by the DatabaseMigration class itself.
    migration = DatabaseMigration({
        'host': 'localhost',
        'port': 5432,
        'database': 'easm_db',
        'user': 'easm_user',
        'password': 'easm_pass',
        'type': 'postgresql' # Explicitly state type for DatabaseMigration to attempt Redis
    })

    # Migration 1: Add optimization tables
    migration_1_up = """
    -- Create scan_cache table for caching scan results
    CREATE TABLE IF NOT EXISTS scan_cache (
        id SERIAL PRIMARY KEY,
        cache_key VARCHAR(255) UNIQUE NOT NULL,
        domain VARCHAR(255) NOT NULL,
        scan_type VARCHAR(50) NOT NULL,
        scan_data JSONB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        hit_count INTEGER DEFAULT 0,
        last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX idx_scan_cache_key ON scan_cache(cache_key);
    CREATE INDEX idx_scan_cache_domain ON scan_cache(domain);
    CREATE INDEX idx_scan_cache_expires ON scan_cache(expires_at);

    -- Create background_tasks table for task management
    CREATE TABLE IF NOT EXISTS background_tasks (
        id SERIAL PRIMARY KEY,
        task_id VARCHAR(255) UNIQUE NOT NULL,
        task_type VARCHAR(100) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        priority INTEGER DEFAULT 5,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        started_at TIMESTAMP,
        completed_at TIMESTAMP,
        progress DECIMAL(5,2) DEFAULT 0.00,
        result JSONB,
        error_message TEXT,
        metadata JSONB
    );

    CREATE INDEX idx_background_tasks_status ON background_tasks(status);
    CREATE INDEX idx_background_tasks_priority ON background_tasks(priority);
    CREATE INDEX idx_background_tasks_created ON background_tasks(created_at);

    -- Create rate_limit_tracking table
    CREATE TABLE IF NOT EXISTS rate_limit_tracking (
        id SERIAL PRIMARY KEY,
        client_id VARCHAR(255) NOT NULL,
        endpoint VARCHAR(255) NOT NULL,
        request_count INTEGER DEFAULT 1,
        window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        blocked_count INTEGER DEFAULT 0,
        last_request TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX idx_rate_limit_client ON rate_limit_tracking(client_id, endpoint);
    CREATE INDEX idx_rate_limit_window ON rate_limit_tracking(window_start);
    """

    migration_1_down = """
    DROP TABLE IF EXISTS rate_limit_tracking;
    DROP TABLE IF EXISTS background_tasks;
    DROP TABLE IF EXISTS scan_cache;
    """

    # Migration 2: Add performance indexes
    migration_2_up = """
    -- Add indexes for existing tables if they don't exist
    CREATE INDEX IF NOT EXISTS idx_scan_results_domain ON scan_results(domain);
    CREATE INDEX IF NOT EXISTS idx_scan_results_date ON scan_results(scan_date);
    CREATE INDEX IF NOT EXISTS idx_scan_results_type ON scan_results(scan_type);
    CREATE INDEX IF NOT EXISTS idx_scan_results_status ON scan_results(status);

    -- Add composite indexes for common queries
    CREATE INDEX IF NOT EXISTS idx_scan_results_domain_date ON scan_results(domain, scan_date);
    CREATE INDEX IF NOT EXISTS idx_scan_results_type_status ON scan_results(scan_type, status);
    """

    migration_2_down = """
    DROP INDEX IF EXISTS idx_scan_results_domain_date;
    DROP INDEX IF EXISTS idx_scan_results_type_status;
    DROP INDEX IF EXISTS idx_scan_results_domain;
    DROP INDEX IF EXISTS idx_scan_results_date;
    DROP INDEX IF EXISTS idx_scan_results_type;
    DROP INDEX IF EXISTS idx_scan_results_status;
    """

    # Migration 3: Add audit and monitoring tables
    migration_3_up = """
    -- Create system_metrics table for monitoring
    CREATE TABLE IF NOT EXISTS system_metrics (
        id SERIAL PRIMARY KEY,
        metric_name VARCHAR(100) NOT NULL,
        metric_value DECIMAL(10,4) NOT NULL,
        metric_unit VARCHAR(20),
        recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        tags JSONB
    );

    CREATE INDEX idx_system_metrics_name ON system_metrics(metric_name);
    CREATE INDEX idx_system_metrics_recorded ON system_metrics(recorded_at);

    -- Create audit_log table
    CREATE TABLE IF NOT EXISTS audit_log (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(255),
        action VARCHAR(100) NOT NULL,
        resource_type VARCHAR(50),
        resource_id VARCHAR(255),
        details JSONB,
        ip_address INET,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX idx_audit_log_user ON audit_log(user_id);
    CREATE INDEX idx_audit_log_action ON audit_log(action);
    CREATE INDEX idx_audit_log_created ON audit_log(created_at);
    """

    migration_3_down = """
    DROP TABLE IF EXISTS audit_log;
    DROP TABLE IF EXISTS system_metrics;
    """

    # Create the migrations
    try:
        migration.create_migration("Add optimization tables", migration_1_up, migration_1_down)
        migration.create_migration("Add performance indexes", migration_2_up, migration_2_down)
        migration.create_migration("Add audit and monitoring", migration_3_up, migration_3_down)

        logger.info("Initial optimization migrations created successfully.")
        return True

    except Exception as e:
        logger.error(f"Error creating initial migrations: {e}")
        return False

if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Create initial migrations (files)
    logger.info("Attempting to create initial migration files...")
    if create_initial_optimization_migrations():
        logger.info("Migration files created. Now attempting to apply them to the database.")

        # Apply migrations
        # Ensure your database config is correct for actual application
        db_config = {
            'host': 'localhost',
            'port': 5432,
            'database': 'easm_db',
            'user': 'easm_user',
            'password': 'easm_pass',
            'type': 'postgresql' # Important for DatabaseMigration to try using psycopg2
        }

        # Override HAS_PSYCOPG2 for testing purposes if you want to simulate missing driver
        # HAS_PSYCOPG2 = False

        migration = DatabaseMigration(db_config)

        if migration.enabled:
            logger.info("Database migration service is enabled. Attempting to run migrations.")
            migration.migrate_up()

            status = migration.get_migration_status()
            logger.info(f"Current migration status: {json.dumps(status, indent=2, default=str)}")

            # Example of using DataMigrationHelper (requires actual data/tables)
            # helper = DataMigrationHelper(db_config)
            # if helper.enabled:
            #     logger.info("Data migration helper is enabled. Example usage:")
            #     # try:
            #     #     # Example: transform a 'description' column to uppercase
            #     #     # Make sure 'your_table' and 'description_column' exist
            #     #     # helper.transform_column_data('your_table', 'description_column', lambda x: x.upper())
            #     # except Exception as e:
            #     #     logger.error(f"Data transformation example failed: {e}")
            # else:
            #     logger.warning("Data migration helper is disabled.")
        else:
            logger.warning("Database migration service is disabled. Cannot apply migrations to database.")
    else:
        logger.error("Failed to create initial migration files. Check permissions or template issues.")