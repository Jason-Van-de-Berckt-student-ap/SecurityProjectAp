"""
Database connection pooling and batch operations manager.
"""
import sqlite3
import threading
import logging
from contextlib import contextmanager
from typing import List, Dict, Any, Optional
import time
from queue import Queue, Empty
import os

logger = logging.getLogger(__name__)

class DatabasePool:
    """Thread-safe SQLite connection pool"""
    
    def __init__(self, database_path: str, max_connections: int = 10, timeout: int = 30):
        self.database_path = database_path
        self.max_connections = max_connections
        self.timeout = timeout
        self.pool = Queue(maxsize=max_connections)
        self.lock = threading.Lock()
        self.created_connections = 0
        
        # Create initial connections
        self._initialize_pool()
    
    def _initialize_pool(self):
        """Initialize the connection pool with connections"""
        for _ in range(min(3, self.max_connections)):  # Start with 3 connections
            conn = self._create_connection()
            if conn:
                self.pool.put(conn)
    
    def _create_connection(self) -> Optional[sqlite3.Connection]:
        """Create a new database connection"""
        try:
            conn = sqlite3.connect(
                self.database_path,
                check_same_thread=False,
                timeout=self.timeout
            )
            conn.row_factory = sqlite3.Row  # Enable dict-like access
            
            # Enable WAL mode for better concurrency
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA cache_size=10000")
            conn.execute("PRAGMA temp_store=MEMORY")
            
            with self.lock:
                self.created_connections += 1
            
            logger.debug(f"Created new database connection #{self.created_connections}")
            return conn
            
        except sqlite3.Error as e:
            logger.error(f"Failed to create database connection: {e}")
            return None
    
    @contextmanager
    def get_connection(self):
        """Get a connection from the pool"""
        conn = None
        try:
            # Try to get connection from pool
            try:
                conn = self.pool.get(timeout=5)
            except Empty:
                # Pool is empty, create new connection if under limit
                with self.lock:
                    if self.created_connections < self.max_connections:
                        conn = self._create_connection()
                    else:
                        # Wait longer for connection from pool
                        conn = self.pool.get(timeout=self.timeout)
            
            if conn is None:
                raise Exception("Unable to get database connection")
            
            yield conn
            
        except Exception as e:
            logger.error(f"Database connection error: {e}")
            if conn:
                try:
                    conn.rollback()
                except:
                    pass
            raise
        finally:
            if conn:
                try:
                    # Return connection to pool
                    self.pool.put(conn, timeout=1)
                except:
                    # Pool is full, close connection
                    conn.close()
                    with self.lock:
                        self.created_connections -= 1
    
    def close_all(self):
        """Close all connections in the pool"""
        while not self.pool.empty():
            try:
                conn = self.pool.get_nowait()
                conn.close()
            except:
                break
        
        with self.lock:
            self.created_connections = 0


class DatabaseManager:
    """High-level database operations with pooling and batch support"""
    
    def __init__(self, database_path: str = None):
        if database_path is None:
            # Default to instance folder database
            database_path = os.path.join(os.path.dirname(__file__), '..', 'instance', 'security_scanner.db')
        
        self.pool = DatabasePool(database_path)
    
    def execute_query(self, query: str, params: tuple = None, fetch: bool = False):
        """Execute a SQL query with optional parameters"""
        try:
            # Convert PostgreSQL-style parameters (%s) to SQLite-style (?)
            sqlite_query = query.replace('%s', '?')
            
            with self.pool.get_connection() as conn:
                cursor = conn.cursor()
                
                if params:
                    cursor.execute(sqlite_query, params)
                else:
                    cursor.execute(sqlite_query)
                
                if fetch:
                    return cursor.fetchall()
                else:
                    conn.commit()
                    return cursor.rowcount
                    
        except Exception as e:
            logger.error(f"Failed to execute query: {e}")
            if fetch:
                return []
            else:
                return 0
    
    def batch_insert_scan_results(self, scan_results: List[Dict[str, Any]]) -> bool:
        """Insert multiple scan results in a single transaction"""
        if not scan_results:
            return True
        
        try:
            with self.pool.get_connection() as conn:
                cursor = conn.cursor()
                
                # Begin transaction
                cursor.execute("BEGIN TRANSACTION")
                
                insert_sql = """
                INSERT INTO scan_results (
                    domain, scan_type, dns_records, ssl_info, vulnerabilities,
                    subdomains, related_domains, darkweb_mentions, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
                
                for result in scan_results:
                    cursor.execute(insert_sql, (
                        result.get('domain'),
                        result.get('scan_type', 'batch'),
                        result.get('dns_records'),
                        result.get('ssl_info'),
                        result.get('vulnerabilities'),
                        result.get('subdomains'),
                        result.get('related_domains'),
                        result.get('darkweb_mentions'),
                        result.get('timestamp', time.time())
                    ))
                
                # Commit transaction
                conn.commit()
                logger.info(f"Successfully inserted {len(scan_results)} scan results")
                return True
                
        except Exception as e:
            logger.error(f"Batch insert failed: {e}")
            return False
    
    def get_recent_scan_results(self, domain: str = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent scan results with optional domain filter"""
        try:
            with self.pool.get_connection() as conn:
                cursor = conn.cursor()
                
                if domain:
                    sql = """
                    SELECT * FROM scan_results 
                    WHERE domain = ? 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                    """
                    cursor.execute(sql, (domain, limit))
                else:
                    sql = """
                    SELECT * FROM scan_results 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                    """
                    cursor.execute(sql, (limit,))
                
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
                
        except Exception as e:
            logger.error(f"Failed to get scan results: {e}")
            return []
    
    def delete_old_scan_results(self, days_old: int = 30) -> int:
        """Delete scan results older than specified days"""
        try:
            cutoff_time = time.time() - (days_old * 24 * 60 * 60)
            
            with self.pool.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "DELETE FROM scan_results WHERE timestamp < ?",
                    (cutoff_time,)
                )
                deleted_count = cursor.rowcount
                conn.commit()
                
                logger.info(f"Deleted {deleted_count} old scan results")
                return deleted_count
                
        except Exception as e:
            logger.error(f"Failed to delete old scan results: {e}")
            return 0
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        try:
            with self.pool.get_connection() as conn:
                cursor = conn.cursor()
                
                # Total scans
                cursor.execute("SELECT COUNT(*) FROM scan_results")
                total_scans = cursor.fetchone()[0]
                
                # Scans by type
                cursor.execute("""
                    SELECT scan_type, COUNT(*) 
                    FROM scan_results 
                    GROUP BY scan_type
                """)
                scans_by_type = dict(cursor.fetchall())
                
                # Recent activity (last 24 hours)
                recent_cutoff = time.time() - (24 * 60 * 60)
                cursor.execute("""
                    SELECT COUNT(*) FROM scan_results 
                    WHERE timestamp > ?
                """, (recent_cutoff,))
                recent_scans = cursor.fetchone()[0]
                
                return {
                    'total_scans': total_scans,
                    'scans_by_type': scans_by_type,
                    'recent_scans_24h': recent_scans,
                    'active_connections': self.pool.created_connections
                }
                
        except Exception as e:
            logger.error(f"Failed to get scan statistics: {e}")
            return {}
    
    def ensure_database_schema(self):
        """Ensure the database schema exists"""
        try:
            with self.pool.get_connection() as conn:
                cursor = conn.cursor()
                
                # Create scan_results table if it doesn't exist
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scan_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain TEXT NOT NULL,
                        scan_type TEXT NOT NULL,
                        dns_records TEXT,
                        ssl_info TEXT,
                        vulnerabilities TEXT,
                        subdomains TEXT,
                        related_domains TEXT,
                        darkweb_mentions TEXT,
                        timestamp REAL NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Create indexes for better performance
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_domain ON scan_results(domain)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_timestamp ON scan_results(timestamp)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_scan_type ON scan_results(scan_type)
                """)
                
                conn.commit()
                logger.info("Database schema ensured")
                
        except Exception as e:
            logger.error(f"Failed to ensure database schema: {e}")
    
    def close(self):
        """Close all database connections"""
        self.pool.close_all()


# Global database manager instance
db_manager = None

def get_db_manager() -> DatabaseManager:
    """Get or create the global database manager"""
    global db_manager
    if db_manager is None:
        db_manager = DatabaseManager()
        db_manager.ensure_database_schema()
    return db_manager
