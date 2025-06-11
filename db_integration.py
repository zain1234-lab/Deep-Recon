import logging
import threading
import time
import hashlib
from typing import Dict, Any, Optional, List, Union
from pathlib import Path
import json
import sqlite3
from datetime import datetime
from contextlib import contextmanager
from dataclasses import dataclass
import re

logger = logging.getLogger('recon_tool')

@dataclass
class DatabaseConfig:
    """Database configuration with connection pooling settings"""
    max_connections: int = 10
    connection_timeout: float = 30.0
    retry_attempts: int = 3
    retry_delay: float = 1.0
    enable_wal_mode: bool = True
    pragma_settings: Dict[str, Any] = None

    def __post_init__(self):
        if self.pragma_settings is None:
            self.pragma_settings = {
                'journal_mode': 'WAL',
                'synchronous': 'NORMAL',
                'cache_size': -64000,  # 64MB cache
                'temp_store': 'MEMORY',
                'mmap_size': 268435456,  # 256MB mmap
                'optimize': None
            }

class ConnectionPool:
    """Thread-safe connection pool for SQLite"""
    
    def __init__(self, db_path: str, config: DatabaseConfig):
        self.db_path = db_path
        self.config = config
        self._pool = []
        self._pool_lock = threading.Lock()
        self._active_connections = 0
        self.logger = logging.getLogger(f'{__name__}.ConnectionPool')
        
    @contextmanager
    def get_connection(self):
        """Context manager for getting and returning connections"""
        conn = None
        try:
            conn = self._acquire_connection()
            yield conn
        except Exception as e:
            if conn:
                try:
                    conn.rollback()
                except:
                    pass
            raise
        finally:
            if conn:
                self._release_connection(conn)
    
    def _acquire_connection(self) -> sqlite3.Connection:
        """Acquire a connection from the pool or create new one"""
        with self._pool_lock:
            if self._pool:
                conn = self._pool.pop()
                try:
                    # Test connection
                    conn.execute('SELECT 1').fetchone()
                    return conn
                except sqlite3.Error:
                    # Connection is stale, create new one
                    try:
                        conn.close()
                    except:
                        pass
            
            if self._active_connections >= self.config.max_connections:
                raise RuntimeError(f"Maximum connection limit ({self.config.max_connections}) reached")
            
            conn = self._create_connection()
            self._active_connections += 1
            return conn
    
    def _release_connection(self, conn: sqlite3.Connection):
        """Return connection to pool"""
        try:
            # Ensure no active transaction
            conn.rollback()
            with self._pool_lock:
                if len(self._pool) < self.config.max_connections // 2:
                    self._pool.append(conn)
                else:
                    conn.close()
                    self._active_connections -= 1
        except Exception as e:
            self.logger.error(f"Error releasing connection: {e}")
            try:
                conn.close()
            except:
                pass
            with self._pool_lock:
                self._active_connections -= 1
    
    def _create_connection(self) -> sqlite3.Connection:
        """Create a new database connection with optimizations"""
        try:
            conn = sqlite3.connect(
                self.db_path,
                timeout=self.config.connection_timeout,
                check_same_thread=False
            )
            
            # Apply pragma settings for performance
            for pragma, value in self.config.pragma_settings.items():
                if value is not None:
                    conn.execute(f'PRAGMA {pragma} = {value}')
                else:
                    conn.execute(f'PRAGMA {pragma}')
            
            conn.execute('PRAGMA foreign_keys = ON')
            return conn
            
        except sqlite3.Error as e:
            self.logger.error(f"Failed to create connection to {self.db_path}: {e}")
            raise RuntimeError(f"Database connection failed: {e}")
    
    def close_all(self):
        """Close all connections in pool"""
        with self._pool_lock:
            for conn in self._pool:
                try:
                    conn.close()
                except:
                    pass
            self._pool.clear()
            self._active_connections = 0

class DatabaseValidator:
    """Validates and sanitizes database inputs"""
    
    @staticmethod
    def validate_target(target: str) -> str:
        """Validate and sanitize target name"""
        if not target or not isinstance(target, str):
            raise ValueError("Target must be a non-empty string")
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[^\w\-\.\:]', '_', target.strip())
        if not sanitized:
            raise ValueError("Target name contains only invalid characters")
        
        return sanitized[:255]  # Limit length
    
    @staticmethod
    def validate_module(module: str) -> str:
        """Validate module name"""
        if not module or not isinstance(module, str):
            raise ValueError("Module must be a non-empty string")
        
        sanitized = re.sub(r'[^\w\-_]', '_', module.strip())
        if not sanitized:
            raise ValueError("Module name contains only invalid characters")
        
        return sanitized[:100]
    
    @staticmethod
    def validate_json_data(data: Any) -> str:
        """Validate and serialize data to JSON"""
        try:
            if data is None:
                return '{}'
            
            # Ensure it's JSON serializable
            json_str = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
            
            # Limit size (10MB max)
            if len(json_str.encode('utf-8')) > 10 * 1024 * 1024:
                raise ValueError("Data too large (max 10MB)")
            
            return json_str
            
        except (TypeError, ValueError) as e:
            raise ValueError(f"Invalid JSON data: {e}")

# Global connection pools cache
_connection_pools: Dict[str, ConnectionPool] = {}
_pools_lock = threading.Lock()

def _get_connection_pool(db_path: str, config: DatabaseConfig = None) -> ConnectionPool:
    """Get or create connection pool for database"""
    abs_path = str(Path(db_path).resolve())
    
    with _pools_lock:
        if abs_path not in _connection_pools:
            if config is None:
                config = DatabaseConfig()
            _connection_pools[abs_path] = ConnectionPool(abs_path, config)
        
        return _connection_pools[abs_path]

def _execute_with_retry(func, max_retries: int = 3, delay: float = 1.0):
    """Execute function with retry logic for transient failures"""
    last_exception = None
    
    for attempt in range(max_retries):
        try:
            return func()
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
            last_exception = e
            if attempt < max_retries - 1:
                error_msg = str(e).lower()
                # Retry on transient errors
                if any(x in error_msg for x in ['locked', 'busy', 'temporary']):
                    logger.warning(f"Database operation failed (attempt {attempt + 1}), retrying: {e}")
                    time.sleep(delay * (2 ** attempt))  # Exponential backoff
                    continue
            raise
        except Exception as e:
            # Don't retry on non-database errors
            raise
    
    raise last_exception

def init_db(db_path: str) -> sqlite3.Connection:
    """Initialize database with robust schema and optimizations"""
    try:
        logger.info(f"Initializing database: {db_path}")
        
        # Ensure directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        pool = _get_connection_pool(db_path)
        
        def _init_schema():
            with pool.get_connection() as conn:
                cursor = conn.cursor()
                
                # Create tables with proper constraints and indexes
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS database_info (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS findings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        target TEXT NOT NULL,
                        module TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        data TEXT NOT NULL,
                        data_hash TEXT NOT NULL,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        CONSTRAINT unique_finding UNIQUE (target, module, data_hash)
                    )
                ''')
                
                # Create indexes for performance
                indexes = [
                    'CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target)',
                    'CREATE INDEX IF NOT EXISTS idx_findings_module ON findings(module)',
                    'CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp)',
                    'CREATE INDEX IF NOT EXISTS idx_findings_target_module ON findings(target, module)',
                    'CREATE INDEX IF NOT EXISTS idx_findings_hash ON findings(data_hash)'
                ]
                
                for index_sql in indexes:
                    cursor.execute(index_sql)
                
                # Set database version
                cursor.execute('''
                    INSERT OR REPLACE INTO database_info (key, value, updated_at)
                    VALUES ('schema_version', '1.0', ?)
                ''', (datetime.now().isoformat(),))
                
                # Store initialization timestamp
                cursor.execute('''
                    INSERT OR IGNORE INTO database_info (key, value, updated_at)
                    VALUES ('initialized_at', ?, ?)
                ''', (datetime.now().isoformat(), datetime.now().isoformat()))
                
                conn.commit()
                return conn
        
        # Execute with retry logic
        connection = _execute_with_retry(_init_schema)
        logger.info(f"Database initialized successfully: {db_path}")
        return connection
        
    except Exception as e:
        logger.error(f"Failed to initialize database {db_path}: {e}")
        raise RuntimeError(f"Database initialization failed: {e}")

def db_integration(findings: Dict[str, Any], db_path: str = 'recon.db') -> None:
    """Store findings in database with validation and error handling"""
    if not findings:
        logger.warning("Empty findings provided, skipping database integration")
        return
    
    target = findings.get('target', 'unknown')
    
    try:
        # Validate target
        target = DatabaseValidator.validate_target(target)
        logger.info(f"Storing findings for target '{target}' in database {db_path}")
        
        pool = _get_connection_pool(db_path)
        
        def _store_findings():
            with pool.get_connection() as conn:
                cursor = conn.cursor()
                
                # Prepare batch data
                batch_data = []
                timestamp = datetime.now().isoformat()
                
                for module, data in findings.items():
                    if module == 'target':
                        continue
                    
                    try:
                        # Validate module and data
                        validated_module = DatabaseValidator.validate_module(module)
                        validated_data = DatabaseValidator.validate_json_data(data)
                        
                        # Create hash for deduplication
                        data_hash = hashlib.sha256(
                            f"{target}:{validated_module}:{validated_data}".encode('utf-8')
                        ).hexdigest()
                        
                        batch_data.append((
                            target, validated_module, timestamp, 
                            validated_data, data_hash, datetime.now().isoformat()
                        ))
                        
                    except ValueError as e:
                        logger.error(f"Validation failed for module '{module}': {e}")
                        continue
                
                if not batch_data:
                    logger.warning(f"No valid data to store for target '{target}'")
                    return
                
                # Batch insert with conflict resolution
                cursor.executemany('''
                    INSERT OR IGNORE INTO findings 
                    (target, module, timestamp, data, data_hash, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', batch_data)
                
                rows_affected = cursor.rowcount
                conn.commit()
                
                logger.info(f"Stored {rows_affected} new findings for target '{target}' "
                           f"({len(batch_data) - rows_affected} duplicates skipped)")
        
        # Execute with retry logic
        _execute_with_retry(_store_findings)
        
    except Exception as e:
        logger.error(f"Database integration failed for target '{target}': {e}")
        raise RuntimeError(f"Database integration failed: {e}")

def query_findings(db_path: str, target: Optional[str] = None, 
                  module: Optional[str] = None, limit: Optional[int] = None,
                  offset: int = 0, order_by: str = 'timestamp DESC') -> List[Dict]:
    """Query findings with advanced filtering and pagination"""
    try:
        pool = _get_connection_pool(db_path)
        
        def _query_data():
            with pool.get_connection() as conn:
                cursor = conn.cursor()
                
                # Build query with proper parameterization
                query_parts = ['SELECT target, module, timestamp, data, created_at FROM findings']
                params = []
                where_conditions = []
                
                if target:
                    validated_target = DatabaseValidator.validate_target(target)
                    where_conditions.append('target = ?')
                    params.append(validated_target)
                
                if module:
                    validated_module = DatabaseValidator.validate_module(module)
                    where_conditions.append('module = ?')
                    params.append(validated_module)
                
                if where_conditions:
                    query_parts.append('WHERE ' + ' AND '.join(where_conditions))
                
                # Validate and add ordering
                allowed_columns = ['timestamp', 'target', 'module', 'created_at']
                order_parts = order_by.split()
                if len(order_parts) >= 1 and order_parts[0] in allowed_columns:
                    direction = 'DESC' if len(order_parts) > 1 and order_parts[1].upper() == 'DESC' else 'ASC'
                    query_parts.append(f'ORDER BY {order_parts[0]} {direction}')
                else:
                    query_parts.append('ORDER BY timestamp DESC')
                
                # Add pagination
                if limit is not None and limit > 0:
                    query_parts.append('LIMIT ?')
                    params.append(min(limit, 10000))  # Cap at 10k results
                
                if offset > 0:
                    query_parts.append('OFFSET ?')
                    params.append(offset)
                
                final_query = ' '.join(query_parts)
                logger.debug(f"Executing query: {final_query} with params: {params}")
                
                cursor.execute(final_query, params)
                results = []
                
                for row in cursor.fetchall():
                    try:
                        result = {
                            'target': row[0],
                            'module': row[1], 
                            'timestamp': row[2],
                            'data': json.loads(row[3]),
                            'created_at': row[4]
                        }
                        results.append(result)
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse JSON data for finding {row[0]}/{row[1]}: {e}")
                        continue
                
                logger.debug(f"Retrieved {len(results)} findings from {db_path}")
                return results
        
        # Execute with retry logic
        return _execute_with_retry(_query_data)
        
    except Exception as e:
        logger.error(f"Query failed for database {db_path}: {e}")
        raise RuntimeError(f"Query failed: {e}")

def get_database_stats(db_path: str) -> Dict[str, Any]:
    """Get database statistics and health information"""
    try:
        pool = _get_connection_pool(db_path)
        
        def _get_stats():
            with pool.get_connection() as conn:
                cursor = conn.cursor()
                
                stats = {}
                
                # Basic counts
                cursor.execute('SELECT COUNT(*) FROM findings')
                stats['total_findings'] = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(DISTINCT target) FROM findings')
                stats['unique_targets'] = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(DISTINCT module) FROM findings')
                stats['unique_modules'] = cursor.fetchone()[0]
                
                # Recent activity
                cursor.execute('''
                    SELECT COUNT(*) FROM findings 
                    WHERE created_at > datetime('now', '-24 hours')
                ''')
                stats['findings_last_24h'] = cursor.fetchone()[0]
                
                # Database size
                cursor.execute('SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()')
                result = cursor.fetchone()
                stats['database_size_bytes'] = result[0] if result else 0
                
                # Get database info
                cursor.execute('SELECT key, value FROM database_info')
                db_info = dict(cursor.fetchall())
                stats['database_info'] = db_info
                
                return stats
        
        return _execute_with_retry(_get_stats)
        
    except Exception as e:
        logger.error(f"Failed to get database stats for {db_path}: {e}")
        return {'error': str(e)}

def cleanup_database_connections():
    """Cleanup all database connection pools"""
    global _connection_pools
    with _pools_lock:
        for pool in _connection_pools.values():
            try:
                pool.close_all()
            except Exception as e:
                logger.error(f"Error closing connection pool: {e}")
        _connection_pools.clear()
    logger.info("Database connection pools cleaned up")

# Register cleanup function for graceful shutdown
import atexit
atexit.register(cleanup_database_connections)
