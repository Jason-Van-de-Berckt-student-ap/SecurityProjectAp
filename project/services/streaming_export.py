"""
Streaming CSV export for large scan result datasets.
"""
import csv
import io
import json
import logging
from typing import Dict, Any, List, Generator, Optional
from flask import Response
import time

logger = logging.getLogger(__name__)

class StreamingCSVExporter:
    """Streaming CSV exporter for large datasets"""
    
    def __init__(self):
        self.headers_written = False
    
    def _flatten_json_field(self, data: Any, prefix: str = '') -> Dict[str, Any]:
        """Flatten JSON data into flat key-value pairs"""
        result = {}
        
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except (json.JSONDecodeError, TypeError):
                # If it's not JSON, treat as string
                return {prefix: str(data)}
        
        if isinstance(data, dict):
            for key, value in data.items():
                new_key = f"{prefix}_{key}" if prefix else key
                if isinstance(value, (dict, list)):
                    result.update(self._flatten_json_field(value, new_key))
                else:
                    result[new_key] = str(value) if value is not None else ''
        elif isinstance(data, list):
            if data:
                for i, item in enumerate(data):
                    new_key = f"{prefix}_{i}" if prefix else str(i)
                    if isinstance(item, (dict, list)):
                        result.update(self._flatten_json_field(item, new_key))
                    else:
                        result[new_key] = str(item) if item is not None else ''
            else:
                result[prefix] = ''
        else:
            result[prefix] = str(data) if data is not None else ''
        
        return result
    
    def _process_scan_result(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single scan result row for CSV export"""
        processed = {
            'id': row.get('id', ''),
            'domain': row.get('domain', ''),
            'scan_type': row.get('scan_type', ''),
            'timestamp': row.get('timestamp', ''),
            'created_at': row.get('created_at', '')
        }
        
        # Flatten complex JSON fields
        for field in ['dns_records', 'ssl_info', 'vulnerabilities', 'subdomains', 
                     'related_domains', 'darkweb_mentions']:
            if field in row and row[field]:
                flattened = self._flatten_json_field(row[field], field)
                processed.update(flattened)
        
        return processed
    
    def generate_csv_stream(self, data_generator: Generator[Dict[str, Any], None, None]) -> Generator[str, None, None]:
        """Generate CSV data as a stream"""
        output = io.StringIO()
        writer = None
        headers_written = False
        
        for row in data_generator:
            processed_row = self._process_scan_result(row)
            
            # Write headers on first row
            if not headers_written:
                output.seek(0)
                output.truncate(0)
                
                writer = csv.DictWriter(output, fieldnames=processed_row.keys())
                writer.writeheader()
                
                # Yield header
                output.seek(0)
                yield output.read()
                headers_written = True
            
            # Write data row
            output.seek(0)
            output.truncate(0)
            
            if writer:
                writer.writerow(processed_row)
                output.seek(0)
                yield output.read()
    
    def create_streaming_response(self, data_generator: Generator[Dict[str, Any], None, None], 
                                filename: str = None) -> Response:
        """Create a streaming Flask response for CSV export"""
        if filename is None:
            filename = f"scan_results_{int(time.time())}.csv"
        
        def generate():
            try:
                for chunk in self.generate_csv_stream(data_generator):
                    yield chunk
            except Exception as e:
                logger.error(f"Error during CSV streaming: {e}")
                yield f"\n# Error: {str(e)}\n"
        
        response = Response(
            generate(),
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Cache-Control': 'no-cache'
            }
        )
        
        return response


class DatabaseStreamingExporter:
    """Streaming exporter that reads from database in chunks"""
    
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.exporter = StreamingCSVExporter()
    
    def _get_data_generator(self, filters: Dict[str, Any] = None, chunk_size: int = 1000) -> Generator[Dict[str, Any], None, None]:
        """Generate data from database in chunks"""
        try:
            with self.db_manager.pool.get_connection() as conn:
                cursor = conn.cursor()
                
                # Build query with filters
                base_query = "SELECT * FROM scan_results"
                conditions = []
                params = []
                
                if filters:
                    if filters.get('domain'):
                        conditions.append("domain LIKE ?")
                        params.append(f"%{filters['domain']}%")
                    
                    if filters.get('scan_type'):
                        conditions.append("scan_type = ?")
                        params.append(filters['scan_type'])
                    
                    if filters.get('start_date'):
                        conditions.append("timestamp >= ?")
                        params.append(filters['start_date'])
                    
                    if filters.get('end_date'):
                        conditions.append("timestamp <= ?")
                        params.append(filters['end_date'])
                
                query = base_query
                if conditions:
                    query += " WHERE " + " AND ".join(conditions)
                
                query += " ORDER BY timestamp DESC"
                
                # Execute query and fetch in chunks
                cursor.execute(query, params)
                
                while True:
                    rows = cursor.fetchmany(chunk_size)
                    if not rows:
                        break
                    
                    for row in rows:
                        yield dict(row)
                        
        except Exception as e:
            logger.error(f"Database streaming error: {e}")
            raise
    
    def export_scan_results(self, filters: Dict[str, Any] = None, filename: str = None) -> Response:
        """Export scan results as streaming CSV"""
        data_generator = self._get_data_generator(filters)
        return self.exporter.create_streaming_response(data_generator, filename)
    
    def get_export_summary(self, filters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Get summary of data that would be exported"""
        try:
            with self.db_manager.pool.get_connection() as conn:
                cursor = conn.cursor()
                
                # Build count query
                base_query = "SELECT COUNT(*) as total, MIN(timestamp) as earliest, MAX(timestamp) as latest FROM scan_results"
                conditions = []
                params = []
                
                if filters:
                    if filters.get('domain'):
                        conditions.append("domain LIKE ?")
                        params.append(f"%{filters['domain']}%")
                    
                    if filters.get('scan_type'):
                        conditions.append("scan_type = ?")
                        params.append(filters['scan_type'])
                    
                    if filters.get('start_date'):
                        conditions.append("timestamp >= ?")
                        params.append(filters['start_date'])
                    
                    if filters.get('end_date'):
                        conditions.append("timestamp <= ?")
                        params.append(filters['end_date'])
                
                query = base_query
                if conditions:
                    query += " WHERE " + " AND ".join(conditions)
                
                cursor.execute(query, params)
                result = cursor.fetchone()
                
                return {
                    'total_records': result['total'],
                    'earliest_scan': result['earliest'],
                    'latest_scan': result['latest'],
                    'estimated_size_mb': (result['total'] * 2) // 1024  # Rough estimate
                }
                
        except Exception as e:
            logger.error(f"Export summary error: {e}")
            return {'error': str(e)}


# Global exporter instances
streaming_exporter = None
db_streaming_exporter = None

def get_streaming_exporter() -> StreamingCSVExporter:
    """Get or create the global streaming exporter"""
    global streaming_exporter
    if streaming_exporter is None:
        streaming_exporter = StreamingCSVExporter()
    return streaming_exporter

def get_db_streaming_exporter() -> DatabaseStreamingExporter:
    """Get or create the database streaming exporter"""
    global db_streaming_exporter
    if db_streaming_exporter is None:
        from services.database_manager import get_db_manager
        db_streaming_exporter = DatabaseStreamingExporter(get_db_manager())
    return db_streaming_exporter
