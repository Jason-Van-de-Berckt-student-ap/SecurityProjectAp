"""
Background task processing for long-running scans.
"""
import threading
import queue
import time
import logging
from typing import Dict, Any, Callable, Optional, List
from enum import Enum
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import wraps

logger = logging.getLogger(__name__)

class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class Task:
    id: str
    name: str
    func: Callable
    args: tuple
    kwargs: dict
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = None
    started_at: datetime = None
    completed_at: datetime = None
    result: Any = None
    error: str = None
    progress: float = 0.0

class BackgroundTaskManager:
    """Simple background task manager using threading"""
    
    def __init__(self, max_workers: int = 3):
        self.max_workers = max_workers
        self.task_queue = queue.Queue()
        self.tasks = {}
        self.workers = []
        self.shutdown_event = threading.Event()
        self.lock = threading.Lock()
        
        # Start worker threads
        self._start_workers()
    
    def _start_workers(self):
        """Start worker threads"""
        for i in range(self.max_workers):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f"TaskWorker-{i}",
                daemon=True
            )
            worker.start()
            self.workers.append(worker)
        
        logger.info(f"Started {self.max_workers} background task workers")
    
    def _worker_loop(self):
        """Main worker loop"""
        while not self.shutdown_event.is_set():
            try:
                # Get task from queue with timeout
                task = self.task_queue.get(timeout=1)
                
                if task is None:  # Shutdown signal
                    break
                
                self._execute_task(task)
                self.task_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker error: {e}")
    
    def _execute_task(self, task: Task):
        """Execute a single task"""
        with self.lock:
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.now()
        
        logger.info(f"Starting task {task.id}: {task.name}")
        
        try:
            # Execute the task function
            result = task.func(*task.args, **task.kwargs)
            
            with self.lock:
                task.status = TaskStatus.COMPLETED
                task.completed_at = datetime.now()
                task.result = result
                task.progress = 100.0
            
            logger.info(f"Completed task {task.id}: {task.name}")
            
        except Exception as e:
            with self.lock:
                task.status = TaskStatus.FAILED
                task.completed_at = datetime.now()
                task.error = str(e)
            
            logger.error(f"Failed task {task.id}: {task.name} - {e}")
    
    def submit_task(self, name: str, func: Callable, *args, **kwargs) -> str:
        """Submit a task for background execution"""
        task_id = str(uuid.uuid4())
        
        task = Task(
            id=task_id,
            name=name,
            func=func,
            args=args,
            kwargs=kwargs,
            created_at=datetime.now()
        )
        
        with self.lock:
            self.tasks[task_id] = task
        
        self.task_queue.put(task)
        
        logger.info(f"Submitted task {task_id}: {name}")
        return task_id
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task status and result"""
        with self.lock:
            task = self.tasks.get(task_id)
            
            if not task:
                return None
            
            return {
                'id': task.id,
                'name': task.name,
                'status': task.status.value,
                'created_at': task.created_at.isoformat() if task.created_at else None,
                'started_at': task.started_at.isoformat() if task.started_at else None,
                'completed_at': task.completed_at.isoformat() if task.completed_at else None,
                'progress': task.progress,
                'result': task.result if task.status == TaskStatus.COMPLETED else None,
                'error': task.error if task.status == TaskStatus.FAILED else None
            }
    
    def cancel_task(self, task_id: str) -> bool:
        """Cancel a pending task"""
        with self.lock:
            task = self.tasks.get(task_id)
            
            if not task:
                return False
            
            if task.status == TaskStatus.PENDING:
                task.status = TaskStatus.CANCELLED
                return True
            
            return False
    
    def get_all_tasks(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all tasks with their status"""
        with self.lock:
            tasks = list(self.tasks.values())
            
            # Sort by creation time, newest first
            tasks.sort(key=lambda t: t.created_at or datetime.min, reverse=True)
            
            return [
                {
                    'id': task.id,
                    'name': task.name,
                    'status': task.status.value,
                    'created_at': task.created_at.isoformat() if task.created_at else None,
                    'started_at': task.started_at.isoformat() if task.started_at else None,
                    'completed_at': task.completed_at.isoformat() if task.completed_at else None,
                    'progress': task.progress
                }
                for task in tasks[:limit]
            ]
    
    def cleanup_old_tasks(self, max_age_hours: int = 24):
        """Clean up old completed/failed tasks"""
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        
        with self.lock:
            tasks_to_remove = []
            
            for task_id, task in self.tasks.items():
                if (task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED] and
                    task.completed_at and task.completed_at < cutoff_time):
                    tasks_to_remove.append(task_id)
            
            for task_id in tasks_to_remove:
                del self.tasks[task_id]
            
            if tasks_to_remove:
                logger.info(f"Cleaned up {len(tasks_to_remove)} old tasks")
    
    def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue and worker statistics"""
        with self.lock:
            task_counts = {}
            for task in self.tasks.values():
                status = task.status.value
                task_counts[status] = task_counts.get(status, 0) + 1
        
        return {
            'queue_size': self.task_queue.qsize(),
            'active_workers': len([w for w in self.workers if w.is_alive()]),
            'total_workers': len(self.workers),
            'total_tasks': len(self.tasks),
            'task_counts': task_counts
        }
    
    def shutdown(self, timeout: int = 30):
        """Shutdown the task manager"""
        logger.info("Shutting down background task manager")
        
        # Signal shutdown
        self.shutdown_event.set()
        
        # Add shutdown signals to queue
        for _ in self.workers:
            self.task_queue.put(None)
        
        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=timeout)
        
        logger.info("Background task manager shutdown complete")


# Global task manager instance
task_manager = None

def get_task_manager() -> BackgroundTaskManager:
    """Get or create the global task manager"""
    global task_manager
    if task_manager is None:
        task_manager = BackgroundTaskManager()
    return task_manager

def submit_background_task(name: str, func: Callable, *args, **kwargs) -> str:
    """Submit a task for background execution"""
    return get_task_manager().submit_task(name, func, *args, **kwargs)

def get_task_status(task_id: str) -> Optional[Dict[str, Any]]:
    """Get task status"""
    return get_task_manager().get_task_status(task_id)

def background_task(name: str = None):
    """Decorator to make a function a background task"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            task_name = name or f"{func.__module__}.{func.__name__}"
            return submit_background_task(task_name, func, *args, **kwargs)
        
        # Add a sync version
        wrapper.sync = func
        return wrapper
    
    return decorator

# Background scan functions
@background_task("Batch Domain Scan")
def background_batch_scan(domains: List[str], scan_options: Dict[str, bool], brave_api_key: str = None):
    """Background batch scan for large domain lists"""
    from services.optimized_scanner import optimized_scanner
    return optimized_scanner.scan_domains_batch_parallel(domains, scan_options, brave_api_key)

@background_task("Single Domain Deep Scan")
def background_deep_scan(domain: str, scan_options: Dict[str, bool], brave_api_key: str = None):
    """Background deep scan for comprehensive analysis"""
    from services.optimized_scanner import optimized_scanner
    return optimized_scanner.scan_domain_parallel(domain, scan_options, brave_api_key)
