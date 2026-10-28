import time
from collections import defaultdict
from functools import wraps
from flask import request, jsonify

class MemoryRateLimiter:
    def __init__(self):
        self.records = defaultdict(list)

    def is_allowed(self, key: str, max_requests: int = 15, window_seconds: int = 60) -> bool:
        now = time.time()
        timestamps = self.records[key]
        valid_timestamps = [ts for ts in timestamps if now - ts < window_seconds]
        self.records[key] = valid_timestamps
        
        if len(valid_timestamps) >= max_requests:
            return False
            
        self.records[key].append(now)
        return True

limiter = MemoryRateLimiter()

def rate_limit(max_requests: int = 20, window_seconds: int = 60):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import current_app
            if current_app and current_app.config.get("TESTING"):
                return f(*args, **kwargs)
                
            client_ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "127.0.0.1"
            endpoint = request.endpoint or "unknown"
            key = f"{client_ip}:{endpoint}"
            
            if not limiter.is_allowed(key, max_requests=max_requests, window_seconds=window_seconds):
                return jsonify({
                    "error": "SECURITY RATE LIMIT EXCEEDED. REQUEST THROTTLED.",
                    "code": "RATE_LIMIT_EXCEEDED"
                }), 429
            return f(*args, **kwargs)
        return decorated_function
    return decorator
