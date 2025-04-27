import json
from datetime import datetime

def format_response(data, status_code=200):
    return {
        'status': 'success' if status_code < 400 else 'error',
        'data': data,
        'timestamp': datetime.utcnow().isoformat()
    }

def parse_json(data):
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return None 