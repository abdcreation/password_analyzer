from typing import List, Dict, Any

def aggregate_metrics(logs: List[str]) -> Dict[str, Dict[str, Any]]:
    service_stats = {}

    for line in logs:
        parts = line.split('|')
        if len(parts) != 4:
            continue
        
        timestamp_str, service_name_raw, status_code_str, response_time_str = [p.strip() for p in parts]
        
        try:
            status_code = int(status_code_str)
            response_time = int(response_time_str)
        except ValueError:
            continue
            
        service_name = service_name_raw.lower()
        
        # Outlier Filtering: ignore response time > 5000ms unless status code is 5xx
        if response_time > 5000:
            if not (500 <= status_code <= 599):
                continue
                
        if service_name not in service_stats:
            service_stats[service_name] = {
                'total_requests': 0,
                'errors': 0,
                'max_latency': -1
            }
            
        stats = service_stats[service_name]
        stats['total_requests'] += 1
        
        if 400 <= status_code <= 599:
            stats['errors'] += 1
            
        if response_time > stats['max_latency']:
            stats['max_latency'] = response_time
            
    # Format the output
    result = {}
    for service_name, stats in service_stats.items():
        total_requests = stats['total_requests']
        error_rate = 0.0
        if total_requests > 0:
            error_rate = round((stats['errors'] / total_requests) * 100, 2)
            
        result[service_name] = {
            "total_requests": total_requests,
            "error_rate": error_rate,
            "max_latency": stats['max_latency']
        }
        
    return result

if __name__ == "__main__":
    raw_logs = [
        "1717113600 | Auth-Service | 200 | 120",
        "1717113605 | auth-service | 500 | 6000",
        "1717113610 | Payment-Gate | 200 | 150",
        "1717113615 | Auth-Service | 200 | 5500",
        "INVALID_LOG_LINE_MISSING_PIPES",
        "1717113620 | Payment-Gate | 404 | 90",
        "1717113625 | payment-gate | 200 | ERROR_TIME"
    ]
    
    import json
    print(json.dumps(aggregate_metrics(raw_logs), indent=2))
