from datetime import datetime

def build_event(user, ip):
    return {
        "user_id": user,
        "role": "employee",
        "department": "it",
        "privilege_level": 1,
        "auth_type": "ssh",
        "login_result": "failed",
        "failed_attempts_before_success": 1,
        "timestamp": datetime.now().isoformat(),
        "hour_of_day": datetime.now().hour,
        "day_of_week": datetime.now().weekday(),
        "country": "Unknown",
        "is_vpn": 0,
        "device_type": "unknown",
        "resource_name": "SSH",
        "resource_type": "server",
        "resource_sensitivity": 4,
        "access_action": "login",
        "access_result": "failed",
        "is_anomaly": 1
    }
