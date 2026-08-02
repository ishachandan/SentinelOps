"""Test utilities and mock helpers"""
from unittest.mock import Mock


def mock_abuseipdb_response(abuse_score, total_reports=100, country="US"):
    """Create a mock AbuseIPDB API response"""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "abuseConfidenceScore": abuse_score,
            "totalReports": total_reports,
            "countryCode": country
        }
    }
    return mock_response


def mock_abuseipdb_malicious():
    """Mock response for a malicious IP (100% confidence)"""
    return mock_abuseipdb_response(100, 172, "DE")


def mock_abuseipdb_clean():
    """Mock response for a clean IP (0% confidence)"""
    return mock_abuseipdb_response(0, 190, "AU")
