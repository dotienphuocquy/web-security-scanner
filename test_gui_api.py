"""
Test GUI API directly
"""
import requests
import time
import json

API_BASE = "http://127.0.0.1:5000/api"

def test_scan():
    """Test scanning through API"""
    print("=" * 60)
    print("Testing GUI API")
    print("=" * 60)
    
    # Start scan
    print("\n[1] Starting scan...")
    response = requests.post(f"{API_BASE}/scan", json={
        'url': 'http://127.0.0.1:8080/login',
        'type': 'all'
    })
    
    if response.status_code != 200:
        print(f"ERROR: Failed to start scan: {response.text}")
        return
    
    data = response.json()
    scan_id = data['scan_id']
    print(f"✓ Scan started: {scan_id}")
    
    # Poll status
    print("\n[2] Polling scan status...")
    while True:
        response = requests.get(f"{API_BASE}/scan/{scan_id}/status")
        status = response.json()
        
        print(f"  Status: {status['status']} - {status['progress']}% - {status['message']}")
        
        if status['status'] in ['completed', 'error']:
            break
        
        time.sleep(1)
    
    # Get results
    print("\n[3] Getting results...")
    response = requests.get(f"{API_BASE}/scan/{scan_id}/results")
    
    if response.status_code != 200:
        print(f"ERROR: Failed to get results: {response.text}")
        return
    
    results = response.json()
    print(f"\n✓ Scan completed!")
    print(f"  Total vulnerabilities: {results['total_vulnerabilities']}")
    print(f"  High severity: {results['high_severity']}")
    print(f"  Medium severity: {results['medium_severity']}")
    
    if results['vulnerabilities']:
        print(f"\n[4] Vulnerabilities found:")
        for i, vuln in enumerate(results['vulnerabilities'], 1):
            print(f"  {i}. {vuln['type']} - {vuln['parameter']} ({vuln['severity']})")
    else:
        print("\n[!] No vulnerabilities found")
        if 'error' in results:
            print(f"  Error: {results['error']}")

if __name__ == '__main__':
    try:
        test_scan()
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
