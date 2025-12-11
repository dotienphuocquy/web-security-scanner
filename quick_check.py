"""
Quick verification script
"""
import requests

print("=" * 60)
print("Quick System Check")
print("=" * 60)

# Check vulnerable app
print("\n[1] Checking vulnerable app (port 8080)...")
try:
    response = requests.get("http://127.0.0.1:8080/", timeout=3)
    if response.status_code == 200:
        print("    ✅ Vulnerable app is RUNNING")
    else:
        print(f"    ⚠️  Vulnerable app responded with status {response.status_code}")
except Exception as e:
    print(f"    ❌ Vulnerable app is NOT running")
    print(f"       Error: {e}")
    print("\n    👉 Start it with:")
    print('       python -c "from vulnerable_app.app import start_vulnerable_app; start_vulnerable_app()"')

# Check GUI
print("\n[2] Checking GUI (port 5000)...")
try:
    response = requests.get("http://127.0.0.1:5000/", timeout=3)
    if response.status_code == 200:
        print("    ✅ GUI is RUNNING")
    else:
        print(f"    ⚠️  GUI responded with status {response.status_code}")
except Exception as e:
    print(f"    ❌ GUI is NOT running")
    print(f"       Error: {e}")
    print("\n    👉 Start it with:")
    print("       python main.py --gui")

# Test scanner directly
print("\n[3] Testing scanner directly...")
try:
    from scanners.sql_injection import SQLInjectionScanner
    scanner = SQLInjectionScanner("http://127.0.0.1:8080/login")
    print("    ✅ Scanner module imports OK")
except Exception as e:
    print(f"    ❌ Scanner module error: {e}")

print("\n" + "=" * 60)
print("Check complete!")
print("=" * 60)
