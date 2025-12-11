"""
Start both vulnerable app and GUI in separate processes
"""
import subprocess
import time
import sys
import os

def main():
    print("=" * 60)
    print("Starting Web Security Scanner Demo Environment")
    print("=" * 60)
    
    # Change to project directory
    os.chdir(r"d:\vscode\ky7\kiem-thu-xam-nhap")
    
    try:
        # Start vulnerable app
        print("\n[1] Starting vulnerable app on port 8080...")
        vuln_process = subprocess.Popen(
            [sys.executable, "-c", "from vulnerable_app.app import start_vulnerable_app; start_vulnerable_app()"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        time.sleep(3)
        print("✓ Vulnerable app started")
        
        # Start GUI
        print("\n[2] Starting GUI on port 5000...")
        gui_process = subprocess.Popen(
            [sys.executable, "main.py", "--gui"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        time.sleep(3)
        print("✓ GUI started")
        
        print("\n" + "=" * 60)
        print("✓ All services started successfully!")
        print("=" * 60)
        print("\n📌 Access points:")
        print("  • Vulnerable App: http://127.0.0.1:8080")
        print("  • Scanner GUI:    http://127.0.0.1:5000")
        print("\n💡 Test scanning:")
        print("  1. Open http://127.0.0.1:5000 in browser")
        print("  2. Enter URL: http://127.0.0.1:8080/login")
        print("  3. Click 'Start Scan'")
        print("\nPress Ctrl+C to stop all services...")
        
        # Keep processes running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n\n🛑 Stopping services...")
        if 'vuln_process' in locals():
            vuln_process.terminate()
        if 'gui_process' in locals():
            gui_process.terminate()
        print("✓ All services stopped")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
