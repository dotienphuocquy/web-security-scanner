"""
Flask Web GUI for Web Security Scanner
"""

from flask import Flask, render_template, request, jsonify, send_file
import os
import json
import threading
from datetime import datetime

from scanners.sql_injection import SQLInjectionScanner
from scanners.xss_scanner import XSSScanner
from utils.report_generator import ReportGenerator

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Store scan results in memory (for demo purposes)
scan_results = {}
scan_status = {}


@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new scan"""
    data = request.get_json()
    url = data.get('url')
    scan_type = data.get('type', 'all')
    enable_extraction = data.get('enable_extraction', False)
    enable_context_detection = data.get('enable_context_detection', False)
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Generate scan ID
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Initialize scan status
    scan_status[scan_id] = {
        'status': 'running',
        'progress': 0,
        'message': 'Initializing scan...'
    }
    
    # Start scan in background thread
    thread = threading.Thread(target=run_scan, args=(scan_id, url, scan_type, enable_extraction, enable_context_detection))
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'scan_id': scan_id,
        'message': 'Scan started successfully',
        'extraction_enabled': enable_extraction,
        'context_detection_enabled': enable_context_detection
    })


@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """Get scan status"""
    if scan_id not in scan_status:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan_status[scan_id])


@app.route('/api/scan/<scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
    """Get scan results"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Results not found'}), 404
    
    return jsonify(scan_results[scan_id])


@app.route('/api/scan/<scan_id>/report', methods=['GET'])
def download_report(scan_id):
    """Download scan report"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Results not found'}), 404
    
    # Get absolute path for reports directory
    app_dir = os.path.dirname(os.path.abspath(__file__))
    reports_dir = os.path.join(app_dir, 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    
    print(f"[Flask] App directory: {app_dir}")
    print(f"[Flask] Reports directory: {reports_dir}")
    print(f"[Flask] Scan ID: {scan_id}")
    
    # Generate report with absolute path
    report_gen = ReportGenerator(report_dir=reports_dir)
    
    try:
        vulnerabilities = scan_results[scan_id]['vulnerabilities']
        print(f"[Flask] Generating report for {len(vulnerabilities)} vulnerabilities")
        
        report_files = report_gen.generate(vulnerabilities, f"{scan_id}_report")
        
        print(f"[Flask] Report files generated:")
        print(f"  - HTML: {report_files['html']}")
        print(f"  - JSON: {report_files['json']}")
        
        # Verify file exists
        html_path = report_files['html']
        if not os.path.exists(html_path):
            print(f"[Flask] ERROR: Report file not found: {html_path}")
            # List files in reports directory
            if os.path.exists(reports_dir):
                files = os.listdir(reports_dir)
                print(f"[Flask] Files in reports directory: {files}")
            return jsonify({'error': 'Report generation failed'}), 500
        
        file_size = os.path.getsize(html_path)
        print(f"[Flask] File exists, size: {file_size} bytes")
        print(f"[Flask] Sending file: {html_path}")
        
        return send_file(html_path, as_attachment=True, download_name=f"{scan_id}_report.html")
    
    except Exception as e:
        print(f"[ERROR] Report generation failed: {str(e)}")
        return jsonify({'error': f'Report generation failed: {str(e)}'}), 500


def run_scan(scan_id, url, scan_type, enable_extraction=False, enable_context_detection=False):
    """Run scan in background"""
    try:
        results = []
        print(f"\n{'='*60}")
        print(f"[SCAN] Starting {scan_type.upper()} scan for {url}")
        print(f"{'='*60}\n")
        
        # SQL Injection scan
        if scan_type in ['sqli', 'all']:
            scan_status[scan_id].update({
                'status': 'running',
                'progress': 25,
                'message': 'Running SQL Injection scan...' + (' (with data extraction)' if enable_extraction else '')
            })
            
            sqli_scanner = SQLInjectionScanner(url, enable_extraction=enable_extraction)
            sqli_results = sqli_scanner.scan()
            results.extend(sqli_results)
        
        # XSS scan
        if scan_type in ['xss', 'all']:
            scan_status[scan_id].update({
                'status': 'running',
                'progress': 60,
                'message': 'Running XSS scan...' + (' (with context detection)' if enable_context_detection else '')
            })
            
            xss_scanner = XSSScanner(url, enable_context_detection=enable_context_detection)
            xss_results = xss_scanner.scan()
            results.extend(xss_results)
        
        # Check for extracted data (SQL Injection)
        extracted_data_list = [v.get('extracted_data') for v in results if 'extracted_data' in v]
        
        # Check for context analysis (XSS)
        context_analysis_list = [v.get('context') for v in results if 'context' in v]
        
        # Store results
        scan_results[scan_id] = {
            'url': url,
            'scan_type': scan_type,
            'extraction_enabled': enable_extraction,
            'context_detection_enabled': enable_context_detection,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': results,
            'total_vulnerabilities': len(results),
            'high_severity': len([v for v in results if v.get('severity') == 'High']),
            'medium_severity': len([v for v in results if v.get('severity') == 'Medium']),
            'low_severity': len([v for v in results if v.get('severity') == 'Low']),
            'critical_severity': len([v for v in results if v.get('severity') == 'Critical']),
            'extracted_data': extracted_data_list if extracted_data_list else None,
            'context_analysis': context_analysis_list if context_analysis_list else None
        }
        
        # Update status
        scan_status[scan_id].update({
            'status': 'completed',
            'progress': 100,
            'message': f'Scan completed. Found {len(results)} vulnerability(ies).'
        })
        
        print(f"\n{'='*60}")
        print(f"[COMPLETE] Scan finished: {len(results)} vulnerability(ies) found")
        print(f"{'='*60}\n")
        
    except Exception as e:
        print(f"\n[ERROR] Scan failed: {str(e)}")
        
        scan_status[scan_id].update({
            'status': 'error',
            'progress': 0,
            'message': f'Error: {str(e)}'
        })
        
        # Store empty results so the frontend doesn't crash
        scan_results[scan_id] = {
            'url': url,
            'scan_type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'total_vulnerabilities': 0,
            'high_severity': 0,
            'medium_severity': 0,
            'low_severity': 0,
            'error': str(e)
        }


def start_gui():
    """Start Flask web server"""
    print("Starting Web GUI on http://127.0.0.1:5000")
    print("Press Ctrl+C to stop")
    app.run(debug=False, host='0.0.0.0', port=5000)


if __name__ == '__main__':
    start_gui()
