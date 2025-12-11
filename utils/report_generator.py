"""
Report Generator Module
Generate security scan reports in HTML and JSON formats
"""

import os
import json
from datetime import datetime
from jinja2 import Template


class ReportGenerator:
    """Generate security scan reports"""
    
    def __init__(self, report_dir='reports'):
        self.report_dir = report_dir
        os.makedirs(report_dir, exist_ok=True)
    
    def generate(self, vulnerabilities, output_name='report'):
        """Generate both HTML and JSON reports"""
        # Generate HTML report
        html_path = self._generate_html(vulnerabilities, output_name)
        
        # Generate JSON report
        json_path = self._generate_json(vulnerabilities, output_name)
        
        return {
            'html': html_path,
            'json': json_path
        }
    
    def _generate_html(self, vulnerabilities, output_name):
        """Generate HTML report"""
        template = self._get_html_template()
        
        # Calculate statistics
        stats = self._calculate_stats(vulnerabilities)
        
        # Render template
        html_content = template.render(
            vulnerabilities=vulnerabilities,
            stats=stats,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total_vulns=len(vulnerabilities)
        )
        
        # Save to file
        output_path = os.path.join(self.report_dir, f"{output_name}.html")
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path
    
    def _generate_json(self, vulnerabilities, output_name):
        """Generate JSON report"""
        stats = self._calculate_stats(vulnerabilities)
        
        report_data = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'tool': 'Web Security Scanner',
                'version': '1.0'
            },
            'statistics': stats,
            'vulnerabilities': vulnerabilities
        }
        
        # Save to file
        output_path = os.path.join(self.report_dir, f"{output_name}.json")
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        return output_path
    
    def _calculate_stats(self, vulnerabilities):
        """Calculate vulnerability statistics"""
        stats = {
            'total': len(vulnerabilities),
            'high': 0,
            'medium': 0,
            'low': 0,
            'sqli': 0,
            'xss': 0,
            'by_type': {}
        }
        
        for vuln in vulnerabilities:
            # Count by severity
            severity = vuln.get('severity', 'Low').lower()
            if severity == 'high':
                stats['high'] += 1
            elif severity == 'medium':
                stats['medium'] += 1
            else:
                stats['low'] += 1
            
            # Count by category
            category = vuln.get('category', 'Unknown')
            if 'SQL' in category:
                stats['sqli'] += 1
            elif 'XSS' in category:
                stats['xss'] += 1
            
            # Count by type
            vuln_type = vuln.get('type', 'Unknown')
            stats['by_type'][vuln_type] = stats['by_type'].get(vuln_type, 0) + 1
        
        return stats
    
    def _get_html_template(self):
        """Get HTML report template"""
        template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Security Scan Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f7fa;
            padding: 20px;
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }

        .timestamp {
            margin-top: 15px;
            font-size: 0.9em;
            opacity: 0.8;
        }

        .content {
            padding: 40px;
        }

        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }

        .stat-box {
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            color: white;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        .stat-box.total {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }

        .stat-box.high {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }

        .stat-box.medium {
            background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%);
        }

        .stat-box.low {
            background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%);
        }

        .stat-number {
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
        }

        .stat-label {
            font-size: 1.1em;
            opacity: 0.9;
        }

        .section {
            margin-bottom: 40px;
        }

        .section h2 {
            color: #333;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 25px;
            font-size: 1.8em;
        }

        .vulnerability {
            background: #f8f9fa;
            border-left: 5px solid #667eea;
            padding: 25px;
            margin-bottom: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }

        .vulnerability.high {
            border-left-color: #f5576c;
        }

        .vulnerability.medium {
            border-left-color: #fcb69f;
        }

        .vulnerability.low {
            border-left-color: #95e1d3;
        }

        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }

        .vuln-title {
            font-size: 1.4em;
            color: #333;
            font-weight: 600;
        }

        .severity-badge {
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.9em;
            text-transform: uppercase;
        }

        .severity-badge.high {
            background: #f5576c;
            color: white;
        }

        .severity-badge.medium {
            background: #fcb69f;
            color: white;
        }

        .severity-badge.low {
            background: #95e1d3;
            color: white;
        }

        .vuln-detail {
            margin-bottom: 15px;
        }

        .vuln-detail-label {
            font-weight: 600;
            color: #555;
            display: inline-block;
            min-width: 120px;
        }

        .vuln-detail-value {
            color: #333;
        }

        .payload-box {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin: 10px 0;
        }

        .recommendation-box {
            background: #e8f5e9;
            border-left: 4px solid #4caf50;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
        }

        .recommendation-box strong {
            color: #2e7d32;
        }

        .no-vulnerabilities {
            text-align: center;
            padding: 60px 20px;
            background: #e8f5e9;
            border-radius: 10px;
            color: #2e7d32;
        }

        .no-vulnerabilities h3 {
            font-size: 2em;
            margin-bottom: 15px;
        }

        .footer {
            background: #f8f9fa;
            padding: 30px;
            text-align: center;
            color: #666;
            border-top: 1px solid #e0e0e0;
        }

        .category-badge {
            display: inline-block;
            padding: 4px 12px;
            background: #667eea;
            color: white;
            border-radius: 12px;
            font-size: 0.85em;
            margin-left: 10px;
        }

        @media print {
            body {
                background: white;
            }
            .container {
                box-shadow: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Web Security Scan Report</h1>
            <div class="subtitle">SQL Injection & XSS Detection</div>
            <div class="timestamp">📅 Generated: {{ timestamp }}</div>
        </div>

        <div class="content">
            <!-- Summary Statistics -->
            <div class="section">
                <h2>📊 Summary</h2>
                <div class="summary">
                    <div class="stat-box total">
                        <div class="stat-number">{{ stats.total }}</div>
                        <div class="stat-label">Total Vulnerabilities</div>
                    </div>
                    <div class="stat-box high">
                        <div class="stat-number">{{ stats.high }}</div>
                        <div class="stat-label">High Severity</div>
                    </div>
                    <div class="stat-box medium">
                        <div class="stat-number">{{ stats.medium }}</div>
                        <div class="stat-label">Medium Severity</div>
                    </div>
                    <div class="stat-box low">
                        <div class="stat-number">{{ stats.low }}</div>
                        <div class="stat-label">Low Severity</div>
                    </div>
                </div>
            </div>

            <!-- Vulnerabilities List -->
            <div class="section">
                <h2>🔍 Detected Vulnerabilities</h2>
                
                {% if vulnerabilities %}
                    {% for vuln in vulnerabilities %}
                    <div class="vulnerability {{ vuln.severity|lower }}">
                        <div class="vuln-header">
                            <div class="vuln-title">
                                {{ loop.index }}. {{ vuln.type }}
                                <span class="category-badge">{{ vuln.category }}</span>
                            </div>
                            <span class="severity-badge {{ vuln.severity|lower }}">{{ vuln.severity }}</span>
                        </div>

                        <div class="vuln-detail">
                            <span class="vuln-detail-label">🌐 URL:</span>
                            <span class="vuln-detail-value">{{ vuln.url }}</span>
                        </div>

                        <div class="vuln-detail">
                            <span class="vuln-detail-label">📌 Parameter:</span>
                            <span class="vuln-detail-value">{{ vuln.parameter }}</span>
                        </div>

                        <div class="vuln-detail">
                            <span class="vuln-detail-label">🔧 Method:</span>
                            <span class="vuln-detail-value">{{ vuln.method }}</span>
                        </div>

                        <div class="vuln-detail">
                            <span class="vuln-detail-label">🔎 Evidence:</span>
                            <span class="vuln-detail-value">{{ vuln.evidence }}</span>
                        </div>

                        <div class="vuln-detail">
                            <span class="vuln-detail-label">💉 Payload:</span>
                            <div class="payload-box">{{ vuln.payload }}</div>
                        </div>

                        <div class="recommendation-box">
                            <strong>💡 Recommendation:</strong><br>
                            {{ vuln.recommendation }}
                        </div>
                    </div>
                    {% endfor %}
                {% else %}
                    <div class="no-vulnerabilities">
                        <h3>✅ All Clear!</h3>
                        <p>No vulnerabilities were detected in this scan.</p>
                        <p>The tested application appears to be secure against SQL Injection and XSS attacks.</p>
                    </div>
                {% endif %}
            </div>
        </div>

        <div class="footer">
            <p><strong>Web Security Scanner v1.0</strong></p>
            <p>SQL Injection & XSS Detection Tool</p>
            <p style="margin-top: 10px; font-size: 0.9em;">
                ⚠️ This report is for authorized security testing purposes only.
            </p>
        </div>
    </div>
</body>
</html>
        """
        
        return Template(template_str)


# Convenience function
def generate_report(vulnerabilities, output_name='report', report_dir='reports'):
    """Generate report - convenience function"""
    generator = ReportGenerator(report_dir)
    return generator.generate(vulnerabilities, output_name)
