# scripts/report_generator.py
from jinja2 import Template
import pdfkit
from datetime import datetime

def generate_html_report(scan_data, template_file="templates/report.html"):
    with open(template_file) as f:
        template = Template(f.read())
    
    html = template.render(
        target=scan_data['target'],
        date=datetime.now().strftime("%Y-%m-%d"),
        vulnerabilities=scan_data['findings'],
        scan_duration=scan_data['stats']['duration']
    )
    
    report_path = f"scans/reports/{scan_data['target']}_{datetime.now().strftime('%Y%m%d_%H%M')}.html"
    with open(report_path, 'w') as f:
        f.write(html)
    
    # Convert to PDF
    pdfkit.from_file(report_path, report_path.replace('.html','.pdf'))
    return report_path
