import json
import csv
import io
from datetime import datetime
from jinja2 import Environment, BaseLoader
import logging

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self):
        self.jinja_env = Environment(loader=BaseLoader())
    
    def generate_html_report(self, scan_data, results):
        """Generate HTML compliance report"""
        template_str = """
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIS Compliance Report - {{ scan_data.scan_name }}</title>
    <link href="https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css" rel="stylesheet">
    <style>
        .status-pass { color: #28a745; }
        .status-fail { color: #dc3545; }
        .status-skip { color: #ffc107; }
        .status-error { color: #fd7e14; }
        .compliance-score {
            font-size: 2rem;
            font-weight: bold;
        }
        .category-section {
            margin-bottom: 2rem;
        }
        @media print {
            .no-print { display: none; }
        }
        .summary-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .result-row:hover {
            background-color: rgba(255, 255, 255, 0.05);
        }
    </style>
</head>
<body>
    <div class="container mt-4">
        <div class="row">
            <div class="col-12">
                <div class="text-center mb-4">
                    <h1 class="display-4">CIS Palo Alto Firewall Compliance Report</h1>
                    <p class="lead text-muted">Automated Security Compliance Assessment</p>
                </div>
                
                <div class="card summary-card mb-4">
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <h5 class="card-title">
                                    <i class="fas fa-info-circle me-2"></i>Scan Information
                                </h5>
                                <div class="row">
                                    <div class="col-6">
                                        <p><strong>Firewall:</strong></p>
                                        <p><strong>Hostname:</strong></p>
                                        <p><strong>Scan Name:</strong></p>
                                        <p><strong>Started:</strong></p>
                                        <p><strong>Completed:</strong></p>
                                    </div>
                                    <div class="col-6">
                                        <p>{{ scan_data.firewall.name }}</p>
                                        <p>{{ scan_data.firewall.hostname }}</p>
                                        <p>{{ scan_data.scan_name }}</p>
                                        <p>{{ scan_data.started_at.strftime('%Y-%m-%d %H:%M:%S UTC') if scan_data.started_at else 'N/A' }}</p>
                                        <p>{{ scan_data.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC') if scan_data.completed_at else 'In Progress' }}</p>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="text-center">
                                    <div class="compliance-score {% if compliance_percentage >= 80 %}text-success{% elif compliance_percentage >= 60 %}text-warning{% else %}text-danger{% endif %}">
                                        {{ "%.1f"|format(compliance_percentage) }}%
                                    </div>
                                    <p class="mb-0">Overall Compliance Score</p>
                                </div>
                                <div class="mt-3">
                                    <div class="row text-center">
                                        <div class="col-3">
                                            <div class="h4 text-success mb-0">{{ scan_data.passed_checks }}</div>
                                            <small>Passed</small>
                                        </div>
                                        <div class="col-3">
                                            <div class="h4 text-danger mb-0">{{ scan_data.failed_checks }}</div>
                                            <small>Failed</small>
                                        </div>
                                        <div class="col-3">
                                            <div class="h4 text-warning mb-0">{{ scan_data.skipped_checks }}</div>
                                            <small>Skipped</small>
                                        </div>
                                        <div class="col-3">
                                            <div class="h4 text-info mb-0">{{ error_count }}</div>
                                            <small>Errors</small>
                                        </div>
                                    </div>
                                    <div class="progress mt-3" style="height: 10px;">
                                        {% set pass_pct = (scan_data.passed_checks / scan_data.total_checks * 100) if scan_data.total_checks > 0 else 0 %}
                                        {% set fail_pct = (scan_data.failed_checks / scan_data.total_checks * 100) if scan_data.total_checks > 0 else 0 %}
                                        {% set skip_pct = (scan_data.skipped_checks / scan_data.total_checks * 100) if scan_data.total_checks > 0 else 0 %}
                                        <div class="progress-bar bg-success" style="width: {{ pass_pct }}%"></div>
                                        <div class="progress-bar bg-danger" style="width: {{ fail_pct }}%"></div>
                                        <div class="progress-bar bg-warning" style="width: {{ skip_pct }}%"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                {% for category, category_results in results_by_category.items() %}
                <div class="category-section">
                    <div class="card">
                        <div class="card-header">
                            <h3 class="mb-0">
                                <i class="fas fa-folder me-2"></i>
                                {{ category }}
                                <span class="badge bg-secondary ms-2">{{ category_results|length }} checks</span>
                                {% set cat_passed = category_results | selectattr("status", "equalto", "pass") | list | length %}
                                {% set cat_failed = category_results | selectattr("status", "equalto", "fail") | list | length %}
                                {% if cat_passed + cat_failed > 0 %}
                                    {% set cat_compliance = (cat_passed / (cat_passed + cat_failed) * 100) | round(1) %}
                                    <span class="badge {% if cat_compliance >= 80 %}bg-success{% elif cat_compliance >= 60 %}bg-warning{% else %}bg-danger{% endif %} ms-2">
                                        {{ cat_compliance }}% compliant
                                    </span>
                                {% endif %}
                            </h3>
                        </div>
                        <div class="card-body p-0">
                            <div class="table-responsive">
                                <table class="table table-hover mb-0">
                                    <thead class="table-dark">
                                        <tr>
                                            <th style="width: 10%">Control ID</th>
                                            <th style="width: 35%">Title</th>
                                            <th style="width: 10%">Status</th>
                                            <th style="width: 20%">Current Value</th>
                                            <th style="width: 20%">Expected Value</th>
                                            <th style="width: 5%">Profile</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% for result in category_results %}
                                        <tr class="result-row">
                                            <td><code class="small">{{ result.control_id }}</code></td>
                                            <td>
                                                <strong>{{ result.control_title }}</strong>
                                                {% if not result.automated %}
                                                    <span class="badge bg-info ms-1">Manual</span>
                                                {% endif %}
                                            </td>
                                            <td>
                                                {% if result.status == 'pass' %}
                                                    <span class="badge bg-success">
                                                        <i class="fas fa-check me-1"></i>PASS
                                                    </span>
                                                {% elif result.status == 'fail' %}
                                                    <span class="badge bg-danger">
                                                        <i class="fas fa-times me-1"></i>FAIL
                                                    </span>
                                                {% elif result.status == 'skip' %}
                                                    <span class="badge bg-warning">
                                                        <i class="fas fa-minus me-1"></i>SKIP
                                                    </span>
                                                {% else %}
                                                    <span class="badge bg-secondary">
                                                        <i class="fas fa-exclamation me-1"></i>ERROR
                                                    </span>
                                                {% endif %}
                                            </td>
                                            <td>
                                                {% if result.current_value %}
                                                    <small class="text-muted">{{ result.current_value[:80] }}{% if result.current_value|length > 80 %}...{% endif %}</small>
                                                {% else %}
                                                    <em class="text-muted">N/A</em>
                                                {% endif %}
                                            </td>
                                            <td>
                                                {% if result.expected_value %}
                                                    <small class="text-muted">{{ result.expected_value[:80] }}{% if result.expected_value|length > 80 %}...{% endif %}</small>
                                                {% else %}
                                                    <em class="text-muted">N/A</em>
                                                {% endif %}
                                            </td>
                                            <td><small>{{ result.profile }}</small></td>
                                        </tr>
                                        
                                        {% if result.remediation or result.error_details or result.rationale or result.impact %}
                                        <tr class="table-secondary">
                                            <td colspan="6">
                                                <div class="small p-2">
                                                    {% if result.error_details %}
                                                    <div class="alert alert-danger mb-2 py-1">
                                                        <i class="fas fa-exclamation-triangle me-1"></i>
                                                        <strong>Error:</strong> {{ result.error_details }}
                                                    </div>
                                                    {% endif %}
                                                    {% if result.remediation %}
                                                    <div class="mb-2">
                                                        <i class="fas fa-wrench me-1 text-info"></i>
                                                        <strong>Remediation:</strong> {{ result.remediation }}
                                                    </div>
                                                    {% endif %}
                                                    {% if result.rationale %}
                                                    <div class="mb-2">
                                                        <i class="fas fa-lightbulb me-1 text-warning"></i>
                                                        <strong>Rationale:</strong> {{ result.rationale }}
                                                    </div>
                                                    {% endif %}
                                                    {% if result.impact %}
                                                    <div>
                                                        <i class="fas fa-shield-alt me-1 text-danger"></i>
                                                        <strong>Impact:</strong> {{ result.impact }}
                                                    </div>
                                                    {% endif %}
                                                </div>
                                            </td>
                                        </tr>
                                        {% endif %}
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
                {% endfor %}
                
                <div class="card mt-4">
                    <div class="card-body text-center">
                        <h5>Report Generated</h5>
                        <p class="text-muted mb-0">
                            <i class="fas fa-calendar me-1"></i>
                            {{ datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC') }} | 
                            <i class="fas fa-book me-1"></i>
                            CIS Palo Alto Firewall 10 Benchmark v1.1.0
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
        """
        
        # Calculate compliance percentage
        total_applicable = scan_data.passed_checks + scan_data.failed_checks
        compliance_percentage = (scan_data.passed_checks / total_applicable * 100) if total_applicable > 0 else 0
        
        # Group results by category
        results_by_category = {}
        error_count = 0
        for result in results:
            if result.status == 'error':
                error_count += 1
            category = result.category
            if category not in results_by_category:
                results_by_category[category] = []
            results_by_category[category].append(result)
        
        template = self.jinja_env.from_string(template_str)
        return template.render(
            scan_data=scan_data,
            results_by_category=results_by_category,
            compliance_percentage=compliance_percentage,
            error_count=error_count,
            datetime=datetime
        )
    
    def generate_json_report(self, scan_data, results):
        """Generate JSON compliance report"""
        report_data = {
            'scan_info': {
                'scan_name': scan_data.scan_name,
                'firewall_name': scan_data.firewall.name,
                'firewall_hostname': scan_data.firewall.hostname,
                'started_at': scan_data.started_at.isoformat() if scan_data.started_at else None,
                'completed_at': scan_data.completed_at.isoformat() if scan_data.completed_at else None,
                'status': scan_data.status,
                'total_checks': scan_data.total_checks,
                'passed_checks': scan_data.passed_checks,
                'failed_checks': scan_data.failed_checks,
                'skipped_checks': scan_data.skipped_checks
            },
            'compliance_results': []
        }
        
        for result in results:
            result_data = {
                'control_id': result.control_id,
                'control_title': result.control_title,
                'category': result.category,
                'status': result.status,
                'current_value': result.current_value,
                'expected_value': result.expected_value,
                'remediation': result.remediation,
                'impact': result.impact,
                'rationale': result.rationale,
                'profile': result.profile,
                'automated': result.automated,
                'error_details': result.error_details,
                'checked_at': result.checked_at.isoformat() if result.checked_at else None
            }
            report_data['compliance_results'].append(result_data)
        
        return json.dumps(report_data, indent=2)
    
    def generate_csv_report(self, scan_data, results):
        """Generate CSV compliance report"""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Control ID', 'Title', 'Category', 'Status', 'Current Value', 
            'Expected Value', 'Remediation', 'Impact', 'Profile', 'Automated', 
            'Error Details', 'Checked At'
        ])
        
        # Write results
        for result in results:
            writer.writerow([
                result.control_id,
                result.control_title,
                result.category,
                result.status,
                result.current_value,
                result.expected_value,
                result.remediation,
                result.impact,
                result.profile,
                'Yes' if result.automated else 'No',
                result.error_details,
                result.checked_at.isoformat() if result.checked_at else ''
            ])
        
        return output.getvalue()
