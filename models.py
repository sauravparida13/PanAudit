from datetime import datetime
from app import db
from flask_login import UserMixin
import json

class Firewall(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    hostname = db.Column(db.String(255), nullable=False)
    port = db.Column(db.Integer, default=443)
    api_key = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_scan = db.Column(db.DateTime)
    status = db.Column(db.String(50), default='active')
    
    # Relationships
    scans = db.relationship('ComplianceScan', backref='firewall', lazy=True, cascade='all, delete-orphan')

class ComplianceScan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firewall_id = db.Column(db.Integer, db.ForeignKey('firewall.id'), nullable=False)
    scan_name = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(50), default='pending')  # pending, running, completed, failed
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    total_checks = db.Column(db.Integer, default=0)
    passed_checks = db.Column(db.Integer, default=0)
    failed_checks = db.Column(db.Integer, default=0)
    skipped_checks = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text)
    
    # Store scan configuration as JSON
    scan_config = db.Column(db.Text)  # JSON string
    
    # Relationships
    results = db.relationship('ComplianceResult', backref='scan', lazy=True, cascade='all, delete-orphan')
    
    def get_scan_config(self):
        if self.scan_config:
            return json.loads(self.scan_config)
        return {}
    
    def set_scan_config(self, config):
        self.scan_config = json.dumps(config)

class ComplianceResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('compliance_scan.id'), nullable=False)
    control_id = db.Column(db.String(50), nullable=False)
    control_title = db.Column(db.String(500), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # pass, fail, skip, error
    current_value = db.Column(db.Text)
    expected_value = db.Column(db.Text)
    remediation = db.Column(db.Text)
    impact = db.Column(db.Text)
    rationale = db.Column(db.Text)
    profile = db.Column(db.String(50))  # Level 1, Level 2
    automated = db.Column(db.Boolean, default=True)
    error_details = db.Column(db.Text)
    checked_at = db.Column(db.DateTime, default=datetime.utcnow)
