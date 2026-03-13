from flask import render_template, request, redirect, url_for, flash, jsonify, make_response
from app import app, db
from models import Firewall, ComplianceScan, ComplianceResult
from palo_alto_api import PaloAltoAPI
from cis_compliance import CISComplianceChecker
from report_generator import ReportGenerator
import logging
from datetime import datetime
import threading
import os

logger = logging.getLogger(__name__)

@app.route('/')
def dashboard():
    """Main dashboard"""
    firewalls = Firewall.query.all()
    recent_scans = ComplianceScan.query.order_by(ComplianceScan.started_at.desc()).limit(10).all()
    
    # Calculate summary statistics
    total_firewalls = len(firewalls)
    active_scans = ComplianceScan.query.filter_by(status='running').count()
    completed_scans = ComplianceScan.query.filter_by(status='completed').count()
    
    return render_template('dashboard.html', 
                         firewalls=firewalls,
                         recent_scans=recent_scans,
                         total_firewalls=total_firewalls,
                         active_scans=active_scans,
                         completed_scans=completed_scans)

@app.route('/firewalls')
def list_firewalls():
    """List all firewalls"""
    firewalls = Firewall.query.all()
    return render_template('firewalls.html', firewalls=firewalls)

@app.route('/firewalls/add', methods=['GET', 'POST'])
def add_firewall():
    """Add new firewall"""
    if request.method == 'POST':
        try:
            name = request.form['name']
            hostname = request.form['hostname']
            port = int(request.form.get('port', 443))
            api_key = request.form['api_key']
            description = request.form.get('description', '')
            
            # Test connection before saving
            api = PaloAltoAPI(hostname, api_key, port)
            success, message = api.test_connection()
            
            if not success:
                flash(f'Connection test failed: {message}', 'error')
                return render_template('firewall_form.html', 
                                     form_data=request.form,
                                     title='Add Firewall')
            
            firewall = Firewall(
                name=name,
                hostname=hostname,
                port=port,
                api_key=api_key,
                description=description
            )
            
            db.session.add(firewall)
            db.session.commit()
            
            flash(f'Firewall {name} added successfully!', 'success')
            return redirect(url_for('list_firewalls'))
            
        except Exception as e:
            flash(f'Error adding firewall: {str(e)}', 'error')
            logger.error(f"Error adding firewall: {str(e)}")
    
    return render_template('firewall_form.html', title='Add Firewall')

@app.route('/firewalls/<int:firewall_id>/edit', methods=['GET', 'POST'])
def edit_firewall(firewall_id):
    """Edit firewall"""
    firewall = Firewall.query.get_or_404(firewall_id)
    
    if request.method == 'POST':
        try:
            firewall.name = request.form['name']
            firewall.hostname = request.form['hostname']
            firewall.port = int(request.form.get('port', 443))
            firewall.api_key = request.form['api_key']
            firewall.description = request.form.get('description', '')
            
            # Test connection if credentials changed
            if 'test_connection' in request.form:
                api = PaloAltoAPI(firewall.hostname, firewall.api_key, firewall.port)
                success, message = api.test_connection()
                
                if not success:
                    flash(f'Connection test failed: {message}', 'error')
                    return render_template('firewall_form.html', 
                                         firewall=firewall,
                                         title='Edit Firewall')
            
            db.session.commit()
            flash(f'Firewall {firewall.name} updated successfully!', 'success')
            return redirect(url_for('list_firewalls'))
            
        except Exception as e:
            flash(f'Error updating firewall: {str(e)}', 'error')
            logger.error(f"Error updating firewall: {str(e)}")
    
    return render_template('firewall_form.html', firewall=firewall, title='Edit Firewall')

@app.route('/firewalls/<int:firewall_id>/delete', methods=['POST'])
def delete_firewall(firewall_id):
    """Delete firewall"""
    firewall = Firewall.query.get_or_404(firewall_id)
    
    try:
        db.session.delete(firewall)
        db.session.commit()
        flash(f'Firewall {firewall.name} deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting firewall: {str(e)}', 'error')
        logger.error(f"Error deleting firewall: {str(e)}")
    
    return redirect(url_for('list_firewalls'))

@app.route('/scan/new')
def new_scan():
    """Create new compliance scan"""
    firewalls = Firewall.query.filter_by(status='active').all()
    return render_template('scan_form.html', firewalls=firewalls)

@app.route('/scan/start', methods=['POST'])
def start_scan():
    """Start compliance scan"""
    try:
        firewall_ids = request.form.getlist('firewall_ids')
        scan_name = request.form['scan_name']
        
        if not firewall_ids:
            flash('Please select at least one firewall', 'error')
            return redirect(url_for('new_scan'))
        
        # Create scan records
        scans = []
        for firewall_id in firewall_ids:
            firewall = Firewall.query.get(firewall_id)
            if firewall:
                scan = ComplianceScan(
                    firewall_id=firewall.id,
                    scan_name=f"{scan_name} - {firewall.name}",
                    status='pending'
                )
                db.session.add(scan)
                scans.append(scan)
        
        db.session.commit()
        
        # Start scans in background
        for scan in scans:
            thread = threading.Thread(target=run_compliance_scan, args=(scan.id,))
            thread.daemon = True
            thread.start()
        
        flash(f'Started {len(scans)} compliance scan(s)!', 'success')
        return redirect(url_for('list_scans'))
        
    except Exception as e:
        flash(f'Error starting scan: {str(e)}', 'error')
        logger.error(f"Error starting scan: {str(e)}")
        return redirect(url_for('new_scan'))

def run_compliance_scan(scan_id):
    """Background task to run compliance scan"""
    with app.app_context():
        try:
            scan = ComplianceScan.query.get(scan_id)
            if not scan:
                return
            
            scan.status = 'running'
            scan.started_at = datetime.utcnow()
            db.session.commit()
            
            # Initialize API connection
            firewall = scan.firewall
            api = PaloAltoAPI(firewall.hostname, firewall.api_key, firewall.port)
            
            # Test connection
            success, message = api.test_connection()
            if not success:
                scan.status = 'failed'
                scan.error_message = f'Connection failed: {message}'
                scan.completed_at = datetime.utcnow()
                db.session.commit()
                return
            
            # Run compliance checks
            checker = CISComplianceChecker(api)
            results = checker.run_all_checks()
            
            # Save results
            passed = failed = skipped = 0
            for result_data in results:
                result = ComplianceResult(
                    scan_id=scan.id,
                    control_id=result_data['control_id'],
                    control_title=result_data['control_title'],
                    category=result_data['category'],
                    status=result_data['status'],
                    current_value=result_data['current_value'],
                    expected_value=result_data['expected_value'],
                    remediation=result_data['remediation'],
                    impact=result_data['impact'],
                    rationale=result_data['rationale'],
                    profile=result_data['profile'],
                    automated=result_data['automated'],
                    error_details=result_data['error_details']
                )
                db.session.add(result)
                
                if result.status == 'pass':
                    passed += 1
                elif result.status == 'fail':
                    failed += 1
                elif result.status == 'skip':
                    skipped += 1
            
            # Update scan status
            scan.status = 'completed'
            scan.completed_at = datetime.utcnow()
            scan.total_checks = len(results)
            scan.passed_checks = passed
            scan.failed_checks = failed
            scan.skipped_checks = skipped
            firewall.last_scan = scan.completed_at
            
            db.session.commit()
            logger.info(f"Completed compliance scan for {firewall.name}")
            
        except Exception as e:
            logger.error(f"Error in compliance scan {scan_id}: {str(e)}")
            scan.status = 'failed'
            scan.error_message = str(e)
            scan.completed_at = datetime.utcnow()
            db.session.commit()

@app.route('/scans')
def list_scans():
    """List all compliance scans"""
    page = request.args.get('page', 1, type=int)
    scans = ComplianceScan.query.order_by(ComplianceScan.started_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    return render_template('scan_list.html', scans=scans)

@app.route('/scans/<int:scan_id>')
def view_scan(scan_id):
    """View scan results"""
    scan = ComplianceScan.query.get_or_404(scan_id)
    results = ComplianceResult.query.filter_by(scan_id=scan.id).all()
    
    # Group results by category
    results_by_category = {}
    for result in results:
        category = result.category
        if category not in results_by_category:
            results_by_category[category] = []
        results_by_category[category].append(result)
    
    return render_template('scan_results.html', scan=scan, results_by_category=results_by_category)

@app.route('/scans/<int:scan_id>/report/<format>')
def download_report(scan_id, format):
    """Download scan report in specified format"""
    scan = ComplianceScan.query.get_or_404(scan_id)
    results = ComplianceResult.query.filter_by(scan_id=scan.id).all()
    
    generator = ReportGenerator()
    
    if format == 'html':
        content = generator.generate_html_report(scan, results)
        response = make_response(content)
        response.headers['Content-Type'] = 'text/html'
        response.headers['Content-Disposition'] = f'attachment; filename=compliance_report_{scan.id}.html'
        return response
    
    elif format == 'json':
        content = generator.generate_json_report(scan, results)
        response = make_response(content)
        response.headers['Content-Type'] = 'application/json'
        response.headers['Content-Disposition'] = f'attachment; filename=compliance_report_{scan.id}.json'
        return response
    
    elif format == 'csv':
        content = generator.generate_csv_report(scan, results)
        response = make_response(content)
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename=compliance_report_{scan.id}.csv'
        return response
    
    else:
        flash('Invalid report format', 'error')
        return redirect(url_for('view_scan', scan_id=scan_id))

@app.route('/api/scan/<int:scan_id>/status')
def get_scan_status(scan_id):
    """Get scan status via API"""
    scan = ComplianceScan.query.get_or_404(scan_id)
    return jsonify({
        'id': scan.id,
        'status': scan.status,
        'started_at': scan.started_at.isoformat() if scan.started_at else None,
        'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
        'total_checks': scan.total_checks,
        'passed_checks': scan.passed_checks,
        'failed_checks': scan.failed_checks,
        'skipped_checks': scan.skipped_checks,
        'error_message': scan.error_message
    })

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', 
                         error_code=404, 
                         error_message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error.html', 
                         error_code=500, 
                         error_message="Internal server error"), 500
