import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///compliance.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Palo Alto API Configuration
    PA_DEFAULT_TIMEOUT = int(os.environ.get('PA_API_TIMEOUT', '30'))
    PA_MAX_RETRIES = int(os.environ.get('PA_MAX_RETRIES', '3'))
    
    # Report Configuration
    REPORTS_DIR = os.environ.get('REPORTS_DIR', 'reports')
    MAX_CONCURRENT_SCANS = int(os.environ.get('MAX_CONCURRENT_SCANS', '5'))
