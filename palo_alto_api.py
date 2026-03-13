import requests
import xml.etree.ElementTree as ET
import logging
import urllib3
from urllib.parse import urljoin
import time

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

class PaloAltoAPI:
    def __init__(self, hostname, api_key, port=443, timeout=30):
        self.hostname = hostname
        self.api_key = api_key
        self.port = port
        self.timeout = timeout
        self.base_url = f"https://{hostname}:{port}/api/"
        
    def _make_request(self, params):
        """Make API request to Palo Alto firewall"""
        try:
            params['key'] = self.api_key
            response = requests.get(
                self.base_url,
                params=params,
                verify=False,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            # Parse XML response
            root = ET.fromstring(response.text)
            
            # Check for API errors
            if root.get('status') == 'error':
                error_msg = root.find('.//msg')
                if error_msg is not None:
                    raise Exception(f"API Error: {error_msg.text}")
                else:
                    raise Exception("Unknown API error")
            
            return root
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            raise Exception(f"Connection error: {str(e)}")
        except ET.ParseError as e:
            logger.error(f"XML parsing failed: {str(e)}")
            raise Exception(f"Invalid XML response: {str(e)}")
    
    def test_connection(self):
        """Test API connectivity and authentication"""
        try:
            params = {'type': 'op', 'cmd': '<show><system><info></info></system></show>'}
            result = self._make_request(params)
            return True, "Connection successful"
        except Exception as e:
            return False, str(e)
    
    def get_system_info(self):
        """Get system information"""
        params = {'type': 'op', 'cmd': '<show><system><info></info></system></show>'}
        return self._make_request(params)
    
    def get_config(self, xpath=None):
        """Get configuration from firewall"""
        params = {'type': 'config', 'action': 'get'}
        if xpath:
            params['xpath'] = xpath
        return self._make_request(params)
    
    def get_device_config(self):
        """Get complete device configuration"""
        return self.get_config('/config/devices/entry[@name="localhost.localdomain"]/deviceconfig')
    
    def get_shared_config(self):
        """Get shared configuration"""
        return self.get_config('/config/shared')
    
    def get_panorama_config(self):
        """Get Panorama configuration if applicable"""
        return self.get_config('/config/panorama')
    
    def get_network_config(self):
        """Get network configuration"""
        return self.get_config('/config/devices/entry[@name="localhost.localdomain"]/network')
    
    def get_vsys_config(self, vsys='vsys1'):
        """Get virtual system configuration"""
        xpath = f'/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="{vsys}"]'
        return self.get_config(xpath)
    
    def commit_check(self):
        """Perform commit check"""
        params = {'type': 'commit', 'action': 'partial', 'cmd': '<commit-all></commit-all>'}
        return self._make_request(params)
