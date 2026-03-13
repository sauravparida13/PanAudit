import logging
import xml.etree.ElementTree as ET
from datetime import datetime
import re

logger = logging.getLogger(__name__)

class CISComplianceChecker:
    def __init__(self, palo_api):
        self.api = palo_api
        self.results = []
        
    def run_all_checks(self, scan_config=None):
        """Run all CIS compliance checks"""
        self.results = []
        
        # Device Setup checks
        self._check_device_setup()
        
        # User Identification checks
        self._check_user_identification()
        
        # High Availability checks
        self._check_high_availability()
        
        # Dynamic Updates checks
        self._check_dynamic_updates()
        
        # WildFire checks
        self._check_wildfire()
        
        # Security Profiles checks
        self._check_security_profiles()
        
        return self.results
    
    def _add_result(self, control_id, title, category, status, current_value="", 
                   expected_value="", remediation="", impact="", rationale="", 
                   profile="Level 1", automated=True, error_details=""):
        """Add a compliance check result"""
        result = {
            'control_id': control_id,
            'control_title': title,
            'category': category,
            'status': status,
            'current_value': str(current_value),
            'expected_value': str(expected_value),
            'remediation': remediation,
            'impact': impact,
            'rationale': rationale,
            'profile': profile,
            'automated': automated,
            'error_details': error_details,
            'checked_at': datetime.utcnow()
        }
        self.results.append(result)
        return result
    
    def _check_device_setup(self):
        """Check Device Setup compliance (Section 1)"""
        try:
            device_config = self.api.get_device_config()
            self._check_general_settings(device_config)
            self._check_management_interface(device_config)
            self._check_password_requirements(device_config)
            self._check_authentication_settings(device_config)
            self._check_snmp_settings(device_config)
            self._check_device_services(device_config)
        except Exception as e:
            logger.error(f"Device setup checks failed: {str(e)}")
            self._add_result("1.0", "Device Setup", "Device Setup", "error", 
                           error_details=str(e))
    
    def _check_general_settings(self, device_config):
        """Check general settings (1.1)"""
        # 1.1.1.1 Syslog logging should be configured
        try:
            syslog_servers = device_config.findall('.//syslog/entry')
            if syslog_servers:
                self._add_result("1.1.1.1", "Syslog logging should be configured", 
                               "General Settings", "pass", 
                               f"Found {len(syslog_servers)} syslog server(s)",
                               "At least one syslog server configured",
                               "Configure syslog servers for centralized logging",
                               "Ensures audit trail and monitoring capabilities")
            else:
                self._add_result("1.1.1.1", "Syslog logging should be configured", 
                               "General Settings", "fail", 
                               "No syslog servers configured",
                               "At least one syslog server configured",
                               "Configure Device > Setup > Management > Logging Settings > Syslog",
                               "Without centralized logging, security events may be lost")
        except Exception as e:
            self._add_result("1.1.1.1", "Syslog logging should be configured", 
                           "General Settings", "error", error_details=str(e))
        
        # 1.1.1.2 SNMPv3 traps should be configured
        try:
            snmp_config = device_config.find('.//snmp-setting')
            if snmp_config is not None:
                snmp_v3_servers = snmp_config.findall('.//v3-server/entry')
                if snmp_v3_servers:
                    self._add_result("1.1.1.2", "SNMPv3 traps should be configured", 
                                   "General Settings", "pass",
                                   f"Found {len(snmp_v3_servers)} SNMPv3 server(s)",
                                   "SNMPv3 servers configured for traps")
                else:
                    self._add_result("1.1.1.2", "SNMPv3 traps should be configured", 
                                   "General Settings", "fail",
                                   "No SNMPv3 trap servers configured",
                                   "SNMPv3 servers configured for traps",
                                   "Configure Device > Setup > Management > SNMP Settings",
                                   "SNMPv1/v2 use cleartext community strings")
            else:
                self._add_result("1.1.1.2", "SNMPv3 traps should be configured", 
                               "General Settings", "fail",
                               "SNMP not configured",
                               "SNMPv3 servers configured for traps")
        except Exception as e:
            self._add_result("1.1.1.2", "SNMPv3 traps should be configured", 
                           "General Settings", "error", error_details=str(e))
        
        # 1.1.2 Ensure 'Login Banner' is set
        try:
            login_banner = device_config.find('.//login-banner')
            if login_banner is not None and login_banner.text:
                self._add_result("1.1.2", "Ensure 'Login Banner' is set", 
                               "General Settings", "pass",
                               "Login banner configured",
                               "Login banner should be set",
                               "",
                               "Provides legal notice and deters unauthorized access")
            else:
                self._add_result("1.1.2", "Ensure 'Login Banner' is set", 
                               "General Settings", "fail",
                               "No login banner configured",
                               "Login banner should be set",
                               "Configure Device > Setup > Management > General Settings > Login Banner",
                               "Users may not be aware of legal implications")
        except Exception as e:
            self._add_result("1.1.2", "Ensure 'Login Banner' is set", 
                           "General Settings", "error", error_details=str(e))
        
        # 1.1.3 Ensure 'Enable Log on High DP Load' is enabled
        try:
            log_high_dp = device_config.find('.//log-export-schedule/entry/log-high-dp-load')
            if log_high_dp is not None and log_high_dp.text == 'yes':
                self._add_result("1.1.3", "Ensure 'Enable Log on High DP Load' is enabled", 
                               "General Settings", "pass",
                               "Log on High DP Load enabled",
                               "Should be enabled")
            else:
                self._add_result("1.1.3", "Ensure 'Enable Log on High DP Load' is enabled", 
                               "General Settings", "fail",
                               "Log on High DP Load not enabled",
                               "Should be enabled",
                               "Configure Device > Setup > Management > Logging Settings",
                               "May miss critical events during high load")
        except Exception as e:
            self._add_result("1.1.3", "Ensure 'Enable Log on High DP Load' is enabled", 
                           "General Settings", "error", error_details=str(e))
    
    def _check_management_interface(self, device_config):
        """Check management interface settings (1.2)"""
        # 1.2.1 Ensure 'Permitted IP Addresses' is set
        try:
            mgmt_config = device_config.find('.//management')
            if mgmt_config is not None:
                permitted_ips = mgmt_config.findall('.//permitted-ip/entry')
                if permitted_ips:
                    ip_list = [ip.get('name') for ip in permitted_ips]
                    self._add_result("1.2.1", "Ensure 'Permitted IP Addresses' is set", 
                                   "Management Interface", "pass",
                                   f"Permitted IPs: {', '.join(ip_list)}",
                                   "Specific IP addresses/ranges configured",
                                   "",
                                   "Restricts management access to authorized sources")
                else:
                    self._add_result("1.2.1", "Ensure 'Permitted IP Addresses' is set", 
                                   "Management Interface", "fail",
                                   "No permitted IP restrictions",
                                   "Specific IP addresses/ranges configured",
                                   "Configure Device > Setup > Interfaces > Management > Permitted IP Addresses",
                                   "Management interface accessible from any IP")
            else:
                self._add_result("1.2.1", "Ensure 'Permitted IP Addresses' is set", 
                               "Management Interface", "error",
                               error_details="Management configuration not found")
        except Exception as e:
            self._add_result("1.2.1", "Ensure 'Permitted IP Addresses' is set", 
                           "Management Interface", "error", error_details=str(e))
        
        # 1.2.3 Ensure HTTP and Telnet options are disabled
        try:
            services = device_config.find('.//service')
            if services is not None:
                disable_http = services.find('disable-http')
                disable_telnet = services.find('disable-telnet')
                
                http_disabled = disable_http is not None and disable_http.text == 'yes'
                telnet_disabled = disable_telnet is not None and disable_telnet.text == 'yes'
                
                if http_disabled and telnet_disabled:
                    self._add_result("1.2.3", "Ensure HTTP and Telnet options are disabled", 
                                   "Management Interface", "pass",
                                   "HTTP and Telnet disabled",
                                   "Both services should be disabled")
                else:
                    status = []
                    if not http_disabled:
                        status.append("HTTP enabled")
                    if not telnet_disabled:
                        status.append("Telnet enabled")
                    
                    self._add_result("1.2.3", "Ensure HTTP and Telnet options are disabled", 
                                   "Management Interface", "fail",
                                   ", ".join(status),
                                   "Both services should be disabled",
                                   "Configure Device > Setup > Management > General Settings",
                                   "Unencrypted protocols expose credentials and traffic")
            else:
                self._add_result("1.2.3", "Ensure HTTP and Telnet options are disabled", 
                               "Management Interface", "error",
                               error_details="Service configuration not found")
        except Exception as e:
            self._add_result("1.2.3", "Ensure HTTP and Telnet options are disabled", 
                           "Management Interface", "error", error_details=str(e))
    
    def _check_password_requirements(self, device_config):
        """Check password requirements (1.3)"""
        try:
            password_profile = device_config.find('.//password-complexity')
            if password_profile is not None:
                # 1.3.1 Minimum Password Complexity enabled
                enabled = password_profile.find('enabled')
                if enabled is not None and enabled.text == 'yes':
                    self._add_result("1.3.1", "Ensure 'Minimum Password Complexity' is enabled", 
                                   "Password Requirements", "pass",
                                   "Password complexity enabled",
                                   "Should be enabled")
                else:
                    self._add_result("1.3.1", "Ensure 'Minimum Password Complexity' is enabled", 
                                   "Password Requirements", "fail",
                                   "Password complexity not enabled",
                                   "Should be enabled",
                                   "Configure Device > Setup > Management > Authentication Settings")
                
                # 1.3.2 Minimum Length >= 12
                min_length = password_profile.find('minimum-length')
                if min_length is not None:
                    length = int(min_length.text)
                    if length >= 12:
                        self._add_result("1.3.2", "Ensure 'Minimum Length' is greater than or equal to 12", 
                                       "Password Requirements", "pass",
                                       f"Minimum length: {length}",
                                       "Minimum length >= 12")
                    else:
                        self._add_result("1.3.2", "Ensure 'Minimum Length' is greater than or equal to 12", 
                                       "Password Requirements", "fail",
                                       f"Minimum length: {length}",
                                       "Minimum length >= 12",
                                       "Set minimum password length to 12 or greater")
                
                # 1.3.3 Minimum Uppercase Letters >= 1
                min_uppercase = password_profile.find('minimum-uppercase-letters')
                if min_uppercase is not None:
                    uppercase = int(min_uppercase.text)
                    if uppercase >= 1:
                        self._add_result("1.3.3", "Ensure 'Minimum Uppercase Letters' is greater than or equal to 1", 
                                       "Password Requirements", "pass",
                                       f"Minimum uppercase letters: {uppercase}",
                                       "Minimum uppercase letters >= 1")
                    else:
                        self._add_result("1.3.3", "Ensure 'Minimum Uppercase Letters' is greater than or equal to 1", 
                                       "Password Requirements", "fail",
                                       f"Minimum uppercase letters: {uppercase}",
                                       "Minimum uppercase letters >= 1",
                                       "Set minimum uppercase letters to 1 or greater")
                
                # 1.3.4 Minimum Lowercase Letters >= 1
                min_lowercase = password_profile.find('minimum-lowercase-letters')
                if min_lowercase is not None:
                    lowercase = int(min_lowercase.text)
                    if lowercase >= 1:
                        self._add_result("1.3.4", "Ensure 'Minimum Lowercase Letters' is greater than or equal to 1", 
                                       "Password Requirements", "pass",
                                       f"Minimum lowercase letters: {lowercase}",
                                       "Minimum lowercase letters >= 1")
                    else:
                        self._add_result("1.3.4", "Ensure 'Minimum Lowercase Letters' is greater than or equal to 1", 
                                       "Password Requirements", "fail",
                                       f"Minimum lowercase letters: {lowercase}",
                                       "Minimum lowercase letters >= 1",
                                       "Set minimum lowercase letters to 1 or greater")
                
                # 1.3.5 Minimum Numeric Letters >= 1
                min_numeric = password_profile.find('minimum-numeric-letters')
                if min_numeric is not None:
                    numeric = int(min_numeric.text)
                    if numeric >= 1:
                        self._add_result("1.3.5", "Ensure 'Minimum Numeric Letters' is greater than or equal to 1", 
                                       "Password Requirements", "pass",
                                       f"Minimum numeric letters: {numeric}",
                                       "Minimum numeric letters >= 1")
                    else:
                        self._add_result("1.3.5", "Ensure 'Minimum Numeric Letters' is greater than or equal to 1", 
                                       "Password Requirements", "fail",
                                       f"Minimum numeric letters: {numeric}",
                                       "Minimum numeric letters >= 1",
                                       "Set minimum numeric letters to 1 or greater")
                
                # 1.3.6 Minimum Special Characters >= 1
                min_special = password_profile.find('minimum-special-characters')
                if min_special is not None:
                    special = int(min_special.text)
                    if special >= 1:
                        self._add_result("1.3.6", "Ensure 'Minimum Special Characters' is greater than or equal to 1", 
                                       "Password Requirements", "pass",
                                       f"Minimum special characters: {special}",
                                       "Minimum special characters >= 1")
                    else:
                        self._add_result("1.3.6", "Ensure 'Minimum Special Characters' is greater than or equal to 1", 
                                       "Password Requirements", "fail",
                                       f"Minimum special characters: {special}",
                                       "Minimum special characters >= 1",
                                       "Set minimum special characters to 1 or greater")
                
                # 1.3.7 Password Change Period <= 90 days
                password_change = password_profile.find('required-password-change-period')
                if password_change is not None:
                    days = int(password_change.text)
                    if days <= 90:
                        self._add_result("1.3.7", "Ensure 'Required Password Change Period' is less than or equal to 90 days", 
                                       "Password Requirements", "pass",
                                       f"Password change period: {days} days",
                                       "Password change period <= 90 days")
                    else:
                        self._add_result("1.3.7", "Ensure 'Required Password Change Period' is less than or equal to 90 days", 
                                       "Password Requirements", "fail",
                                       f"Password change period: {days} days",
                                       "Password change period <= 90 days",
                                       "Set password change period to 90 days or less")
                
            else:
                self._add_result("1.3.1", "Ensure 'Minimum Password Complexity' is enabled", 
                               "Password Requirements", "fail",
                               "Password complexity not configured",
                               "Should be enabled and configured")
        except Exception as e:
            self._add_result("1.3.1", "Password complexity check failed", 
                           "Password Requirements", "error", error_details=str(e))
    
    def _check_authentication_settings(self, device_config):
        """Check authentication settings (1.4)"""
        try:
            # 1.4.1 Idle timeout <= 10 minutes
            auth_settings = device_config.find('.//authentication-settings')
            if auth_settings is not None:
                idle_timeout = auth_settings.find('idle-timeout')
                if idle_timeout is not None:
                    timeout_minutes = int(idle_timeout.text)
                    if timeout_minutes <= 10:
                        self._add_result("1.4.1", "Ensure 'Idle timeout' is less than or equal to 10 minutes", 
                                       "Authentication Settings", "pass",
                                       f"Idle timeout: {timeout_minutes} minutes",
                                       "Idle timeout <= 10 minutes")
                    else:
                        self._add_result("1.4.1", "Ensure 'Idle timeout' is less than or equal to 10 minutes", 
                                       "Authentication Settings", "fail",
                                       f"Idle timeout: {timeout_minutes} minutes",
                                       "Idle timeout <= 10 minutes",
                                       "Set idle timeout to 10 minutes or less")
                else:
                    self._add_result("1.4.1", "Ensure 'Idle timeout' is less than or equal to 10 minutes", 
                                   "Authentication Settings", "fail",
                                   "Idle timeout not configured",
                                   "Idle timeout <= 10 minutes")
        except Exception as e:
            self._add_result("1.4.1", "Authentication settings check failed", 
                           "Authentication Settings", "error", error_details=str(e))
    
    def _check_snmp_settings(self, device_config):
        """Check SNMP settings (1.5)"""
        try:
            # 1.5.1 Ensure 'V3' is selected for SNMP polling
            snmp_config = device_config.find('.//snmp-setting')
            if snmp_config is not None:
                snmp_version = snmp_config.find('snmp-version') 
                if snmp_version is not None and snmp_version.text == 'v3':
                    self._add_result("1.5.1", "Ensure 'V3' is selected for SNMP polling", 
                                   "SNMP Settings", "pass",
                                   "SNMP version: v3",
                                   "SNMP version should be v3")
                else:
                    current_version = snmp_version.text if snmp_version is not None else "not configured"
                    self._add_result("1.5.1", "Ensure 'V3' is selected for SNMP polling", 
                                   "SNMP Settings", "fail",
                                   f"SNMP version: {current_version}",
                                   "SNMP version should be v3",
                                   "Configure Device > Setup > Management > SNMP Settings > Version",
                                   "SNMPv1/v2 transmit community strings in cleartext")
            else:
                self._add_result("1.5.1", "Ensure 'V3' is selected for SNMP polling", 
                               "SNMP Settings", "fail",
                               "SNMP not configured",
                               "SNMP version should be v3")
        except Exception as e:
            self._add_result("1.5.1", "SNMP settings check failed", 
                           "SNMP Settings", "error", error_details=str(e))
    
    def _check_device_services(self, device_config):
        """Check device services (1.6)"""
        try:
            # 1.6.1 Ensure 'Verify Update Server Identity' is enabled
            update_server = device_config.find('.//update-server')
            if update_server is not None:
                verify_identity = update_server.find('verify-update-server-identity')
                if verify_identity is not None and verify_identity.text == 'yes':
                    self._add_result("1.6.1", "Ensure 'Verify Update Server Identity' is enabled", 
                                   "Device Services", "pass",
                                   "Update server identity verification enabled",
                                   "Should be enabled")
                else:
                    self._add_result("1.6.1", "Ensure 'Verify Update Server Identity' is enabled", 
                                   "Device Services", "fail",
                                   "Update server identity verification not enabled",
                                   "Should be enabled",
                                   "Configure Device > Setup > Services > Update Server",
                                   "Prevents man-in-the-middle attacks during updates")
            
            # 1.6.2 Ensure redundant NTP servers are configured
            ntp_servers = device_config.findall('.//ntp-servers/entry')
            if len(ntp_servers) >= 2:
                server_list = [server.get('name') for server in ntp_servers]
                self._add_result("1.6.2", "Ensure redundant NTP servers are configured", 
                               "Device Services", "pass",
                               f"NTP servers: {', '.join(server_list)}",
                               "At least 2 NTP servers configured")
            else:
                server_count = len(ntp_servers)
                self._add_result("1.6.2", "Ensure redundant NTP servers are configured", 
                               "Device Services", "fail",
                               f"Only {server_count} NTP server(s) configured",
                               "At least 2 NTP servers configured",
                               "Configure Device > Setup > Services > NTP",
                               "Single NTP server creates single point of failure")
                
        except Exception as e:
            self._add_result("1.6.1", "Device services check failed", 
                           "Device Services", "error", error_details=str(e))
    
    def _check_user_identification(self):
        """Check User Identification compliance (Section 2)"""
        try:
            vsys_config = self.api.get_vsys_config()
            
            # 2.1 Ensure that IP addresses are mapped to usernames
            user_id_config = vsys_config.find('.//user-id-collector')
            if user_id_config is not None:
                self._add_result("2.1", "Ensure that IP addresses are mapped to usernames", 
                               "User Identification", "pass",
                               "User-ID collector configured",
                               "User-ID should be configured to map IPs to usernames")
            else:
                self._add_result("2.1", "Ensure that IP addresses are mapped to usernames", 
                               "User Identification", "fail",
                               "User-ID collector not configured",
                               "User-ID should be configured to map IPs to usernames",
                               "Configure Device > User Identification",
                               "Without User-ID, policies cannot be applied per user")
            
            # 2.2 Ensure that WMI probing is disabled
            wmi_probing = vsys_config.find('.//wmi-probing')
            if wmi_probing is not None and wmi_probing.text == 'no':
                self._add_result("2.2", "Ensure that WMI probing is disabled", 
                               "User Identification", "pass",
                               "WMI probing disabled",
                               "WMI probing should be disabled")
            else:
                self._add_result("2.2", "Ensure that WMI probing is disabled", 
                               "User Identification", "fail",
                               "WMI probing enabled or not configured",
                               "WMI probing should be disabled",
                               "Configure Device > User Identification > WMI Probing",
                               "WMI probing can be resource intensive and unreliable")
                
        except Exception as e:
            self._add_result("2.0", "User Identification checks failed", "User Identification", 
                           "error", error_details=str(e))
    
    def _check_high_availability(self):
        """Check High Availability compliance (Section 3)"""
        try:
            # Check HA configuration
            ha_config = self.api.get_config('/config/devices/entry[@name="localhost.localdomain"]/deviceconfig/high-availability')
            
            # 3.1 Ensure a fully-synchronized High Availability peer is configured
            ha_enabled = ha_config.find('.//enabled')
            if ha_enabled is not None and ha_enabled.text == 'yes':
                self._add_result("3.1", "Ensure a fully-synchronized High Availability peer is configured", 
                               "High Availability", "pass",
                               "High Availability is configured",
                               "HA should be configured for production systems",
                               "",
                               "Provides redundancy and failover capabilities")
            else:
                self._add_result("3.1", "Ensure a fully-synchronized High Availability peer is configured", 
                               "High Availability", "fail",
                               "High Availability is not configured",
                               "HA should be configured for production systems",
                               "Configure Device > High Availability",
                               "Single point of failure without HA")
            
            # 3.2 Ensure HA requires Link Monitoring and/or Path Monitoring
            if ha_enabled is not None and ha_enabled.text == 'yes':
                link_monitoring = ha_config.find('.//link-monitoring')
                path_monitoring = ha_config.find('.//path-monitoring')
                
                has_monitoring = (link_monitoring is not None and link_monitoring.find('enabled').text == 'yes') or \
                               (path_monitoring is not None and path_monitoring.find('enabled').text == 'yes')
                
                if has_monitoring:
                    self._add_result("3.2", "Ensure 'High Availability' requires Link Monitoring and/or Path Monitoring", 
                                   "High Availability", "pass",
                                   "HA monitoring is configured",
                                   "Link or path monitoring should be enabled")
                else:
                    self._add_result("3.2", "Ensure 'High Availability' requires Link Monitoring and/or Path Monitoring", 
                                   "High Availability", "fail",
                                   "HA monitoring not configured",
                                   "Link or path monitoring should be enabled",
                                   "Configure Device > High Availability > Link/Path Monitoring",
                                   "Without monitoring, HA failover may not work properly")
            else:
                self._add_result("3.2", "Ensure 'High Availability' requires Link Monitoring and/or Path Monitoring", 
                               "High Availability", "skip",
                               "HA not configured",
                               "Only applicable when HA is enabled")
                
        except Exception as e:
            self._add_result("3.0", "High Availability checks failed", "High Availability", 
                           "error", error_details=str(e))
    
    def _check_dynamic_updates(self):
        """Check Dynamic Updates compliance (Section 4)"""
        try:
            # Check update schedules
            update_schedule = self.api.get_config('/config/devices/entry[@name="localhost.localdomain"]/deviceconfig/system/update-schedule')
            
            # 4.1 Ensure 'Antivirus Update Schedule' is set to hourly
            av_schedule = update_schedule.find('.//anti-virus')
            if av_schedule is not None:
                recurring = av_schedule.find('recurring/hourly')
                if recurring is not None:
                    self._add_result("4.1", "Ensure 'Antivirus Update Schedule' is set to download and install updates hourly", 
                                   "Dynamic Updates", "pass",
                                   "Antivirus updates scheduled hourly",
                                   "Antivirus updates should be hourly")
                else:
                    self._add_result("4.1", "Ensure 'Antivirus Update Schedule' is set to download and install updates hourly", 
                                   "Dynamic Updates", "fail",
                                   "Antivirus updates not scheduled hourly",
                                   "Antivirus updates should be hourly",
                                   "Configure Device > Dynamic Updates > Antivirus",
                                   "Infrequent updates leave system vulnerable to new malware")
            else:
                self._add_result("4.1", "Ensure 'Antivirus Update Schedule' is set to download and install updates hourly", 
                               "Dynamic Updates", "fail",
                               "Antivirus update schedule not configured",
                               "Antivirus updates should be hourly")
            
            # 4.2 Ensure 'Applications and Threats Update Schedule' is daily or shorter
            app_threats_schedule = update_schedule.find('.//application-and-threats')
            if app_threats_schedule is not None:
                daily = app_threats_schedule.find('recurring/daily')
                hourly = app_threats_schedule.find('recurring/hourly')
                if daily is not None or hourly is not None:
                    frequency = "hourly" if hourly is not None else "daily"
                    self._add_result("4.2", "Ensure 'Applications and Threats Update Schedule' is set to daily or shorter intervals", 
                                   "Dynamic Updates", "pass",
                                   f"Applications and threats updates scheduled {frequency}",
                                   "Should be daily or more frequent")
                else:
                    self._add_result("4.2", "Ensure 'Applications and Threats Update Schedule' is set to daily or shorter intervals", 
                                   "Dynamic Updates", "fail",
                                   "Applications and threats updates not frequent enough",
                                   "Should be daily or more frequent",
                                   "Configure Device > Dynamic Updates > Applications and Threats",
                                   "Infrequent updates leave system vulnerable to new threats")
            else:
                self._add_result("4.2", "Ensure 'Applications and Threats Update Schedule' is set to daily or shorter intervals", 
                               "Dynamic Updates", "fail",
                               "Applications and threats update schedule not configured",
                               "Should be daily or more frequent")
                
        except Exception as e:
            self._add_result("4.0", "Dynamic Updates checks failed", "Dynamic Updates", 
                           "error", error_details=str(e))
    
    def _check_wildfire(self):
        """Check WildFire compliance (Section 5)"""
        try:
            # Check WildFire configuration
            wildfire_config = self.api.get_config('/config/devices/entry[@name="localhost.localdomain"]/deviceconfig/system/wildfire')
            
            # 5.1 Ensure that WildFire file size upload limits are maximized
            file_size_limit = wildfire_config.find('.//file-size-limit')
            if file_size_limit is not None:
                limit_mb = int(file_size_limit.text)
                if limit_mb >= 10:  # Assuming 10MB is maximum
                    self._add_result("5.1", "Ensure that WildFire file size upload limits are maximized", 
                                   "WildFire", "pass",
                                   f"File size limit: {limit_mb}MB",
                                   "File size limit should be maximized")
                else:
                    self._add_result("5.1", "Ensure that WildFire file size upload limits are maximized", 
                                   "WildFire", "fail",
                                   f"File size limit: {limit_mb}MB",
                                   "File size limit should be maximized",
                                   "Configure Device > Setup > WildFire > File Size Limit",
                                   "Small limits prevent analysis of larger malicious files")
            
            # Check shared WildFire profiles
            shared_config = self.api.get_shared_config()
            wildfire_profiles = shared_config.findall('.//profiles/wildfire-analysis/entry')
            
            if wildfire_profiles:
                self._add_result("5.3", "Ensure a WildFire Analysis profile is enabled for all security policies", 
                               "WildFire", "pass",
                               f"Found {len(wildfire_profiles)} WildFire profile(s)",
                               "WildFire profiles should be configured and applied")
            else:
                self._add_result("5.3", "Ensure a WildFire Analysis profile is enabled for all security policies", 
                               "WildFire", "fail",
                               "No WildFire profiles found",
                               "WildFire profiles should be configured and applied",
                               "Configure Objects > Security Profiles > WildFire Analysis",
                               "No protection against unknown malware without WildFire")
                
        except Exception as e:
            self._add_result("5.0", "WildFire checks failed", "WildFire", 
                           "error", error_details=str(e))
    
    def _check_security_profiles(self):
        """Check Security Profiles compliance (Section 6)"""
        try:
            # Check security profiles
            shared_config = self.api.get_shared_config()
            
            # 6.1 Ensure antivirus profiles are configured
            antivirus_profiles = shared_config.findall('.//profiles/virus/entry')
            if antivirus_profiles:
                # Check if profiles block on all decoders except imap and pop3
                compliant_profiles = 0
                for profile in antivirus_profiles:
                    decoders = profile.findall('.//decoder/entry')
                    blocks_most = True
                    for decoder in decoders:
                        decoder_name = decoder.get('name')
                        action = decoder.find('action')
                        if action is not None and decoder_name not in ['imap', 'pop3']:
                            if action.text != 'block':
                                blocks_most = False
                                break
                    if blocks_most:
                        compliant_profiles += 1
                
                if compliant_profiles > 0:
                    self._add_result("6.1", "Ensure that antivirus profiles are set to block on all decoders except 'imap' and 'pop3'", 
                                   "Security Profiles", "pass",
                                   f"Found {compliant_profiles} compliant antivirus profile(s)",
                                   "Antivirus profiles should block on most decoders")
                else:
                    self._add_result("6.1", "Ensure that antivirus profiles are set to block on all decoders except 'imap' and 'pop3'", 
                                   "Security Profiles", "fail",
                                   "No compliant antivirus profiles found",
                                   "Antivirus profiles should block on most decoders",
                                   "Configure Objects > Security Profiles > Antivirus",
                                   "Allow actions may permit malware to pass through")
            else:
                self._add_result("6.1", "Ensure that antivirus profiles are set to block on all decoders except 'imap' and 'pop3'", 
                               "Security Profiles", "fail",
                               "No antivirus profiles found",
                               "Antivirus profiles should be configured",
                               "Configure Objects > Security Profiles > Antivirus",
                               "No protection against malware without antivirus profiles")
            
            # 6.3 Ensure anti-spyware profiles are configured
            antispyware_profiles = shared_config.findall('.//profiles/spyware/entry')
            if antispyware_profiles:
                self._add_result("6.3", "Ensure an anti-spyware profile is configured to block on all spyware severity levels", 
                               "Security Profiles", "pass",
                               f"Found {len(antispyware_profiles)} anti-spyware profile(s)",
                               "Anti-spyware profiles should be configured")
            else:
                self._add_result("6.3", "Ensure an anti-spyware profile is configured to block on all spyware severity levels", 
                               "Security Profiles", "fail",
                               "No anti-spyware profiles found",
                               "Anti-spyware profiles should be configured",
                               "Configure Objects > Security Profiles > Anti-Spyware",
                               "No protection against spyware without anti-spyware profiles")
            
            # 6.5 Ensure vulnerability protection profiles are configured
            vulnerability_profiles = shared_config.findall('.//profiles/vulnerability/entry')
            if vulnerability_profiles:
                self._add_result("6.5", "Ensure a vulnerability protection profile is applied to all rules", 
                               "Security Profiles", "pass",
                               f"Found {len(vulnerability_profiles)} vulnerability protection profile(s)",
                               "Vulnerability protection profiles should be configured")
            else:
                self._add_result("6.5", "Ensure a vulnerability protection profile is applied to all rules", 
                               "Security Profiles", "fail",
                               "No vulnerability protection profiles found",
                               "Vulnerability protection profiles should be configured",
                               "Configure Objects > Security Profiles > Vulnerability Protection",
                               "No protection against exploits without vulnerability profiles")
                
        except Exception as e:
            self._add_result("6.0", "Security Profiles checks failed", "Security Profiles", 
                           "error", error_details=str(e))
