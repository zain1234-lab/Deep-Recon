import logging
import requests
from typing import Dict, Any, List, Optional
from pathlib import Path
import json
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
import re

logger = logging.getLogger('recon_tool')

class DeepSeekAnalyzer:
    def __init__(self, api_key: str):
        if not api_key or api_key.strip() == "":
            raise ValueError("DeepSeek API key cannot be empty")
        self.api_key = api_key
        self.base_url = "https://api.deepseek.com/v1/chat/completions"
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

    def analyze_findings(self, findings: Dict[str, Any], analysis_type: str = "security") -> Dict[str, Any]:
        """Analyze reconnaissance findings using DeepSeek API with improved error handling and retries"""
        import time
        max_retries = 3
        retry_delay = 5  # seconds
        
        try:
            filtered_findings = self._filter_successful_findings(findings)
            
            if not filtered_findings or len(filtered_findings) <= 1:  # Only target key
                return {"error": "No valid findings to analyze", "analysis": "Insufficient data for AI analysis"}
            
            prompt = self._create_analysis_prompt(filtered_findings, analysis_type)
            
            payload = {
                "model": "deepseek-chat",
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert analyzing reconnaissance data. Provide detailed, actionable insights and recommendations."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "max_tokens": 2000,
                "temperature": 0.3
            }
            
            for attempt in range(max_retries):
                try:
                    response = requests.post(self.base_url, headers=self.headers, json=payload, timeout=30)
                    
                    if response.status_code == 401:
                        return {"error": "Invalid API key", "analysis": "API authentication failed"}
                    elif response.status_code == 429:
                        if attempt < max_retries - 1:
                            time.sleep(retry_delay)
                            continue
                        return {"error": "Rate limit exceeded", "analysis": "API rate limit reached"}
                    elif response.status_code != 200:
                        return {"error": f"API error: {response.status_code}", "analysis": "API request failed"}
                    
                    response.raise_for_status()
                    
                    result = response.json()
                    if 'choices' not in result or not result['choices']:
                        return {"error": "Invalid API response", "analysis": "No analysis content received"}
                    
                    analysis = result['choices'][0]['message']['content']
                    return self._parse_analysis(analysis)
                except requests.exceptions.Timeout:
                    logger.warning(f"DeepSeek API timeout on attempt {attempt + 1}")
                    if attempt == max_retries - 1:
                        return {"error": "API timeout", "analysis": "AI analysis timed out"}
                except requests.exceptions.ConnectionError:
                    logger.warning(f"DeepSeek API connection error on attempt {attempt + 1}")
                    if attempt == max_retries - 1:
                        return {"error": "Connection failed", "analysis": "Unable to connect to AI service"}
                except Exception as e:
                    logger.warning(f"DeepSeek API error on attempt {attempt + 1}: {e}")
                    if attempt == max_retries - 1:
                        return {"error": str(e), "analysis": "AI analysis unavailable"}
                    time.sleep(retry_delay)
        except Exception as e:
            logger.error(f"DeepSeek analysis failed: {e}")
            return {"error": str(e), "analysis": "AI analysis unavailable"}

    def _filter_successful_findings(self, findings: Dict[str, Any]) -> Dict[str, Any]:
        """Filter out failed findings and 404 errors"""
        filtered = {"target": findings.get("target", "Unknown")}
        
        for key, value in findings.items():
            if key == "target":
                continue
                
            # Skip if value indicates failure
            if self._is_failed_finding(value):
                logger.debug(f"Filtering out failed finding: {key}")
                continue
                
            filtered[key] = value
            
        return filtered

    def _is_failed_finding(self, value: Any) -> bool:
        """Check if a finding indicates failure or error"""
        if not value:
            return True
            
        value_str = str(value).lower()
        
        # Check for common error indicators
        error_indicators = [
            "404", "not found", "error", "failed", "timeout", 
            "connection refused", "unable to connect", "no response",
            "invalid", "access denied", "forbidden", "503", "500"
        ]
        
        for indicator in error_indicators:
            if indicator in value_str:
                return True
                
        # Check for empty or minimal responses
        if isinstance(value, dict):
            if not value or all(not v for v in value.values()):
                return True
        elif isinstance(value, list):
            if not value:
                return True
        elif isinstance(value, str):
            if len(value.strip()) < 10:  # Very short responses likely errors
                return True
                
        return False

    def _create_analysis_prompt(self, findings: Dict[str, Any], analysis_type: str) -> str:
        """Create analysis prompt based on findings and type with enhanced IDS-like detection"""
        sanitized_findings = sanitize_output(findings)
        
        if analysis_type == "security":
            return f"""
            As an advanced Intrusion Detection System, analyze the following reconnaissance findings for security threats, vulnerabilities, and potential intrusion attempts:
            
            Target: {findings.get('target', 'Unknown')}
            Findings: {json.dumps(sanitized_findings, indent=2)}
            
            Please provide a detailed security analysis including:
            1. Critical security threats and vulnerabilities detected
                - Potential intrusion attempts or suspicious patterns
                - Exposed services and vulnerabilities
                - Misconfigurations that could lead to compromise
            2. Risk Assessment
                - Severity (Critical/High/Medium/Low) for each finding
                - Likelihood of exploitation
                - Potential impact on system security
            3. Detailed Remediation Steps
                - Immediate actions needed to prevent intrusion
                - Security hardening recommendations
                - Configuration fixes and updates required
            4. Attack Vector Analysis
                - Identified attack paths and entry points
                - Potential exploitation scenarios
                - Lateral movement possibilities
            5. Priority-based Action Plan
                - Emergency fixes (immediate action required)
                - Short-term remediation steps
                - Long-term security improvements
            
            Format your response as structured JSON with sections: threats_detected, risk_assessment, remediation_steps, attack_vectors, action_plan, with clear categorization and priority levels.
            """
        elif analysis_type == "comprehensive":
            return f"""
            As an advanced Security Information and Event Management (SIEM) system, provide a comprehensive analysis of the following reconnaissance data:
            
            Target: {findings.get('target', 'Unknown')}
            Findings: {json.dumps(sanitized_findings, indent=2)}
            
            Please analyze and provide:
            1. Infrastructure Analysis
                - Technology stack vulnerabilities
                - Architecture security assessment
                - Service exposure analysis
            2. Threat Detection
                - Suspicious patterns or behaviors
                - Potential security incidents
                - Anomaly detection results
            3. Security Posture Evaluation
                - Overall security stance
                - Defense-in-depth assessment
                - Security control effectiveness
            4. Risk Analysis
                - Information disclosure threats
                - Attack surface evaluation
                - Potential business impact
            5. Compliance Status
                - Security standard adherence
                - Regulatory compliance gaps
                - Required security controls
            6. Actionable Intelligence
                - Critical security alerts
                - Recommended monitoring rules
                - Security improvement roadmap
            
            Format your response as a comprehensive security analysis with clear sections for threats, risks, compliance, and actionable recommendations.
            """
        else:
            return f"Analyze these reconnaissance findings for security threats and intrusion indicators: {json.dumps(sanitized_findings, indent=2)}"

    def _parse_analysis(self, analysis: str) -> Dict[str, Any]:
        """Parse AI analysis response into structured format with enhanced IDS insights"""
        try:
            # Try to extract JSON if present
            json_match = re.search(r'\{.*\}', analysis, re.DOTALL)
            if json_match:
                try:
                    parsed = json.loads(json_match.group())
                    
                    # Validate and structure the parsed data
                    structured_analysis = {
                        "threats_detected": parsed.get("threats_detected", []),
                        "risk_assessment": parsed.get("risk_assessment", {}),
                        "remediation_steps": parsed.get("remediation_steps", []),
                        "attack_vectors": parsed.get("attack_vectors", []),
                        "action_plan": parsed.get("action_plan", {}),
                        "security_score": self._calculate_security_score(parsed),
                        "raw_analysis": analysis
                    }
                    
                    # Add threat summary
                    critical_threats = [t for t in structured_analysis["threats_detected"] 
                                     if isinstance(t, dict) and t.get("severity", "").lower() == "critical"]
                    high_threats = [t for t in structured_analysis["threats_detected"] 
                                  if isinstance(t, dict) and t.get("severity", "").lower() == "high"]
                    
                    structured_analysis["threat_summary"] = {
                        "critical_count": len(critical_threats),
                        "high_count": len(high_threats),
                        "total_threats": len(structured_analysis["threats_detected"]),
                        "immediate_actions_required": len(critical_threats) > 0 or len(high_threats) > 0
                    }
                    
                    return structured_analysis
                except json.JSONDecodeError:
                    logger.warning("Failed to parse JSON from AI response, falling back to text analysis")
        except Exception as e:
            logger.warning(f"Error during analysis parsing: {e}")
        
        # Fallback to enhanced text analysis
        return self._fallback_text_analysis(analysis)

    def _calculate_security_score(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate a security score based on the AI analysis results"""
        score = 100  # Start with perfect score
        threat_weights = {"critical": 20, "high": 10, "medium": 5, "low": 2}
        
        # Reduce score based on detected threats
        threats = parsed_data.get("threats_detected", [])
        for threat in threats:
            if isinstance(threat, dict):
                severity = threat.get("severity", "").lower()
                score -= threat_weights.get(severity, 0)
        
        # Ensure score stays within 0-100 range
        score = max(0, min(100, score))
        
        return {
            "score": score,
            "rating": "Critical" if score < 40 else "High Risk" if score < 60 
                     else "Medium Risk" if score < 80 else "Low Risk",
            "factors": {
                "threat_count": len(threats),
                "severity_distribution": {
                    severity: len([t for t in threats 
                                 if isinstance(t, dict) and t.get("severity", "").lower() == severity])
                    for severity in threat_weights.keys()
                }
            }
        }

    def _fallback_text_analysis(self, analysis: str) -> Dict[str, Any]:
        """Enhanced fallback analysis when JSON parsing fails"""
        # Extract key sections using regex patterns
        threats = re.findall(r'(?i)(?:critical|high|medium|low)(?:\s+risk)?\s*[:-]\s*([^\n]+)', analysis)
        remediation = re.findall(r'(?i)(?:recommendation|remediation|fix)[:\s-]+([^\n]+)', analysis)
        
        return {
            "raw_analysis": analysis,
            "summary": analysis[:500] + "..." if len(analysis) > 500 else analysis,
            "extracted_insights": {
                "potential_threats": threats,
                "remediation_suggestions": remediation,
                "analysis_length": len(analysis),
                "timestamp": datetime.now().isoformat()
            }
        }

def sanitize_output(data: Dict) -> Dict:
    """Remove sensitive information from output"""
    sensitive_keys = ['proxies', 'api_key', 'password', 'token', 'secret']
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            if isinstance(key, str) and any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = 'REDACTED'
            elif isinstance(value, dict):
                sanitized[key] = sanitize_output(value)
            elif isinstance(value, list):
                sanitized[key] = [sanitize_output(item) if isinstance(item, dict) else item for item in value]
            else:
                sanitized[key] = value
        return sanitized
    return data

def filter_successful_findings(findings: Dict[str, Any]) -> Dict[str, Any]:
    """Filter out failed findings for report generation"""
    filtered = {"target": findings.get("target", "Unknown")}
    
    for key, value in findings.items():
        if key == "target":
            continue
            
        # Skip if value indicates failure
        if is_failed_finding(value):
            logger.debug(f"Excluding failed finding from report: {key}")
            continue
            
        filtered[key] = value
        
    return filtered

def is_failed_finding(value: Any) -> bool:
    """Check if a finding indicates failure or error"""
    if not value:
        return True
        
    value_str = str(value).lower()
    
    # Check for common error indicators
    error_indicators = [
        "404", "not found", "error", "failed", "timeout", 
        "connection refused", "unable to connect", "no response",
        "invalid", "access denied", "forbidden", "503", "500",
        "timed out", "connection error", "dns resolution failed"
    ]
    
    for indicator in error_indicators:
        if indicator in value_str:
            return True
            
    # Check for empty or minimal responses
    if isinstance(value, dict):
        if not value or all(not v for v in value.values()):
            return True
    elif isinstance(value, list):
        if not value:
            return True
    elif isinstance(value, str):
        if len(value.strip()) < 5:  # Very short responses likely errors
            return True
            
    return False
    
def calculate_risk_score(findings: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate comprehensive risk score with enhanced IDS-like detection"""
    # Filter successful findings first
    filtered_findings = filter_successful_findings(findings)
    
    risk_factors = {
        'network_exposure': {
            'score': 0,
            'details': [],
            'weight': 1.5  # Higher weight for network-related risks
        },
        'service_vulnerabilities': {
            'score': 0,
            'details': [],
            'weight': 2.0  # Highest weight for vulnerabilities
        },
        'misconfigurations': {
            'score': 0,
            'details': [],
            'weight': 1.2
        },
        'information_disclosure': {
            'score': 0,
            'details': [],
            'weight': 1.3
        },
        'security_controls': {
            'score': 0,
            'details': [],
            'weight': 1.4
        }
    }
    
    # Analyze different modules for risk factors with enhanced detection
    for module, data in filtered_findings.items():
        if module == 'target':
            continue
            
        # Network exposure analysis
        if any(x in module.lower() for x in ['ports', 'scan', 'network']):
            if isinstance(data, dict):
                # Analyze open ports
                if 'open_ports' in str(data):
                    ports = str(data).count('open_ports')
                    risk_factors['network_exposure']['score'] += ports * 5
                    risk_factors['network_exposure']['details'].append(
                        f"Found {ports} open ports - increasing attack surface"
                    )
                
                # Check for high-risk ports
                high_risk_ports = ['21', '23', '445', '3389', '5432', '6379', '27017']
                for port in high_risk_ports:
                    if port in str(data):
                        risk_factors['network_exposure']['score'] += 15
                        risk_factors['network_exposure']['details'].append(
                            f"High-risk port {port} detected"
                        )
        
        # Service vulnerability analysis
        if any(x in module.lower() for x in ['vuln', 'cve', 'security']):
            if isinstance(data, dict):
                # Count severe vulnerabilities
                severity_scores = {
                    'critical': 25,
                    'high': 15,
                    'medium': 8,
                    'low': 3
                }
                
                for severity, score in severity_scores.items():
                    count = str(data).lower().count(severity)
                    if count > 0:
                        risk_factors['service_vulnerabilities']['score'] += count * score
                        risk_factors['service_vulnerabilities']['details'].append(
                            f"Found {count} {severity} severity vulnerabilities"
                        )
        
        # Security control analysis
        if 'headers' in module.lower():
            if isinstance(data, dict):
                # Check for security headers
                security_headers = {
                    'x-frame-options': 5,
                    'x-content-type-options': 5,
                    'strict-transport-security': 8,
                    'content-security-policy': 10,
                    'x-xss-protection': 5
                }
                
                for header, importance in security_headers.items():
                    if header not in str(data).lower():
                        risk_factors['security_controls']['score'] += importance
                        risk_factors['security_controls']['details'].append(
                            f"Missing {header} security header"
                        )
        
        # SSL/TLS analysis
        if any(x in module.lower() for x in ['ssl', 'tls']):
            if isinstance(data, dict):
                if 'error' in str(data).lower():
                    risk_factors['security_controls']['score'] += 20
                    risk_factors['security_controls']['details'].append(
                        "SSL/TLS configuration issues detected"
                    )
                
                # Check for weak protocols
                weak_protocols = ['sslv2', 'sslv3', 'tlsv1.0', 'tlsv1.1']
                for protocol in weak_protocols:
                    if protocol in str(data).lower():
                        risk_factors['security_controls']['score'] += 15
                        risk_factors['security_controls']['details'].append(
                            f"Weak protocol {protocol} enabled"
                        )
        
        # Information disclosure analysis
        if any(x in module.lower() for x in ['info', 'disclosure', 'leak']):
            if isinstance(data, dict):
                sensitive_patterns = [
                    'version', 'internal', 'private', 'debug',
                    'backup', 'config', 'admin', 'test'
                ]
                for pattern in sensitive_patterns:
                    if pattern in str(data).lower():
                        risk_factors['information_disclosure']['score'] += 8
                        risk_factors['information_disclosure']['details'].append(
                            f"Potential information disclosure: {pattern}"
                        )
    
    # Calculate weighted total score
    total_score = sum(
        factor['score'] * factor['weight']
        for factor in risk_factors.values()
    )
    
    # Normalize to 0-100 range
    max_possible_score = 500  # Theoretical maximum
    normalized_score = min((total_score / max_possible_score) * 100, 100)
    
    # Determine risk level with more granular categories
    risk_level = (
        "CRITICAL" if normalized_score >= 80
        else "HIGH" if normalized_score >= 60
        else "MEDIUM" if normalized_score >= 40
        else "LOW" if normalized_score >= 20
        else "INFO"
    )
    
    return {
        'total_score': round(normalized_score, 2),
        'risk_level': risk_level,
        'factors': {
            name: {
                'score': round(data['score'], 2),
                'weighted_score': round(data['score'] * data['weight'], 2),
                'details': data['details']
            }
            for name, data in risk_factors.items()
        },
        'summary': {
            'highest_risk_factors': sorted(
                [
                    (name, data['score'] * data['weight'])
                    for name, data in risk_factors.items()
                    if data['score'] > 0
                ],
                key=lambda x: x[1],
                reverse=True
            )[:3],
            'total_findings': sum(
                len(data['details'])
                for data in risk_factors.values()
            ),
            'immediate_action_required': normalized_score >= 60
        }
    }

def generate_advanced_report(findings: Dict[str, Any], ai_analysis: Dict[str, Any] = None) -> str:
    """Generate advanced security-focused report with enhanced IDS insights"""
    # Filter successful findings
    filtered_findings = filter_successful_findings(findings)
    
    target = filtered_findings.get('target', 'Unknown')
    timestamp = datetime.now().isoformat()
    risk_assessment = calculate_risk_score(filtered_findings)
    
    report = [
        f"# ADVANCED SECURITY ASSESSMENT REPORT",
        f"## Target: {target}",
        f"## Generated: {timestamp}",
        f"## Risk Level: {risk_assessment['risk_level']} ({risk_assessment['total_score']}/100)",
        "",
        "---",
        "",
        "## ⚠️ EXECUTIVE SUMMARY",
        f"This report presents a comprehensive security assessment for {target}, combining advanced reconnaissance with IDS-like threat detection.",
        "",
        f"🎯 Overall Risk Level: {risk_assessment['risk_level']}",
        f"📊 Security Score: {risk_assessment['total_score']}/100",
        "🚨 Immediate Action Required: " + ("YES" if risk_assessment.get('summary', {}).get('immediate_action_required', False) else "NO"),
        "",
        "### Key Findings",
    ]
    
    # Add highest risk factors
    if risk_assessment.get('summary', {}).get('highest_risk_factors'):
        report.append("Top Risk Factors:")
        for factor, score in risk_assessment['summary']['highest_risk_factors']:
            report.append(f"- {factor.replace('_', ' ').title()}: {round(score, 2)} points")
    
    report.extend([
        "",
        "---",
        "",
        "## 🔍 DETAILED RISK ASSESSMENT"
    ])
    
    # Add detailed risk factors
    for factor_name, factor_data in risk_assessment['factors'].items():
        if factor_data['score'] > 0 or factor_data['details']:
            report.extend([
                f"### {factor_name.replace('_', ' ').title()}",
                f"Score: {factor_data['score']} (Weight: {factor_data.get('weight', 1.0)}x)",
                f"Weighted Impact: {factor_data['weighted_score']}",
                "",
                "Findings:"
            ])
            
            for detail in factor_data['details']:
                report.append(f"- {detail}")
            
            report.append("")
    
    report.extend([
        "---",
        "",
        "## 🛡️ SECURITY ANALYSIS",
        ""
    ])
    
    # Add AI analysis if available and valid
    if ai_analysis and 'error' not in ai_analysis:
        if 'vulnerabilities' in ai_analysis:
            report.extend([
                "### AI-IDENTIFIED VULNERABILITIES",
                json.dumps(ai_analysis.get('vulnerabilities', {}), indent=2),
                "",
                "### SECURITY RECOMMENDATIONS",
                json.dumps(ai_analysis.get('recommendations', {}), indent=2),
                ""
            ])
        elif 'raw_analysis' in ai_analysis:
            report.extend([
                "### AI SECURITY ANALYSIS",
                ai_analysis['raw_analysis'],
                ""
            ])
    
    # Add technical findings (security-focused)
    security_modules = []
    for module, data in filtered_findings.items():
        if module != 'target':
            # Focus on security-relevant modules
            if any(keyword in module.lower() for keyword in ['port', 'ssl', 'header', 'vuln', 'security', 'scan']):
                security_modules.append((module, data))
    
    if security_modules:
        report.append("### SECURITY-RELEVANT TECHNICAL FINDINGS")
        for module, data in security_modules:
            report.extend([
                f"#### {module.replace('_', ' ').upper()}",
                json.dumps(sanitize_output(data), indent=2),
                ""
            ])
    
    # Add other findings in summary
    other_modules = [(m, d) for m, d in filtered_findings.items() 
                    if m != 'target' and (m, d) not in security_modules]
    
    if other_modules:
        report.extend([
            "### OTHER RECONNAISSANCE FINDINGS",
            f"Additional {len(other_modules)} modules executed with successful results.",
            "Contact security team for detailed technical data if needed.",
            ""
        ])
    
    report.extend([
        "---",
        "## COMPLIANCE & RECOMMENDATIONS",
        "- This assessment follows OWASP security testing guidelines",
        "- Critical findings should be addressed within 30 days",
        "- Regular security assessments recommended quarterly",
        "- Manual penetration testing advised for high-risk findings",
        "",
        f"Report generated by Enhanced Recon Tool v2.0 - {timestamp}"
    ])
    
    return '\n'.join(report)

def generate_comprehensive_report(findings: Dict[str, Any], ai_analysis: Dict[str, Any] = None) -> str:
    """Generate comprehensive technical report with all findings"""
    # Filter successful findings
    filtered_findings = filter_successful_findings(findings)
    
    target = filtered_findings.get('target', 'Unknown')
    timestamp = datetime.now().isoformat()
    
    successful_modules = len([k for k in filtered_findings.keys() if k != 'target'])
    total_modules = len([k for k in findings.keys() if k != 'target'])
    failed_modules = total_modules - successful_modules
    
    report = [
        f"# COMPREHENSIVE RECONNAISSANCE REPORT",
        f"## Target: {target}",
        f"## Generated: {timestamp}",
        f"## Success Rate: {successful_modules}/{total_modules} modules ({round(successful_modules/total_modules*100 if total_modules > 0 else 0, 1)}%)",
        "",
        "This report contains comprehensive reconnaissance findings and technical analysis.",
        "",
        "---",
        ""
    ]
    
    # Add AI comprehensive analysis if available
    if ai_analysis and 'error' not in ai_analysis:
        report.extend([
            "## AI-POWERED COMPREHENSIVE ANALYSIS",
            ai_analysis.get('raw_analysis', 'Comprehensive analysis not available'),
            "",
            "---",
            ""
        ])
    
    # Add summary of findings
    report.extend([
        "## RECONNAISSANCE SUMMARY",
        f"- Target analyzed: {target}",
        f"- Successful modules: {successful_modules}",
        f"- Failed/Error modules: {failed_modules}",
        f"- Data collection timestamp: {timestamp}",
        "",
        "---",
        ""
    ])
    
    # Add all successful findings with detailed breakdown
    report.append("## DETAILED FINDINGS BREAKDOWN")
    
    for module, data in filtered_findings.items():
        if module != 'target':
            report.extend([
                f"### {module.replace('_', ' ').title()} Module Results",
                "",
                "#### Processed Data:",
                "```json",
                json.dumps(sanitize_output(data), indent=2),
                "```",
                "",
                "---",
                ""
            ])
    
    # Add failed modules summary if any
    if failed_modules > 0:
        failed_module_names = []
        for key, value in findings.items():
            if key != 'target' and is_failed_finding(value):
                failed_module_names.append(key.replace('_', ' ').title())
        
        report.extend([
            "## FAILED/INCOMPLETE MODULES",
            f"The following {failed_modules} modules did not return valid data:",
            "",
        ])
        
        for module_name in failed_module_names:
            report.append(f"- {module_name}")
        
        report.extend([
            "",
            "These modules may have failed due to:",
            "- Network connectivity issues",
            "- Target service unavailability", 
            "- Access restrictions or firewalls",
            "- Service-specific errors or timeouts",
            "",
            "---",
            ""
        ])
    
    report.extend([
        "## TECHNICAL METADATA",
        f"- Total reconnaissance modules: {total_modules}",
        f"- Successful data collection: {successful_modules}",
        f"- Success rate: {round(successful_modules/total_modules*100 if total_modules > 0 else 0, 1)}%",
        f"- Report generation timestamp: {timestamp}",  
        f"- Data sanitization: Applied",
        f"- Failed findings: Excluded from analysis",
        "",
        "## DISCLAIMER",
        "This report is generated for authorized security testing purposes only.",
        "Ensure proper authorization before conducting reconnaissance activities.",
        "Only successful reconnaissance results are included in detailed analysis.",
        "",
        f"Generated by Enhanced Recon Tool v2.0"
    ])
    
    return '\n'.join(report)

def generate_html_report(findings: Dict[str, Any], template_dir: str, report_type: str = "advanced", ai_analysis: Dict[str, Any] = None) -> str:
    """Generate HTML report with enhanced IDS insights and modern styling"""
    try:
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template('enhanced_report.html')
        
        # Filter successful findings
        filtered_findings = filter_successful_findings(findings)
        risk_assessment = calculate_risk_score(filtered_findings)
        
        successful_modules = len([k for k in filtered_findings.keys() if k != 'target'])
        total_modules = len([k for k in findings.keys() if k != 'target'])
        
        # Prepare risk data for visualization
        risk_data = {
            'labels': [],
            'scores': [],
            'weights': [],
            'weighted_scores': [],
            'details_count': []
        }
        
        for factor_name, factor_data in risk_assessment['factors'].items():
            risk_data['labels'].append(factor_name.replace('_', ' ').title())
            risk_data['scores'].append(factor_data['score'])
            risk_data['weights'].append(factor_data.get('weight', 1.0))
            risk_data['weighted_scores'].append(factor_data['weighted_score'])
            risk_data['details_count'].append(len(factor_data.get('details', [])))
        
        # Prepare threat summary
        threat_summary = {
            'total_threats': risk_assessment.get('summary', {}).get('total_findings', 0),
            'critical_issues': len([
                d for f in risk_assessment['factors'].values()
                for d in f.get('details', [])
                if 'critical' in d.lower()
            ]),
            'high_risk_issues': len([
                d for f in risk_assessment['factors'].values()
                for d in f.get('details', [])
                if 'high' in d.lower()
            ]),
            'immediate_action': risk_assessment.get('summary', {}).get('immediate_action_required', False)
        }
        
        return template.render(
            target=filtered_findings.get('target', 'Unknown'),
            timestamp=datetime.now().isoformat(),
            findings=sanitize_output(filtered_findings),
            report_type=report_type,
            risk_assessment=risk_assessment,
            risk_data=risk_data,
            threat_summary=threat_summary,
            ai_analysis=ai_analysis or {},
            module_count=successful_modules,
            total_modules=total_modules,
            success_rate=round(successful_modules/total_modules*100 if total_modules > 0 else 0, 1),
            has_ai_analysis=ai_analysis is not None and 'error' not in ai_analysis,
            css_framework="tailwind",  # Using Tailwind CSS for modern styling
            icons={  # Font Awesome icons for better visualization
                'warning': 'fas fa-exclamation-triangle',
                'info': 'fas fa-info-circle',
                'success': 'fas fa-check-circle',
                'error': 'fas fa-times-circle',
                'security': 'fas fa-shield-alt',
                'network': 'fas fa-network-wired',
                'vulnerability': 'fas fa-bug',
                'config': 'fas fa-cogs',
                'disclosure': 'fas fa-user-secret'
            }
        )
    except Exception as e:
        logger.error(f"HTML report generation failed: {e}")
        # Enhanced fallback with basic styling
        filtered_findings = filter_successful_findings(findings)
        risk_assessment = calculate_risk_score(filtered_findings)
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Assessment - {filtered_findings.get('target', 'Unknown')}</title>
            <script src="https://cdn.tailwindcss.com"></script>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
        </head>
        <body class="bg-gray-100 p-8">
            <div class="max-w-4xl mx-auto bg-white rounded-lg shadow-lg p-6">
                <h1 class="text-3xl font-bold mb-4">Security Assessment Report</h1>
                <h2 class="text-xl mb-2">Target: {filtered_findings.get('target', 'Unknown')}</h2>
                <div class="mb-4 p-4 {'bg-red-100 text-red-700' if risk_assessment['risk_level'] in ['HIGH', 'CRITICAL'] else 'bg-yellow-100 text-yellow-700' if risk_assessment['risk_level'] == 'MEDIUM' else 'bg-green-100 text-green-700'} rounded">
                    <p class="font-bold">Risk Level: {risk_assessment['risk_level']}</p>
                    <p>Security Score: {risk_assessment['total_score']}/100</p>
                </div>
                <div class="mb-4">
                    <h3 class="text-lg font-semibold mb-2">Findings Summary</h3>
                    <pre class="bg-gray-50 p-4 rounded overflow-auto">{json.dumps(sanitize_output(filtered_findings), indent=2)}</pre>
                </div>
                <footer class="text-sm text-gray-500 mt-4">
                    Generated: {datetime.now().isoformat()}<br>
                    Note: This is a fallback report with limited formatting.
                </footer>
            </div>
        </body>
        </html>
        """

def enhanced_report_generator(
    findings: Dict[str, Any], 
    output_dir: str, 
    formats: List[str] = ['text', 'html', 'json'],
    template_dir: str = 'templates',
    deepseek_api_key: str = None,
    report_types: List[str] = ['advanced', 'comprehensive']
) -> Dict[str, str]:
    """
    Enhanced report generator with AI analysis and multiple report types
    """
    try:
        target = findings.get('target', 'unknown')
        logger.info(f"Generating enhanced reports for {target}")

        output_dir = Path(output_dir).resolve()
        output_dir.mkdir(exist_ok=True)
        report_files = {}

        # Initialize AI analyzer if API key provided and valid
        ai_analyzer = None
        ai_analysis = {}
        
        if deepseek_api_key and deepseek_api_key.strip():
            try:
                ai_analyzer = DeepSeekAnalyzer(deepseek_api_key)
                logger.info("DeepSeek API integration enabled")
                
                # Get AI analysis for both report types
                ai_analysis['security'] = ai_analyzer.analyze_findings(findings, "security")
                ai_analysis['comprehensive'] = ai_analyzer.analyze_findings(findings, "comprehensive")
                
                # Log AI analysis status
                for analysis_type, analysis_result in ai_analysis.items():
                    if 'error' in analysis_result:
                        logger.warning(f"AI {analysis_type} analysis failed: {analysis_result['error']}")
                    else:
                        logger.info(f"AI {analysis_type} analysis completed successfully")
                
            except Exception as e:
                logger.warning(f"AI analysis initialization failed, continuing without: {e}")

        # Generate reports based on requested types
        for report_type in report_types:
            type_suffix = f"_{report_type}"
            
            if 'text' in formats:
                if report_type == 'advanced':
                    text_report = generate_advanced_report(findings, ai_analysis.get('security'))
                else:
                    text_report = generate_comprehensive_report(findings, ai_analysis.get('comprehensive'))
                    
                text_path = output_dir / f"{target}_report{type_suffix}.txt"
                with open(text_path, 'w', encoding='utf-8') as f:
                    f.write(text_report)
                report_files[f'text_{report_type}'] = str(text_path)
                logger.debug(f"Generated {report_type} text report: {text_path}")

            if 'html' in formats:
                html_report = generate_html_report(
                    findings, 
                    template_dir, 
                    report_type, 
                    ai_analysis.get('security' if report_type == 'advanced' else 'comprehensive')
                )
                html_path = output_dir / f"{target}_report{type_suffix}.html"
                with open(html_path, 'w', encoding='utf-8') as f:
                    f.write(html_report)
                report_files[f'html_{report_type}'] = str(html_path)
                logger.debug(f"Generated {report_type} HTML report: {html_path}")

            if 'json' in formats:
                # Filter findings for JSON export
                filtered_findings = filter_successful_findings(findings)
                
                json_data = {
                    'metadata': {
                        'target': target,
                        'timestamp': datetime.now().isoformat(),
                        'report_type': report_type,
                        'risk_assessment': calculate_risk_score(filtered_findings),
                        'successful_modules': len([k for k in filtered_findings.keys() if k != 'target']),
                        'total_modules': len([k for k in findings.keys() if k != 'target'])
                    },
                    'findings': sanitize_output(filtered_findings),
                    'ai_analysis': ai_analysis.get('security' if report_type == 'advanced' else 'comprehensive', {})
                }
                
                json_path = output_dir / f"{target}_report{type_suffix}.json"
                with open(json_path, 'w', encoding='utf-8') as f:
                    json.dump(json_data, f, indent=2)
                report_files[f'json_{report_type}'] = str(json_path)
                logger.debug(f"Generated {report_type} JSON report: {json_path}")

        logger.info(f"Enhanced report generation completed for {target}")
        logger.info(f"Generated {len(report_files)} report files")
        
        return report_files

    except Exception as e:
        logger.error(f"Enhanced report generation failed for {target}: {e}")
        raise RuntimeError(f"Enhanced report generation failed: {e}")

# Backward compatibility - keep original function
def report_generator(findings: Dict[str, Any], output_dir: str, formats: list[str] = ['text', 'html', 'json'], template_dir: str = 'templates') -> Dict[str, str]:
    """Original report generator for backward compatibility"""
    return enhanced_report_generator(
        findings=findings,
        output_dir=output_dir,
        formats=formats,
        template_dir=template_dir,
        report_types=['comprehensive']  # Default to comprehensive for compatibility
    )
