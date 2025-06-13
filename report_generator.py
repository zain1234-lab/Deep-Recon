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
        """Analyze reconnaissance findings using DeepSeek API"""
        try:
            # Filter out failed findings before analysis
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
            
            response = requests.post(self.base_url, headers=self.headers, json=payload, timeout=30)
            
            if response.status_code == 401:
                return {"error": "Invalid API key", "analysis": "API authentication failed"}
            elif response.status_code == 429:
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
            logger.error("DeepSeek API timeout")
            return {"error": "API timeout", "analysis": "AI analysis timed out"}
        except requests.exceptions.ConnectionError:
            logger.error("DeepSeek API connection error")
            return {"error": "Connection failed", "analysis": "Unable to connect to AI service"}
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
        """Create analysis prompt based on findings and type"""
        sanitized_findings = sanitize_output(findings)
        
        if analysis_type == "security":
            return f"""
            Analyze the following reconnaissance findings for security vulnerabilities and risks:
            
            Target: {findings.get('target', 'Unknown')}
            Findings: {json.dumps(sanitized_findings, indent=2)}
            
            Please provide:
            1. Critical security vulnerabilities identified
            2. Risk assessment (High/Medium/Low) for each finding
            3. Specific recommendations for remediation
            4. Attack vectors that could be exploited
            5. Priority order for addressing issues
            
            Format your response as structured JSON with sections: vulnerabilities, risks, recommendations, attack_vectors, priorities.
            """
        elif analysis_type == "comprehensive":
            return f"""
            Provide a comprehensive analysis of the following reconnaissance data:
            
            Target: {findings.get('target', 'Unknown')}
            Findings: {json.dumps(sanitized_findings, indent=2)}
            
            Please analyze:
            1. Technology stack and architecture insights
            2. Security posture assessment
            3. Information disclosure risks
            4. Business intelligence opportunities
            5. Technical recommendations
            6. Compliance considerations
            
            Format your response as structured analysis with clear sections and actionable insights.
            """
        else:
            return f"Analyze these reconnaissance findings: {json.dumps(sanitized_findings, indent=2)}"

    def _parse_analysis(self, analysis: str) -> Dict[str, Any]:
        """Parse AI analysis response into structured format"""
        try:
            # Try to extract JSON if present
            json_match = re.search(r'\{.*\}', analysis, re.DOTALL)
            if json_match:
                parsed = json.loads(json_match.group())
                return {**parsed, "raw_analysis": analysis}
        except:
            pass
        
        # Fallback to text analysis
        return {
            "raw_analysis": analysis,
            "summary": analysis[:500] + "..." if len(analysis) > 500 else analysis
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
    """Calculate overall risk score based on findings"""
    # Filter successful findings first
    filtered_findings = filter_successful_findings(findings)
    
    risk_factors = {
        'open_ports': 0,
        'outdated_software': 0,
        'misconfigurations': 0,
        'information_disclosure': 0,
        'ssl_issues': 0
    }
    
    total_score = 0
    max_score = 100
    
    # Analyze different modules for risk factors
    for module, data in filtered_findings.items():
        if module == 'target':
            continue
            
        if 'ports' in module.lower() or 'scan' in module.lower():
            if isinstance(data, dict) and 'open_ports' in str(data):
                risk_factors['open_ports'] += 10
        
        if 'headers' in module.lower():
            if isinstance(data, dict):
                # Check for security headers
                security_headers = ['x-frame-options', 'x-content-type-options', 'strict-transport-security']
                missing_headers = sum(1 for header in security_headers if header not in str(data).lower())
                risk_factors['misconfigurations'] += missing_headers * 5
        
        if 'ssl' in module.lower() or 'tls' in module.lower():
            if isinstance(data, dict) and 'error' in str(data).lower():
                risk_factors['ssl_issues'] += 15
    
    total_score = sum(risk_factors.values())
    risk_level = "LOW" if total_score < 20 else "MEDIUM" if total_score < 50 else "HIGH"
    
    return {
        'total_score': min(total_score, max_score),
        'risk_level': risk_level,
        'factors': risk_factors
    }

def generate_advanced_report(findings: Dict[str, Any], ai_analysis: Dict[str, Any] = None) -> str:
    """Generate advanced security-focused report"""
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
        "## EXECUTIVE SUMMARY",
        f"This report presents the security assessment findings for {target}. ",
        f"The overall risk level is assessed as {risk_assessment['risk_level']} based on multiple security factors.",
        f"Only successful reconnaissance results are included in this analysis.",
        "",
        "## RISK ASSESSMENT BREAKDOWN"
    ]
    
    for factor, score in risk_assessment['factors'].items():
        if score > 0:
            report.append(f"- {factor.replace('_', ' ').title()}: {score} points")
    
    report.extend([
        "",
        "## SECURITY FINDINGS ANALYSIS",
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
    """Generate HTML report with enhanced styling and AI insights"""
    try:
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template('enhanced_report.html')
        
        # Filter successful findings
        filtered_findings = filter_successful_findings(findings)
        risk_assessment = calculate_risk_score(filtered_findings)
        
        successful_modules = len([k for k in filtered_findings.keys() if k != 'target'])
        total_modules = len([k for k in findings.keys() if k != 'target'])
        
        return template.render(
            target=filtered_findings.get('target', 'Unknown'),
            timestamp=datetime.now().isoformat(),
            findings=sanitize_output(filtered_findings),
            report_type=report_type,
            risk_assessment=risk_assessment,
            ai_analysis=ai_analysis or {},
            module_count=successful_modules,
            total_modules=total_modules,
            success_rate=round(successful_modules/total_modules*100 if total_modules > 0 else 0, 1),
            has_ai_analysis=ai_analysis is not None and 'error' not in ai_analysis
        )
    except Exception as e:
        logger.error(f"HTML report generation failed: {e}")
        # Fallback to basic HTML with filtered findings
        filtered_findings = filter_successful_findings(findings)
        return f"""
        <html>
        <head><title>Recon Report - {filtered_findings.get('target', 'Unknown')}</title></head>
        <body>
        <h1>Reconnaissance Report</h1>
        <h2>Target: {filtered_findings.get('target', 'Unknown')}</h2>
        <h3>Generated: {datetime.now().isoformat()}</h3>
        <h4>Note: Only successful findings are displayed</h4>
        <pre>{json.dumps(sanitize_output(filtered_findings), indent=2)}</pre>
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
