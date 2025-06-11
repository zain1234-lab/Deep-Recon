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
        self.api_key = api_key #sk-42eb756a6e474f729056d03b8a563672
        self.base_url = "https://api.deepseek.com/v1/chat/completions"
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

    def analyze_findings(self, findings: Dict[str, Any], analysis_type: str = "security") -> Dict[str, Any]:
        """Analyze reconnaissance findings using DeepSeek API"""
        try:
            prompt = self._create_analysis_prompt(findings, analysis_type)
            
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
            response.raise_for_status()
            
            result = response.json()
            analysis = result['choices'][0]['message']['content']
            
            return self._parse_analysis(analysis)
            
        except Exception as e:
            logger.error(f"DeepSeek analysis failed: {e}")
            return {"error": str(e), "analysis": "AI analysis unavailable"}

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
                return json.loads(json_match.group())
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
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = 'REDACTED'
            elif isinstance(value, dict):
                sanitized[key] = sanitize_output(value)
            elif isinstance(value, list):
                sanitized[key] = [sanitize_output(item) if isinstance(item, dict) else item for item in value]
            else:
                sanitized[key] = value
        return sanitized
    return data

def calculate_risk_score(findings: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate overall risk score based on findings"""
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
    for module, data in findings.items():
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
    """Generate advanced report following security standards"""
    target = findings.get('target', 'Unknown')
    timestamp = datetime.now().isoformat()
    risk_assessment = calculate_risk_score(findings)
    
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
        "",
        "## RISK ASSESSMENT BREAKDOWN"
    ]
    
    for factor, score in risk_assessment['factors'].items():
        if score > 0:
            report.append(f"- {factor.replace('_', ' ').title()}: {score} points")
    
    report.extend([
        "",
        "## DETAILED FINDINGS",
        ""
    ])
    
    # Add AI analysis if available
    if ai_analysis and 'vulnerabilities' in ai_analysis:
        report.extend([
            "### AI-POWERED VULNERABILITY ANALYSIS",
            json.dumps(ai_analysis.get('vulnerabilities', {}), indent=2),
            "",
            "### RECOMMENDED ACTIONS",
            json.dumps(ai_analysis.get('recommendations', {}), indent=2),
            ""
        ])
    
    # Add technical findings
    for module, data in findings.items():
        if module != 'target':
            report.extend([
                f"### {module.replace('_', ' ').upper()}",
                json.dumps(sanitize_output(data), indent=2),
                ""
            ])
    
    report.extend([
        "---",
        "## COMPLIANCE NOTES",
        "- This assessment follows OWASP guidelines",
        "- Report generated using automated reconnaissance tools",
        "- Manual verification recommended for critical findings",
        "",
        f"Report generated by Enhanced Recon Tool v2.0 - {timestamp}"
    ])
    
    return '\n'.join(report)

def generate_comprehensive_report(findings: Dict[str, Any], ai_analysis: Dict[str, Any] = None) -> str:
    """Generate comprehensive report with all findings"""
    target = findings.get('target', 'Unknown')
    timestamp = datetime.now().isoformat()
    
    report = [
        f"# COMPREHENSIVE RECONNAISSANCE REPORT",
        f"## Target: {target}",
        f"## Generated: {timestamp}",
        "",
        "This report contains all reconnaissance findings and analysis.",
        "",
        "---",
        ""
    ]
    
    # Add AI comprehensive analysis
    if ai_analysis:
        report.extend([
            "## AI-POWERED COMPREHENSIVE ANALYSIS",
            ai_analysis.get('raw_analysis', 'Analysis not available'),
            "",
            "---",
            ""
        ])
    
    # Add all findings with detailed breakdown
    report.append("## COMPLETE FINDINGS BREAKDOWN")
    
    for module, data in findings.items():
        if module != 'target':
            report.extend([
                f"### {module.replace('_', ' ').title()} Module Results",
                "",
                "#### Raw Data:",
                "```json",
                json.dumps(data, indent=2),
                "```",
                "",
                "#### Sanitized Output:",
                "```json",
                json.dumps(sanitize_output(data), indent=2),
                "```",
                "",
                "---",
                ""
            ])
    
    report.extend([
        "## METADATA",
        f"- Total modules executed: {len([k for k in findings.keys() if k != 'target'])}",
        f"- Report generation time: {timestamp}",
        f"- Data sanitization: Applied",
        "",
        "## DISCLAIMER",
        "This report is generated for authorized security testing purposes only.",
        "Ensure proper authorization before conducting reconnaissance activities.",
        "",
        f"Generated by Enhanced Recon Tool v2.0"
    ])
    
    return '\n'.join(report)

def generate_html_report(findings: Dict[str, Any], template_dir: str, report_type: str = "advanced", ai_analysis: Dict[str, Any] = None) -> str:
    """Generate HTML report with enhanced styling and AI insights"""
    try:
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template('enhanced_report.html')
        
        risk_assessment = calculate_risk_score(findings)
        
        return template.render(
            target=findings.get('target', 'Unknown'),
            timestamp=datetime.now().isoformat(),
            findings=sanitize_output(findings),
            report_type=report_type,
            risk_assessment=risk_assessment,
            ai_analysis=ai_analysis or {},
            module_count=len([k for k in findings.keys() if k != 'target']),
            has_ai_analysis=ai_analysis is not None
        )
    except Exception as e:
        logger.error(f"HTML report generation failed: {e}")
        # Fallback to basic HTML
        return f"""
        <html>
        <head><title>Recon Report - {findings.get('target', 'Unknown')}</title></head>
        <body>
        <h1>Reconnaissance Report</h1>
        <h2>Target: {findings.get('target', 'Unknown')}</h2>
        <h3>Generated: {datetime.now().isoformat()}</h3>
        <pre>{json.dumps(sanitize_output(findings), indent=2)}</pre>
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

        # Initialize AI analyzer if API key provided
        ai_analyzer = None
        ai_analysis = {}
        
        if deepseek_api_key:
            try:
                ai_analyzer = DeepSeekAnalyzer(deepseek_api_key)
                logger.info("DeepSeek API integration enabled")
                
                # Get AI analysis for both report types
                ai_analysis['security'] = ai_analyzer.analyze_findings(findings, "security")
                ai_analysis['comprehensive'] = ai_analyzer.analyze_findings(findings, "comprehensive")
                
            except Exception as e:
                logger.warning(f"AI analysis failed, continuing without: {e}")

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
                json_data = {
                    'metadata': {
                        'target': target,
                        'timestamp': datetime.now().isoformat(),
                        'report_type': report_type,
                        'risk_assessment': calculate_risk_score(findings)
                    },
                    'findings': sanitize_output(findings),
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
