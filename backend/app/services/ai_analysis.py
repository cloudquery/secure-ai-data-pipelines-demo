"""
AI-powered security analysis engine with secure prompt templates.
"""
import json
import asyncio
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import openai
import anthropic
from dataclasses import dataclass

from ..core.config import settings
from ..core.security import mask_sensitive_fields
from .data_sanitization import DataSanitizer


@dataclass
class SecurityAnalysisResult:
    """Result of AI security analysis."""
    risk_score: float
    severity: str
    findings: List[Dict[str, Any]]
    recommendations: List[str]
    confidence: float
    analysis_metadata: Dict[str, Any]


class SecurePromptTemplate:
    """Secure prompt templates for AI analysis."""

    SECURITY_ANALYSIS_TEMPLATE = """
You are a cloud security expert analyzing sanitized cloud resource configurations. 
Your task is to identify security vulnerabilities and provide remediation guidance.

IMPORTANT SECURITY GUIDELINES:
- The data provided has been sanitized to remove PII and sensitive information
- Focus on configuration security, not specific identifiers
- Provide actionable security recommendations
- Rate risks on a scale of 0-10 (10 being critical)
- Consider compliance frameworks (PCI DSS, SOC 2, ISO 27001)

RESOURCE ANALYSIS:
Resource Type: {resource_type}
Cloud Provider: {provider}
Configuration: {sanitized_config}

Please analyze this resource configuration and provide:
1. Security risk assessment (0-10 scale)
2. Specific vulnerabilities identified
3. Attack vectors and potential impact
4. Remediation recommendations
5. Compliance considerations

Format your response as valid JSON with the following structure:
{{
    "risk_score": <float>,
    "severity": "<critical|high|medium|low>",
    "vulnerabilities": [
        {{
            "type": "<vulnerability_type>",
            "description": "<description>",
            "impact": "<potential_impact>",
            "attack_vectors": ["<vector1>", "<vector2>"]
        }}
    ],
    "recommendations": [
        {{
            "action": "<recommended_action>",
            "priority": "<high|medium|low>",
            "effort": "<low|medium|high>",
            "compliance_benefit": ["<framework1>", "<framework2>"]
        }}
    ],
    "compliance_violations": [
        {{
            "framework": "<framework_name>",
            "control": "<control_id>",
            "description": "<violation_description>"
        }}
    ]
}}
"""

    RELATIONSHIP_ANALYSIS_TEMPLATE = """
You are analyzing relationships between cloud resources to identify security risks.
Focus on privilege escalation paths, data flow vulnerabilities, and network security gaps.

RELATIONSHIP DATA:
{relationship_data}

Analyze these relationships for:
1. Privilege escalation paths
2. Data exfiltration risks
3. Network segmentation issues
4. Trust boundary violations

Provide your analysis in JSON format:
{{
    "risk_paths": [
        {{
            "path": ["resource1", "resource2", "resource3"],
            "risk_type": "<escalation|exfiltration|lateral_movement>",
            "severity": "<critical|high|medium|low>",
            "description": "<path_description>"
        }}
    ],
    "recommendations": [
        {{
            "action": "<recommended_action>",
            "affected_resources": ["<resource1>", "<resource2>"]
        }}
    ]
}}
"""

    COMPLIANCE_ANALYSIS_TEMPLATE = """
Analyze the provided cloud resource configuration for compliance violations.
Focus on major frameworks: PCI DSS, SOC 2, ISO 27001, HIPAA, GDPR.

RESOURCE CONFIGURATION:
{sanitized_config}

Evaluate compliance against:
1. Data encryption requirements
2. Access control standards
3. Logging and monitoring requirements
4. Network security controls
5. Data retention policies

Provide analysis in JSON format:
{{
    "compliance_score": <percentage>,
    "framework_assessments": [
        {{
            "framework": "<framework_name>",
            "score": <percentage>,
            "violations": [
                {{
                    "control": "<control_id>",
                    "description": "<violation>",
                    "severity": "<critical|high|medium|low>"
                }}
            ]
        }}
    ],
    "remediation_priority": [
        {{
            "control": "<control_id>",
            "framework": "<framework>",
            "priority": "<high|medium|low>",
            "estimated_effort": "<hours_or_days>"
        }}
    ]
}}
"""


class AISecurityAnalyzer:
    """AI-powered security analysis engine."""

    def __init__(self):
        self.sanitizer = DataSanitizer()
        self.prompt_templates = SecurePromptTemplate()
        self.openai_client = None
        self.claude_client = None
        self.preferred_ai_provider = None

        # Initialize AI clients if API keys are available
        if settings.openai_api_key:
            openai.api_key = settings.openai_api_key
            self.openai_client = openai
            self.preferred_ai_provider = "openai"

        if settings.anthropic_api_key:
            self.claude_client = anthropic.Anthropic(
                api_key=settings.anthropic_api_key)
            # Prefer Claude if both are available, otherwise use whatever is available
            if not self.preferred_ai_provider:
                self.preferred_ai_provider = "claude"
            else:
                # Both available - prefer Claude for security analysis
                self.preferred_ai_provider = "claude"

    async def analyze_resource_security(
        self,
        resource_data: Dict[str, Any],
        include_relationships: bool = False
    ) -> SecurityAnalysisResult:
        """
        Perform comprehensive security analysis of a cloud resource.

        Args:
            resource_data: Raw resource configuration data
            include_relationships: Whether to include relationship analysis

        Returns:
            SecurityAnalysisResult with findings and recommendations
        """

        # Sanitize the resource data first
        sanitized_data = self.sanitizer.sanitize_cloud_resource(resource_data)

        # Perform AI analysis
        ai_analysis = await self._ai_security_analysis(sanitized_data)

        # Perform rule-based analysis as backup/complement
        rule_analysis = self._rule_based_analysis(resource_data)

        # Combine results
        combined_analysis = self._combine_analyses(ai_analysis, rule_analysis)

        return combined_analysis

    async def analyze_resource_relationships(
        self,
        relationship_data: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze relationships between resources for security risks.

        Args:
            relationship_data: List of resource relationships

        Returns:
            Analysis of security risks in relationships
        """

        # Sanitize relationship data
        sanitized_relationships = [
            self.sanitizer.sanitize_cloud_resource(rel)
            for rel in relationship_data
        ]

        if self.preferred_ai_provider:
            return await self._ai_relationship_analysis(sanitized_relationships)
        else:
            return self._rule_based_relationship_analysis(sanitized_relationships)

    async def analyze_compliance(
        self,
        resource_data: Dict[str, Any],
        frameworks: List[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze resource for compliance violations.

        Args:
            resource_data: Resource configuration data
            frameworks: Specific frameworks to check (optional)

        Returns:
            Compliance analysis results
        """

        if frameworks is None:
            frameworks = ["PCI DSS", "SOC 2", "ISO 27001"]

        # Sanitize data
        sanitized_data = self.sanitizer.sanitize_cloud_resource(resource_data)

        if self.preferred_ai_provider:
            return await self._ai_compliance_analysis(sanitized_data, frameworks)
        else:
            return self._rule_based_compliance_analysis(sanitized_data, frameworks)

    async def _ai_security_analysis(self, sanitized_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform AI-powered security analysis."""

        if not self.preferred_ai_provider:
            return {"error": "AI client not available"}

        try:
            # Prepare prompt
            prompt = self.prompt_templates.SECURITY_ANALYSIS_TEMPLATE.format(
                resource_type=sanitized_data.get("resource_type", "unknown"),
                provider=sanitized_data.get("provider", "unknown"),
                sanitized_config=json.dumps(sanitized_data, indent=2)
            )

            # Call appropriate AI API
            if self.preferred_ai_provider == "claude":
                response = await self._call_claude_api(prompt)
            else:
                response = await self._call_openai_api(prompt)

            # Parse JSON response
            try:
                analysis = json.loads(response)
                analysis["ai_generated"] = True
                analysis["ai_provider"] = self.preferred_ai_provider
                analysis["analysis_timestamp"] = datetime.utcnow().isoformat()
                return analysis
            except json.JSONDecodeError:
                return {"error": "Failed to parse AI response", "raw_response": response}

        except Exception as e:
            return {"error": f"AI analysis failed: {str(e)}"}

    async def _ai_relationship_analysis(self, relationships: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform AI analysis of resource relationships."""

        try:
            prompt = self.prompt_templates.RELATIONSHIP_ANALYSIS_TEMPLATE.format(
                relationship_data=json.dumps(relationships, indent=2)
            )

            # Call appropriate AI API
            if self.preferred_ai_provider == "claude":
                response = await self._call_claude_api(prompt)
            else:
                response = await self._call_openai_api(prompt)

            try:
                analysis = json.loads(response)
                analysis["ai_generated"] = True
                analysis["ai_provider"] = self.preferred_ai_provider
                return analysis
            except json.JSONDecodeError:
                return {"error": "Failed to parse relationship analysis"}

        except Exception as e:
            return {"error": f"Relationship analysis failed: {str(e)}"}

    async def _ai_compliance_analysis(
        self,
        sanitized_data: Dict[str, Any],
        frameworks: List[str]
    ) -> Dict[str, Any]:
        """Perform AI-powered compliance analysis."""

        try:
            prompt = self.prompt_templates.COMPLIANCE_ANALYSIS_TEMPLATE.format(
                sanitized_config=json.dumps(sanitized_data, indent=2)
            )

            # Call appropriate AI API
            if self.preferred_ai_provider == "claude":
                response = await self._call_claude_api(prompt)
            else:
                response = await self._call_openai_api(prompt)

            try:
                analysis = json.loads(response)
                analysis["ai_generated"] = True
                analysis["ai_provider"] = self.preferred_ai_provider
                analysis["frameworks_analyzed"] = frameworks
                return analysis
            except json.JSONDecodeError:
                return {"error": "Failed to parse compliance analysis"}

        except Exception as e:
            return {"error": f"Compliance analysis failed: {str(e)}"}

    async def _call_openai_api(self, prompt: str, max_tokens: int = 2000) -> str:
        """
        Make a secure call to OpenAI API.

        Args:
            prompt: The prompt to send
            max_tokens: Maximum tokens in response

        Returns:
            AI response text
        """

        try:
            response = await self.openai_client.ChatCompletion.acreate(
                model="gpt-4",  # Use GPT-4 for better security analysis
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cloud security expert. Provide accurate, actionable security analysis in JSON format only."
                    },
                    {"role": "user", "content": prompt}
                ],
                max_tokens=max_tokens,
                temperature=0.1,  # Low temperature for consistent analysis
                top_p=0.9
            )

            return response.choices[0].message.content.strip()

        except Exception as e:
            raise Exception(f"OpenAI API call failed: {str(e)}")

    async def _call_claude_api(self, prompt: str, max_tokens: int = 2000) -> str:
        """
        Make a secure call to Claude API.

        Args:
            prompt: The prompt to send
            max_tokens: Maximum tokens in response

        Returns:
            AI response text
        """

        try:
            response = await self.claude_client.messages.create(
                model="claude-3-sonnet-20240229",  # Use Claude 3 Sonnet for security analysis
                max_tokens=max_tokens,
                temperature=0.1,  # Low temperature for consistent analysis
                system="You are a cloud security expert. Provide accurate, actionable security analysis in JSON format only.",
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

            return response.content[0].text.strip()

        except Exception as e:
            raise Exception(f"Claude API call failed: {str(e)}")

    def _rule_based_analysis(self, resource_data: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback rule-based security analysis."""

        findings = []
        risk_score = 0.0

        # Check for public access
        if resource_data.get("public_access"):
            findings.append({
                "type": "public_access",
                "severity": "high",
                "description": "Resource has public access enabled",
                "risk_contribution": 3.0
            })
            risk_score += 3.0

        # Check for encryption
        if not resource_data.get("encryption_enabled"):
            findings.append({
                "type": "encryption_disabled",
                "severity": "medium",
                "description": "Resource does not have encryption enabled",
                "risk_contribution": 2.0
            })
            risk_score += 2.0

        # Determine overall severity
        if risk_score >= 7:
            severity = "critical"
        elif risk_score >= 5:
            severity = "high"
        elif risk_score >= 3:
            severity = "medium"
        else:
            severity = "low"

        return {
            "risk_score": min(risk_score, 10.0),
            "severity": severity,
            "findings": findings,
            "analysis_type": "rule_based",
            "analysis_timestamp": datetime.utcnow().isoformat()
        }

    def _rule_based_relationship_analysis(self, relationships: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Rule-based relationship analysis."""

        risk_paths = []

        # Look for high-risk relationship patterns
        for rel in relationships:
            if rel.get("relationship_type") == "admin_access":
                risk_paths.append({
                    "path": [rel.get("source"), rel.get("target")],
                    "risk_type": "privilege_escalation",
                    "severity": "high",
                    "description": "Administrative access relationship detected"
                })

        return {
            "risk_paths": risk_paths,
            "analysis_type": "rule_based",
            "analysis_timestamp": datetime.utcnow().isoformat()
        }

    def _rule_based_compliance_analysis(
        self,
        sanitized_data: Dict[str, Any],
        frameworks: List[str]
    ) -> Dict[str, Any]:
        """Rule-based compliance analysis."""

        violations = []

        # Basic compliance checks
        if not sanitized_data.get("encryption_enabled"):
            violations.append({
                "framework": "PCI DSS",
                "control": "3.4",
                "description": "Encryption not enabled",
                "severity": "high"
            })

        compliance_score = max(0, 100 - (len(violations) * 20))

        return {
            "compliance_score": compliance_score,
            "violations": violations,
            "frameworks_analyzed": frameworks,
            "analysis_type": "rule_based",
            "analysis_timestamp": datetime.utcnow().isoformat()
        }

    def _combine_analyses(self, ai_analysis: Dict[str, Any], rule_analysis: Dict[str, Any]) -> SecurityAnalysisResult:
        """Combine AI and rule-based analyses."""

        # Use AI analysis if available, otherwise fall back to rules
        if ai_analysis.get("error"):
            primary_analysis = rule_analysis
            confidence = 0.7  # Lower confidence for rule-based only
        else:
            primary_analysis = ai_analysis
            confidence = 0.9  # Higher confidence with AI

        # Extract findings
        findings = []
        if "vulnerabilities" in primary_analysis:
            findings = primary_analysis["vulnerabilities"]
        elif "findings" in primary_analysis:
            findings = primary_analysis["findings"]

        # Extract recommendations
        recommendations = []
        if "recommendations" in primary_analysis:
            if isinstance(primary_analysis["recommendations"], list):
                recommendations = [
                    rec.get("action", str(rec)) if isinstance(
                        rec, dict) else str(rec)
                    for rec in primary_analysis["recommendations"]
                ]

        return SecurityAnalysisResult(
            risk_score=primary_analysis.get("risk_score", 0.0),
            severity=primary_analysis.get("severity", "low"),
            findings=findings,
            recommendations=recommendations,
            confidence=confidence,
            analysis_metadata={
                "ai_analysis": ai_analysis,
                "rule_analysis": rule_analysis,
                "combined_at": datetime.utcnow().isoformat()
            }
        )
