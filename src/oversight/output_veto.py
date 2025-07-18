"""
Output Veto (O_veto) - Policy enforcement for AI outputs
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum
import re
import logging

from ..policies.policy_store import PolicyStore, PolicyType, PolicyAction
from ..core.reasoning_layer import ReasoningOutput

class VetoAction(Enum):
    """Actions that can be taken when output is vetoed"""
    ALLOW = "allow"
    BLOCK = "block"
    MODIFY = "modify"
    ESCALATE = "escalate"
    REQUEST_HUMAN_REVIEW = "request_human_review"

@dataclass
class VetoResult:
    """Result of output veto evaluation"""
    action: VetoAction
    final_output: str
    original_output: str
    triggered_policies: List[str]
    risk_score: float
    modifications: List[str]
    escalation_reason: Optional[str] = None

class OutputVeto:
    """
    Output Veto (O_veto) - Final policy enforcement layer
    
    This component implements the O_veto function from the formal model:
    y_t = O_veto(y_{p,t}, P, τ_t)
    
    It validates proposed outputs from the Core Reasoning Layer against policies
    and trust levels before allowing them to be released externally.
    """
    
    def __init__(self, policy_store: PolicyStore):
        self.policy_store = policy_store
        self.logger = logging.getLogger(__name__)
        
        # Common patterns for sensitive information
        self.pii_patterns = [
            (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN'),  # Social Security Number
            (r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', 'Credit Card'),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email'),
            (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'IP Address'),
            (r'\b\d{3}-\d{3}-\d{4}\b', 'Phone Number'),
        ]
        
        # Harmful content patterns
        self.harmful_patterns = [
            (r'\b(password|secret|token|key)\s*[:=]\s*\S+', 'Credentials'),
            (r'\b(bomb|explosive|weapon|kill|murder)\b', 'Violence'),
            (r'\b(drug|cocaine|heroin|meth)\b', 'Drugs'),
            (r'\b(hack|exploit|vulnerability|backdoor)\b', 'Security'),
        ]
        
        # Placeholder responses for different veto scenarios
        self.veto_responses = {
            'pii_detected': "I cannot provide that information as it contains sensitive personal data.",
            'harmful_content': "I cannot provide that information as it may contain harmful content.",
            'policy_violation': "I cannot provide that information due to policy restrictions.",
            'low_trust': "I cannot process that request at this time. Please try again later.",
            'escalation_required': "This request requires additional review. Please contact an administrator.",
            'generic_denial': "I'm sorry, but I cannot provide that information."
        }
    
    def evaluate_output(self, 
                       reasoning_output: ReasoningOutput, 
                       trust_score: float,
                       context: Optional[Dict[str, Any]] = None) -> VetoResult:
        """
        Evaluate output against policies and trust requirements
        
        Args:
            reasoning_output: Output from the Core Reasoning Layer
            trust_score: Current trust score
            context: Optional context information
            
        Returns:
            VetoResult: Evaluation result with action to take
        """
        self.logger.info(f"Evaluating output for veto (trust: {trust_score:.3f})")
        
        original_output = reasoning_output.response
        current_output = original_output
        triggered_policies = []
        modifications = []
        risk_score = 0.0
        
        # Check for sensitive patterns
        pii_detected = self._check_pii_patterns(current_output)
        harmful_detected = self._check_harmful_patterns(current_output)
        
        if pii_detected:
            risk_score += 0.5
        if harmful_detected:
            risk_score += 0.4
        
        # Check policies
        policy_data = {
            "response": current_output,
            "trust_score": trust_score,
            "confidence": reasoning_output.confidence,
            "context": context or {}
        }
        
        triggered_policy_objects = self.policy_store.check_policies(PolicyType.OUTPUT_VETO, policy_data)
        
        # Process triggered policies
        for policy in triggered_policy_objects:
            triggered_policies.append(policy.id)
            risk_score += 0.1
            
            if policy.action == PolicyAction.DENY:
                return VetoResult(
                    action=VetoAction.BLOCK,
                    final_output=self._get_veto_response(policy.id, pii_detected, harmful_detected),
                    original_output=original_output,
                    triggered_policies=triggered_policies,
                    risk_score=risk_score,
                    modifications=modifications
                )
            
            elif policy.action == PolicyAction.MODIFY:
                current_output = self._apply_modifications(current_output, policy)
                modifications.append(f"Applied modifications from policy: {policy.name}")
            
            elif policy.action == PolicyAction.ESCALATE:
                return VetoResult(
                    action=VetoAction.REQUEST_HUMAN_REVIEW,
                    final_output=self.veto_responses['escalation_required'],
                    original_output=original_output,
                    triggered_policies=triggered_policies,
                    risk_score=risk_score,
                    modifications=modifications,
                    escalation_reason=f"Policy {policy.name} requires escalation"
                )
        
        # Trust-based evaluation
        if trust_score < 0.3:
            return VetoResult(
                action=VetoAction.BLOCK,
                final_output=self.veto_responses['low_trust'],
                original_output=original_output,
                triggered_policies=triggered_policies,
                risk_score=risk_score,
                modifications=modifications
            )
        
        # Confidence-based evaluation
        if reasoning_output.confidence < 0.5 and trust_score < 0.7:
            return VetoResult(
                action=VetoAction.MODIFY,
                final_output=f"{current_output}\n\n(Note: This response has low confidence and should be verified.)",
                original_output=original_output,
                triggered_policies=triggered_policies,
                risk_score=risk_score,
                modifications=modifications + ["Added low confidence warning"]
            )
        
        # Final risk assessment
        if risk_score > 0.6:
            return VetoResult(
                action=VetoAction.BLOCK,
                final_output=self.veto_responses['generic_denial'],
                original_output=original_output,
                triggered_policies=triggered_policies,
                risk_score=risk_score,
                modifications=modifications
            )
        
        # Allow output (possibly with modifications)
        action = VetoAction.MODIFY if modifications else VetoAction.ALLOW
        
        return VetoResult(
            action=action,
            final_output=current_output,
            original_output=original_output,
            triggered_policies=triggered_policies,
            risk_score=risk_score,
            modifications=modifications
        )
    
    def _check_pii_patterns(self, output: str) -> bool:
        """Check for personally identifiable information patterns"""
        for pattern, pii_type in self.pii_patterns:
            if re.search(pattern, output, re.IGNORECASE):
                self.logger.warning(f"PII detected in output: {pii_type}")
                return True
        return False
    
    def _check_harmful_patterns(self, output: str) -> bool:
        """Check for harmful content patterns"""
        for pattern, harm_type in self.harmful_patterns:
            if re.search(pattern, output, re.IGNORECASE):
                self.logger.warning(f"Harmful content detected in output: {harm_type}")
                return True
        return False
    
    def _apply_modifications(self, output: str, policy) -> str:
        """Apply modifications to output based on policy"""
        modified_output = output
        
        # Redact PII
        for pattern, pii_type in self.pii_patterns:
            modified_output = re.sub(pattern, f"[{pii_type} REDACTED]", modified_output, flags=re.IGNORECASE)
        
        # Remove harmful content
        for pattern, harm_type in self.harmful_patterns:
            modified_output = re.sub(pattern, "[FILTERED]", modified_output, flags=re.IGNORECASE)
        
        return modified_output
    
    def _get_veto_response(self, policy_id: str, pii_detected: bool, harmful_detected: bool) -> str:
        """Get appropriate veto response based on violation type"""
        if pii_detected:
            return self.veto_responses['pii_detected']
        elif harmful_detected:
            return self.veto_responses['harmful_content']
        else:
            return self.veto_responses['policy_violation']
    
    def quick_veto_check(self, output: str, trust_score: float) -> bool:
        """
        Quick check to see if output would be vetoed
        
        Args:
            output: Output text to check
            trust_score: Current trust score
            
        Returns:
            bool: True if output would be vetoed, False otherwise
        """
        # Quick PII check
        if self._check_pii_patterns(output):
            return True
        
        # Quick harmful content check
        if self._check_harmful_patterns(output):
            return True
        
        # Quick trust check
        if trust_score < 0.3:
            return True
        
        return False
    
    def add_veto_response(self, key: str, response: str):
        """Add a custom veto response"""
        self.veto_responses[key] = response
    
    def get_veto_stats(self) -> Dict[str, Any]:
        """Get statistics about veto operations"""
        # This would be implemented with proper metrics tracking
        return {
            "total_outputs_evaluated": 0,
            "outputs_blocked": 0,
            "outputs_modified": 0,
            "outputs_escalated": 0,
            "common_violations": [],
            "average_risk_score": 0.0
        }