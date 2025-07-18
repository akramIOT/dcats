"""
Attention Filter (O_filter) - Input sanitization component
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import re
import logging

from ..policies.policy_store import PolicyStore, PolicyType, PolicyAction

@dataclass
class FilterResult:
    """Result of attention filtering operation"""
    filtered_input: str
    is_blocked: bool
    triggered_policies: List[str]
    risk_score: float
    modifications: List[str]

class AttentionFilter:
    """
    Attention Filter (O_filter) - Sanitizes inputs before they reach the Core Reasoning Layer
    
    This component screens all external inputs for malicious content, irrelevant information,
    or content beyond the AI's permitted scope. It implements the O_filter function from
    the formal model: x'_t = O_filter(x_t, P, τ_{t-1})
    """
    
    def __init__(self, policy_store: PolicyStore):
        self.policy_store = policy_store
        self.logger = logging.getLogger(__name__)
        
        # Common patterns for malicious inputs
        self.malicious_patterns = [
            r"ignore.*previous.*instruction",
            r"forget.*everything",
            r"you.*are.*now",
            r"pretend.*to.*be",
            r"roleplay.*as",
            r"jailbreak",
            r"bypass.*filter",
            r"override.*safety"
        ]
        
        # Sensitive information patterns
        self.sensitive_patterns = [
            r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
            r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",  # Credit card
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"  # IP address
        ]
    
    def filter_input(self, input_text: str, trust_score: float, context: Optional[Dict[str, Any]] = None) -> FilterResult:
        """
        Filter and sanitize input text
        
        Args:
            input_text: Raw input text to filter
            trust_score: Current trust score (0.0 to 1.0)
            context: Optional context information
            
        Returns:
            FilterResult: Result of filtering operation
        """
        self.logger.info(f"Filtering input: {input_text[:50]}...")
        
        # Initialize result
        result = FilterResult(
            filtered_input=input_text,
            is_blocked=False,
            triggered_policies=[],
            risk_score=0.0,
            modifications=[]
        )
        
        # Check policies
        data = {
            "query": input_text,
            "trust_score": trust_score,
            "context": context or {}
        }
        
        triggered_policies = self.policy_store.check_policies(PolicyType.INPUT_FILTER, data)
        
        # Process triggered policies
        for policy in triggered_policies:
            result.triggered_policies.append(policy.id)
            
            if policy.action == PolicyAction.DENY:
                result.is_blocked = True
                result.filtered_input = ""
                self.logger.warning(f"Input blocked by policy: {policy.name}")
                break
            elif policy.action == PolicyAction.MODIFY:
                result.filtered_input = self._apply_modifications(result.filtered_input, policy)
                result.modifications.append(f"Applied policy: {policy.name}")
        
        # Calculate risk score
        result.risk_score = self._calculate_risk_score(input_text, trust_score, triggered_policies)
        
        # Apply additional filtering based on trust score
        if trust_score < 0.3:  # Low trust
            result.filtered_input = self._apply_strict_filtering(result.filtered_input)
            result.modifications.append("Applied strict filtering due to low trust score")
        
        return result
    
    def _calculate_risk_score(self, input_text: str, trust_score: float, triggered_policies: list) -> float:
        """Calculate risk score for the input"""
        base_risk = 0.0
        
        # Check for malicious patterns
        for pattern in self.malicious_patterns:
            if re.search(pattern, input_text, re.IGNORECASE):
                base_risk += 0.3
        
        # Check for sensitive information
        for pattern in self.sensitive_patterns:
            if re.search(pattern, input_text, re.IGNORECASE):
                base_risk += 0.2
        
        # Factor in triggered policies
        policy_risk = len(triggered_policies) * 0.1
        
        # Factor in trust score (lower trust = higher risk)
        trust_risk = (1.0 - trust_score) * 0.3
        
        # Calculate final risk score
        total_risk = min(base_risk + policy_risk + trust_risk, 1.0)
        
        return total_risk
    
    def _apply_modifications(self, input_text: str, policy) -> str:
        """Apply modifications based on policy rules"""
        modified_text = input_text
        
        # Remove sensitive information
        for pattern in self.sensitive_patterns:
            modified_text = re.sub(pattern, "[REDACTED]", modified_text, flags=re.IGNORECASE)
        
        # Remove potentially malicious phrases
        for pattern in self.malicious_patterns:
            modified_text = re.sub(pattern, "[FILTERED]", modified_text, flags=re.IGNORECASE)
        
        return modified_text
    
    def _apply_strict_filtering(self, input_text: str) -> str:
        """Apply strict filtering for low trust scenarios"""
        # In strict mode, be more aggressive with filtering
        strict_text = input_text
        
        # Remove any mention of system commands
        system_commands = [
            r"system|admin|root|sudo|exec|eval|import|__.*__"
        ]
        
        for pattern in system_commands:
            strict_text = re.sub(pattern, "[FILTERED]", strict_text, flags=re.IGNORECASE)
        
        # Limit input length in strict mode
        if len(strict_text) > 200:
            strict_text = strict_text[:200] + "... [TRUNCATED]"
        
        return strict_text
    
    def is_input_safe(self, input_text: str, trust_score: float) -> bool:
        """
        Quick safety check for input
        
        Args:
            input_text: Input text to check
            trust_score: Current trust score
            
        Returns:
            bool: True if input is safe, False otherwise
        """
        filter_result = self.filter_input(input_text, trust_score)
        return not filter_result.is_blocked and filter_result.risk_score < 0.5
    
    def get_filter_stats(self) -> Dict[str, Any]:
        """Get statistics about filtering operations"""
        # This would be implemented with proper metrics tracking
        return {
            "total_inputs_processed": 0,
            "inputs_blocked": 0,
            "inputs_modified": 0,
            "average_risk_score": 0.0
        }