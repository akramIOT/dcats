"""
Policy Store (P) - Storage and management of explicit rules and policies
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
import json
import re

class PolicyType(Enum):
    """Types of policies that can be enforced"""
    INPUT_FILTER = "input_filter"
    OUTPUT_VETO = "output_veto"
    MEMORY_ACCESS = "memory_access"
    TRUST_SCORING = "trust_scoring"

class PolicyAction(Enum):
    """Actions that can be taken when a policy is triggered"""
    ALLOW = "allow"
    DENY = "deny"
    MODIFY = "modify"
    ESCALATE = "escalate"

@dataclass
class PolicyRule:
    """Individual policy rule definition"""
    id: str
    name: str
    description: str
    type: PolicyType
    action: PolicyAction
    conditions: List[Dict[str, Any]]
    priority: int = 0
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

class PolicyStore:
    """
    Policy Store (P) - Manages explicit rules and policies for the oversight layer
    
    This component stores and manages the policies that govern the AI system's
    behavior, including input filtering, output vetting, and memory access rules.
    """
    
    def __init__(self):
        self.policies: Dict[str, PolicyRule] = {}
        self._load_default_policies()
    
    def _load_default_policies(self):
        """Load default security and safety policies"""
        
        # Input filtering policies
        self.add_policy(PolicyRule(
            id="block_pii_requests",
            name="Block PII Requests",
            description="Block requests for personally identifiable information",
            type=PolicyType.INPUT_FILTER,
            action=PolicyAction.DENY,
            conditions=[
                {"field": "query", "operator": "contains", "value": "credit card"},
                {"field": "query", "operator": "contains", "value": "ssn"},
                {"field": "query", "operator": "contains", "value": "social security"},
                {"field": "query", "operator": "contains", "value": "password"}
            ],
            priority=10
        ))
        
        self.add_policy(PolicyRule(
            id="block_malicious_prompts",
            name="Block Malicious Prompts",
            description="Block potential prompt injection attacks",
            type=PolicyType.INPUT_FILTER,
            action=PolicyAction.DENY,
            conditions=[
                {"field": "query", "operator": "regex", "value": r"ignore.*instruction"},
                {"field": "query", "operator": "regex", "value": r"forget.*previous"},
                {"field": "query", "operator": "contains", "value": "jailbreak"}
            ],
            priority=10
        ))
        
        # Output veto policies
        self.add_policy(PolicyRule(
            id="prevent_pii_output",
            name="Prevent PII Output",
            description="Prevent output of personally identifiable information",
            type=PolicyType.OUTPUT_VETO,
            action=PolicyAction.DENY,
            conditions=[
                {"field": "response", "operator": "regex", "value": r"\d{3}-\d{2}-\d{4}"},  # SSN
                {"field": "response", "operator": "regex", "value": r"\d{4}-\d{4}-\d{4}-\d{4}"},  # Credit card
                {"field": "response", "operator": "contains", "value": "@"}  # Email (simplified)
            ],
            priority=10
        ))
        
        self.add_policy(PolicyRule(
            id="prevent_harmful_content",
            name="Prevent Harmful Content",
            description="Prevent output of harmful or inappropriate content",
            type=PolicyType.OUTPUT_VETO,
            action=PolicyAction.DENY,
            conditions=[
                {"field": "response", "operator": "contains", "value": "violence"},
                {"field": "response", "operator": "contains", "value": "illegal"}
            ],
            priority=8
        ))
        
        # Memory access policies
        self.add_policy(PolicyRule(
            id="restrict_sensitive_data",
            name="Restrict Sensitive Data Access",
            description="Restrict access to sensitive data tables",
            type=PolicyType.MEMORY_ACCESS,
            action=PolicyAction.DENY,
            conditions=[
                {"field": "table", "operator": "equals", "value": "employee_salaries"},
                {"field": "table", "operator": "equals", "value": "customer_pii"}
            ],
            priority=10
        ))
    
    def add_policy(self, policy: PolicyRule):
        """Add a new policy to the store"""
        self.policies[policy.id] = policy
    
    def remove_policy(self, policy_id: str):
        """Remove a policy from the store"""
        if policy_id in self.policies:
            del self.policies[policy_id]
    
    def get_policy(self, policy_id: str) -> Optional[PolicyRule]:
        """Get a specific policy by ID"""
        return self.policies.get(policy_id)
    
    def get_policies_by_type(self, policy_type: PolicyType) -> List[PolicyRule]:
        """Get all policies of a specific type"""
        return [p for p in self.policies.values() if p.type == policy_type and p.enabled]
    
    def evaluate_condition(self, condition: Dict[str, Any], data: Dict[str, Any]) -> bool:
        """
        Evaluate a single policy condition against data
        
        Args:
            condition: Policy condition to evaluate
            data: Data to evaluate against
            
        Returns:
            bool: True if condition is met, False otherwise
        """
        field = condition.get("field")
        operator = condition.get("operator")
        value = condition.get("value")
        
        if field not in data:
            return False
        
        data_value = data[field]
        
        if operator == "equals":
            return data_value == value
        elif operator == "contains":
            return value.lower() in str(data_value).lower()
        elif operator == "regex":
            return bool(re.search(value, str(data_value), re.IGNORECASE))
        elif operator == "greater_than":
            return float(data_value) > float(value)
        elif operator == "less_than":
            return float(data_value) < float(value)
        else:
            return False
    
    def evaluate_policy(self, policy: PolicyRule, data: Dict[str, Any]) -> bool:
        """
        Evaluate a policy against data
        
        Args:
            policy: Policy to evaluate
            data: Data to evaluate against
            
        Returns:
            bool: True if policy is triggered, False otherwise
        """
        if not policy.enabled:
            return False
        
        # Check if any condition is met (OR logic)
        for condition in policy.conditions:
            if self.evaluate_condition(condition, data):
                return True
        
        return False
    
    def check_policies(self, policy_type: PolicyType, data: Dict[str, Any]) -> List[PolicyRule]:
        """
        Check all policies of a given type against data
        
        Args:
            policy_type: Type of policies to check
            data: Data to evaluate against
            
        Returns:
            List[PolicyRule]: List of triggered policies
        """
        triggered_policies = []
        policies = self.get_policies_by_type(policy_type)
        
        # Sort by priority (higher priority first)
        policies.sort(key=lambda p: p.priority, reverse=True)
        
        for policy in policies:
            if self.evaluate_policy(policy, data):
                triggered_policies.append(policy)
        
        return triggered_policies
    
    def export_policies(self) -> Dict[str, Any]:
        """Export all policies to a dictionary"""
        return {
            policy_id: {
                "id": policy.id,
                "name": policy.name,
                "description": policy.description,
                "type": policy.type.value,
                "action": policy.action.value,
                "conditions": policy.conditions,
                "priority": policy.priority,
                "enabled": policy.enabled,
                "metadata": policy.metadata
            }
            for policy_id, policy in self.policies.items()
        }
    
    def import_policies(self, policies_data: Dict[str, Any]):
        """Import policies from a dictionary"""
        for policy_id, policy_data in policies_data.items():
            policy = PolicyRule(
                id=policy_data["id"],
                name=policy_data["name"],
                description=policy_data["description"],
                type=PolicyType(policy_data["type"]),
                action=PolicyAction(policy_data["action"]),
                conditions=policy_data["conditions"],
                priority=policy_data.get("priority", 0),
                enabled=policy_data.get("enabled", True),
                metadata=policy_data.get("metadata", {})
            )
            self.add_policy(policy)