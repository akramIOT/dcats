"""
Memory Partitioner (O_mem) - Contextual memory access control
"""

from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass
from enum import Enum
import logging

from ..policies.policy_store import PolicyStore, PolicyType

class AccessLevel(Enum):
    """Memory access levels"""
    NONE = "none"
    READ_ONLY = "read_only"
    READ_WRITE = "read_write"
    ADMIN = "admin"

@dataclass
class MemoryPartition:
    """Memory partition definition"""
    id: str
    name: str
    description: str
    data_tables: List[str]
    access_level: AccessLevel
    sensitivity_level: str  # low, medium, high, critical
    required_trust: float
    metadata: Dict[str, Any]

@dataclass
class MemoryAccessResult:
    """Result of memory access request"""
    granted_partitions: List[str]
    denied_partitions: List[str]
    access_token: str
    restrictions: List[str]
    expires_at: float

class MemoryPartitioner:
    """
    Memory Partitioner (O_mem) - Manages contextual memory access
    
    This component implements the O_mem function from the formal model:
    M'_t = O_mem(M, P, τ_t, context(x'_t))
    
    It controls the AI's access to its long-term and working memory based on
    context, trust level, and security policies.
    """
    
    def __init__(self, policy_store: PolicyStore):
        self.policy_store = policy_store
        self.logger = logging.getLogger(__name__)
        
        # Initialize memory partitions
        self.partitions: Dict[str, MemoryPartition] = {}
        self._create_default_partitions()
        
        # Active access tokens
        self.active_tokens: Dict[str, MemoryAccessResult] = {}
        
    def _create_default_partitions(self):
        """Create default memory partitions"""
        
        # Public data partition
        self.partitions["public"] = MemoryPartition(
            id="public",
            name="Public Data",
            description="Generally accessible business data",
            data_tables=["products", "public_reports", "company_info"],
            access_level=AccessLevel.READ_ONLY,
            sensitivity_level="low",
            required_trust=0.2,
            metadata={"created_by": "system"}
        )
        
        # Business analytics partition
        self.partitions["analytics"] = MemoryPartition(
            id="analytics",
            name="Business Analytics",
            description="Business metrics and analytics data",
            data_tables=["sales_data", "revenue_reports", "market_analysis"],
            access_level=AccessLevel.READ_ONLY,
            sensitivity_level="medium",
            required_trust=0.5,
            metadata={"department": "analytics"}
        )
        
        # Customer data partition
        self.partitions["customer"] = MemoryPartition(
            id="customer",
            name="Customer Data",
            description="Customer information and transactions",
            data_tables=["customers", "orders", "customer_history"],
            access_level=AccessLevel.READ_ONLY,
            sensitivity_level="high",
            required_trust=0.7,
            metadata={"contains_pii": True}
        )
        
        # Employee data partition
        self.partitions["employee"] = MemoryPartition(
            id="employee",
            name="Employee Data",
            description="Employee information and HR data",
            data_tables=["employees", "employee_salaries", "hr_records"],
            access_level=AccessLevel.READ_ONLY,
            sensitivity_level="critical",
            required_trust=0.9,
            metadata={"contains_pii": True, "hr_restricted": True}
        )
        
        # System configuration partition
        self.partitions["system"] = MemoryPartition(
            id="system",
            name="System Configuration",
            description="System settings and configuration",
            data_tables=["config", "system_logs", "api_keys"],
            access_level=AccessLevel.ADMIN,
            sensitivity_level="critical",
            required_trust=0.95,
            metadata={"admin_only": True}
        )
    
    def partition_memory(self, 
                        context: Dict[str, Any], 
                        trust_score: float, 
                        query_context: Optional[str] = None) -> MemoryAccessResult:
        """
        Partition memory based on context and trust score
        
        Args:
            context: Current context information
            trust_score: Current trust score (0.0 to 1.0)
            query_context: Optional query context for additional filtering
            
        Returns:
            MemoryAccessResult: Memory access permissions
        """
        self.logger.info(f"Partitioning memory for trust score: {trust_score:.3f}")
        
        granted_partitions = []
        denied_partitions = []
        restrictions = []
        
        # Evaluate each partition
        for partition_id, partition in self.partitions.items():
            if self._can_access_partition(partition, trust_score, context, query_context):
                granted_partitions.append(partition_id)
            else:
                denied_partitions.append(partition_id)
                restrictions.append(f"Denied access to {partition.name}: insufficient trust or policy restriction")
        
        # Check policy restrictions
        policy_data = {
            "context": context,
            "trust_score": trust_score,
            "query_context": query_context,
            "requested_partitions": list(self.partitions.keys())
        }
        
        triggered_policies = self.policy_store.check_policies(PolicyType.MEMORY_ACCESS, policy_data)
        
        # Apply policy restrictions
        for policy in triggered_policies:
            # Remove access to partitions based on policy
            for condition in policy.conditions:
                if condition.get("field") == "table":
                    table_name = condition.get("value")
                    # Find partition containing this table
                    for partition_id, partition in self.partitions.items():
                        if table_name in partition.data_tables and partition_id in granted_partitions:
                            granted_partitions.remove(partition_id)
                            denied_partitions.append(partition_id)
                            restrictions.append(f"Policy {policy.name} denied access to {partition.name}")
        
        # Generate access token
        access_token = self._generate_access_token(granted_partitions, trust_score)
        
        # Create access result
        import time
        expires_at = time.time() + 3600  # 1 hour expiry
        
        result = MemoryAccessResult(
            granted_partitions=granted_partitions,
            denied_partitions=denied_partitions,
            access_token=access_token,
            restrictions=restrictions,
            expires_at=expires_at
        )
        
        # Store active token
        self.active_tokens[access_token] = result
        
        self.logger.info(f"Memory partitioned: {len(granted_partitions)} granted, {len(denied_partitions)} denied")
        
        return result
    
    def _can_access_partition(self, 
                            partition: MemoryPartition, 
                            trust_score: float, 
                            context: Dict[str, Any], 
                            query_context: Optional[str]) -> bool:
        """Check if partition can be accessed"""
        
        # Check minimum trust requirement
        if trust_score < partition.required_trust:
            return False
        
        # Check access level requirements
        if partition.access_level == AccessLevel.ADMIN:
            # Admin access requires very high trust and special context
            return (trust_score >= 0.95 and 
                   context.get("admin_mode", False))
        
        # Check sensitivity level restrictions
        if partition.sensitivity_level == "critical":
            # Critical data requires high trust and authenticated context
            return (trust_score >= 0.8 and 
                   context.get("authenticated", False))
        
        elif partition.sensitivity_level == "high":
            # High sensitivity data requires medium-high trust
            return trust_score >= 0.6
        
        # Check for PII restrictions
        if partition.metadata.get("contains_pii", False):
            # PII data requires authentication and higher trust
            return (trust_score >= 0.7 and 
                   context.get("authenticated", False))
        
        # Check query context restrictions
        if query_context:
            # Some partitions might be restricted based on query intent
            sensitive_keywords = ["password", "secret", "private", "confidential"]
            if any(keyword in query_context.lower() for keyword in sensitive_keywords):
                return trust_score >= 0.8
        
        return True
    
    def _generate_access_token(self, granted_partitions: List[str], trust_score: float) -> str:
        """Generate access token for memory partitions"""
        import hashlib
        import time
        
        # Simple token generation (in production, use proper JWT or similar)
        token_data = f"{':'.join(granted_partitions)}:{trust_score}:{time.time()}"
        token_hash = hashlib.md5(token_data.encode()).hexdigest()
        
        return f"mem_token_{token_hash[:16]}"
    
    def get_accessible_tables(self, access_token: str) -> List[str]:
        """Get list of accessible tables for a given access token"""
        if access_token not in self.active_tokens:
            return []
        
        access_result = self.active_tokens[access_token]
        
        # Check if token has expired
        import time
        if time.time() > access_result.expires_at:
            del self.active_tokens[access_token]
            return []
        
        # Collect all accessible tables
        accessible_tables = []
        for partition_id in access_result.granted_partitions:
            if partition_id in self.partitions:
                accessible_tables.extend(self.partitions[partition_id].data_tables)
        
        return accessible_tables
    
    def validate_table_access(self, table_name: str, access_token: str) -> bool:
        """Validate access to a specific table"""
        accessible_tables = self.get_accessible_tables(access_token)
        return table_name in accessible_tables
    
    def revoke_access_token(self, access_token: str):
        """Revoke an access token"""
        if access_token in self.active_tokens:
            del self.active_tokens[access_token]
            self.logger.info(f"Access token revoked: {access_token}")
    
    def get_partition_info(self, partition_id: str) -> Optional[MemoryPartition]:
        """Get information about a specific partition"""
        return self.partitions.get(partition_id)
    
    def add_partition(self, partition: MemoryPartition):
        """Add a new memory partition"""
        self.partitions[partition.id] = partition
        self.logger.info(f"Memory partition added: {partition.name}")
    
    def remove_partition(self, partition_id: str):
        """Remove a memory partition"""
        if partition_id in self.partitions:
            del self.partitions[partition_id]
            self.logger.info(f"Memory partition removed: {partition_id}")
    
    def get_memory_stats(self) -> Dict[str, Any]:
        """Get memory partitioning statistics"""
        return {
            "total_partitions": len(self.partitions),
            "active_tokens": len(self.active_tokens),
            "partitions_by_sensitivity": {
                level: len([p for p in self.partitions.values() if p.sensitivity_level == level])
                for level in ["low", "medium", "high", "critical"]
            }
        }