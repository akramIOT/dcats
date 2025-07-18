"""
DCATS - Dual-Layer Cognitive Architecture for Trustworthy and Secure AI Systems
Main system orchestrator implementing the dual-layer architecture
"""

from typing import Dict, Any, Optional
from dataclasses import dataclass
import logging
import time

from .core import CoreReasoningLayer, ReasoningInput, ReasoningOutput
from .oversight import (
    AttentionFilter, FilterResult,
    TrustScorer, TrustMetrics,
    MemoryPartitioner, MemoryAccessResult,
    OutputVeto, VetoResult, VetoAction
)
from .policies import PolicyStore

@dataclass
class DCATSInput:
    """Input to the DCATS system"""
    query: str
    context: Optional[Dict[str, Any]] = None
    user_metadata: Optional[Dict[str, Any]] = None

@dataclass
class DCATSOutput:
    """Output from the DCATS system"""
    response: str
    trust_score: float
    confidence: float
    processing_trace: Dict[str, Any]
    security_actions: Dict[str, Any]

class DualLayerAI:
    """
    Main DCATS system implementing the dual-layer cognitive architecture
    
    This system integrates:
    - Core Reasoning Layer (C): Primary AI reasoning engine
    - Oversight Layer (O): Cognitive firewall with four components
      - Attention Filter (O_filter)
      - Trust Scorer (O_trust)
      - Memory Partitioner (O_mem)
      - Output Veto (O_veto)
    - Policy Store (P): Explicit rules and policies
    """
    
    def __init__(self, initial_trust: float = 0.5):
        self.logger = logging.getLogger(__name__)
        self.logger.info("Initializing DCATS system...")
        
        # Initialize components
        self.policy_store = PolicyStore()
        self.core_reasoning = CoreReasoningLayer()
        self.attention_filter = AttentionFilter(self.policy_store)
        self.trust_scorer = TrustScorer(initial_trust)
        self.memory_partitioner = MemoryPartitioner(self.policy_store)
        self.output_veto = OutputVeto(self.policy_store)
        
        # System state
        self.current_trust = initial_trust
        self.session_stats = {
            "total_queries": 0,
            "blocked_inputs": 0,
            "vetoed_outputs": 0,
            "policy_violations": 0,
            "successful_interactions": 0
        }
        
        self.logger.info("DCATS system initialized successfully")
    
    def process(self, dcats_input: DCATSInput) -> DCATSOutput:
        """
        Main processing function implementing the dual-layer architecture
        
        Flow:
        1. Input Phase: Filter input through Attention Filter
        2. Trust Update: Update trust score based on input
        3. Memory Partitioning: Grant appropriate memory access
        4. Core Processing: Generate response through Core Reasoning Layer
        5. Output Veto: Validate output against policies
        6. Return validated response
        
        Args:
            dcats_input: Input to process
            
        Returns:
            DCATSOutput: Processed output with security metadata
        """
        start_time = time.time()
        self.session_stats["total_queries"] += 1
        
        self.logger.info(f"Processing query: {dcats_input.query[:50]}...")
        
        processing_trace = {
            "start_time": start_time,
            "input_length": len(dcats_input.query),
            "phases": {}
        }
        
        security_actions = {
            "input_filtered": False,
            "trust_updated": False,
            "memory_restricted": False,
            "output_vetoed": False,
            "policies_triggered": []
        }
        
        try:
            # Phase 1: Input Filtering (Attention Filter)
            self.logger.debug("Phase 1: Input filtering")
            filter_result = self.attention_filter.filter_input(
                dcats_input.query, 
                self.current_trust,
                dcats_input.context
            )
            
            processing_trace["phases"]["input_filter"] = {
                "duration": time.time() - start_time,
                "risk_score": filter_result.risk_score,
                "triggered_policies": filter_result.triggered_policies,
                "modifications": filter_result.modifications
            }
            
            if filter_result.is_blocked:
                self.session_stats["blocked_inputs"] += 1
                security_actions["input_filtered"] = True
                
                return DCATSOutput(
                    response="I cannot process this request due to security restrictions.",
                    trust_score=self.current_trust,
                    confidence=0.0,
                    processing_trace=processing_trace,
                    security_actions=security_actions
                )
            
            # Phase 2: Trust Score Update
            self.logger.debug("Phase 2: Trust score update")
            phase2_start = time.time()
            
            self.current_trust = self.trust_scorer.update_trust(
                dcats_input.query,
                dcats_input.user_metadata or {}
            )
            
            processing_trace["phases"]["trust_update"] = {
                "duration": time.time() - phase2_start,
                "trust_score": self.current_trust,
                "trust_level": self.trust_scorer.get_trust_level()
            }
            
            security_actions["trust_updated"] = True
            
            # Phase 3: Memory Partitioning
            self.logger.debug("Phase 3: Memory partitioning")
            phase3_start = time.time()
            
            memory_access = self.memory_partitioner.partition_memory(
                dcats_input.context or {},
                self.current_trust,
                filter_result.filtered_input
            )
            
            processing_trace["phases"]["memory_partition"] = {
                "duration": time.time() - phase3_start,
                "granted_partitions": memory_access.granted_partitions,
                "denied_partitions": memory_access.denied_partitions,
                "restrictions": memory_access.restrictions
            }
            
            if memory_access.restrictions:
                security_actions["memory_restricted"] = True
            
            # Phase 4: Core Reasoning
            self.logger.debug("Phase 4: Core reasoning")
            phase4_start = time.time()
            
            reasoning_input = ReasoningInput(
                query=filter_result.filtered_input,
                context=dcats_input.context,
                memory_access={"token": memory_access.access_token}
            )
            
            reasoning_output = self.core_reasoning.process(reasoning_input)
            
            processing_trace["phases"]["core_reasoning"] = {
                "duration": time.time() - phase4_start,
                "confidence": reasoning_output.confidence,
                "reasoning_trace": reasoning_output.reasoning_trace
            }
            
            # Phase 5: Output Veto
            self.logger.debug("Phase 5: Output veto")
            phase5_start = time.time()
            
            veto_result = self.output_veto.evaluate_output(
                reasoning_output,
                self.current_trust,
                dcats_input.context
            )
            
            processing_trace["phases"]["output_veto"] = {
                "duration": time.time() - phase5_start,
                "action": veto_result.action.value,
                "risk_score": veto_result.risk_score,
                "triggered_policies": veto_result.triggered_policies,
                "modifications": veto_result.modifications
            }
            
            # Handle veto actions
            if veto_result.action == VetoAction.BLOCK:
                self.session_stats["vetoed_outputs"] += 1
                security_actions["output_vetoed"] = True
                
                # Record policy violations
                for policy_id in veto_result.triggered_policies:
                    self.trust_scorer.record_policy_violation(policy_id, "medium")
                    security_actions["policies_triggered"].append(policy_id)
                
                self.session_stats["policy_violations"] += len(veto_result.triggered_policies)
                
            elif veto_result.action == VetoAction.REQUEST_HUMAN_REVIEW:
                self.session_stats["vetoed_outputs"] += 1
                security_actions["output_vetoed"] = True
                
            else:
                # Successful interaction
                self.session_stats["successful_interactions"] += 1
                self.trust_scorer.record_successful_interaction(reasoning_output.confidence)
            
            # Final processing trace
            processing_trace["total_duration"] = time.time() - start_time
            processing_trace["final_trust_score"] = self.current_trust
            
            return DCATSOutput(
                response=veto_result.final_output,
                trust_score=self.current_trust,
                confidence=reasoning_output.confidence,
                processing_trace=processing_trace,
                security_actions=security_actions
            )
            
        except Exception as e:
            self.logger.error(f"Error in DCATS processing: {e}")
            
            # Record error and reduce trust
            self.trust_scorer.record_policy_violation("system_error", "high")
            
            return DCATSOutput(
                response="I apologize, but I encountered an error processing your request.",
                trust_score=self.current_trust,
                confidence=0.0,
                processing_trace=processing_trace,
                security_actions=security_actions
            )
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status and statistics"""
        trust_metrics = self.trust_scorer.get_trust_metrics()
        memory_stats = self.memory_partitioner.get_memory_stats()
        
        return {
            "trust_metrics": {
                "current_score": trust_metrics.current_score,
                "trust_level": self.trust_scorer.get_trust_level(),
                "confidence_level": trust_metrics.confidence_level
            },
            "memory_stats": memory_stats,
            "session_stats": self.session_stats.copy(),
            "policy_count": len(self.policy_store.policies),
            "system_health": "operational"
        }
    
    def reset_session(self):
        """Reset session state"""
        self.trust_scorer.reset_trust()
        self.current_trust = self.trust_scorer.current_trust
        self.session_stats = {
            "total_queries": 0,
            "blocked_inputs": 0,
            "vetoed_outputs": 0,
            "policy_violations": 0,
            "successful_interactions": 0
        }
        self.logger.info("Session reset completed")
    
    def update_policies(self, policy_updates: Dict[str, Any]):
        """Update system policies"""
        self.policy_store.import_policies(policy_updates)
        self.logger.info(f"Policies updated: {len(policy_updates)} policies")
    
    def export_audit_log(self) -> Dict[str, Any]:
        """Export audit log for compliance and analysis"""
        trust_metrics = self.trust_scorer.get_trust_metrics()
        
        return {
            "timestamp": time.time(),
            "trust_history": trust_metrics.score_history,
            "trust_events": [
                {
                    "timestamp": event.timestamp,
                    "type": event.event_type,
                    "impact": event.impact,
                    "description": event.description
                }
                for event in trust_metrics.recent_events
            ],
            "session_stats": self.session_stats.copy(),
            "policy_summary": self.policy_store.export_policies()
        }