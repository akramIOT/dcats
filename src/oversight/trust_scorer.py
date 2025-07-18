"""
Trust Scorer (O_trust) - Dynamic trust assessment component
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import time
import math
import logging

@dataclass
class TrustEvent:
    """Event that affects trust score"""
    timestamp: float
    event_type: str
    impact: float
    description: str
    metadata: Dict[str, Any]

@dataclass
class TrustMetrics:
    """Trust metrics and statistics"""
    current_score: float
    baseline_score: float
    confidence_level: float
    recent_events: List[TrustEvent]
    score_history: List[float]

class TrustScorer:
    """
    Trust Scorer (O_trust) - Maintains dynamic trust assessment
    
    This component implements the O_trust function from the formal model:
    τ_t = O_trust(τ_{t-1}, x_t, metadata(x_t))
    
    It maintains a dynamic measure of trust based on user behavior, input patterns,
    system confidence, and historical interactions.
    """
    
    def __init__(self, initial_trust: float = 0.5):
        self.logger = logging.getLogger(__name__)
        self.current_trust = max(0.0, min(1.0, initial_trust))
        self.baseline_trust = initial_trust
        self.trust_history: List[float] = [initial_trust]
        self.trust_events: List[TrustEvent] = []
        self.decay_rate = 0.95  # Trust decay rate over time
        self.last_update = time.time()
        
        # Trust scoring parameters
        self.min_trust = 0.0
        self.max_trust = 1.0
        self.event_memory_window = 3600  # 1 hour in seconds
        
    def update_trust(self, input_text: str, metadata: Dict[str, Any]) -> float:
        """
        Update trust score based on new input and metadata
        
        Args:
            input_text: Current input text
            metadata: Additional metadata about the input
            
        Returns:
            float: Updated trust score
        """
        current_time = time.time()
        
        # Apply time decay
        self._apply_time_decay(current_time)
        
        # Analyze input for trust indicators
        trust_impact = self._analyze_input_trust(input_text, metadata)
        
        # Update trust score
        self.current_trust = self._calculate_new_trust(trust_impact)
        
        # Record trust event
        if abs(trust_impact) > 0.01:  # Only record significant changes
            event = TrustEvent(
                timestamp=current_time,
                event_type="input_analysis",
                impact=trust_impact,
                description=f"Trust impact from input analysis: {trust_impact:.3f}",
                metadata=metadata
            )
            self.trust_events.append(event)
        
        # Update history
        self.trust_history.append(self.current_trust)
        self.last_update = current_time
        
        # Cleanup old events
        self._cleanup_old_events(current_time)
        
        self.logger.debug(f"Trust score updated: {self.current_trust:.3f}")
        return self.current_trust
    
    def _analyze_input_trust(self, input_text: str, metadata: Dict[str, Any]) -> float:
        """Analyze input for trust indicators"""
        trust_change = 0.0
        
        # Check input length (very long inputs might be suspicious)
        if len(input_text) > 1000:
            trust_change -= 0.05
        
        # Check for suspicious patterns
        suspicious_patterns = [
            "hack", "exploit", "bypass", "override", "ignore",
            "jailbreak", "prompt injection", "system prompt"
        ]
        
        suspicion_count = sum(1 for pattern in suspicious_patterns 
                             if pattern.lower() in input_text.lower())
        trust_change -= suspicion_count * 0.1
        
        # Check metadata for trust indicators
        if metadata:
            # Source reputation
            source_reputation = metadata.get("source_reputation", 0.5)
            trust_change += (source_reputation - 0.5) * 0.1
            
            # Previous violations
            violation_count = metadata.get("previous_violations", 0)
            trust_change -= violation_count * 0.05
            
            # Authentication status
            if metadata.get("authenticated", False):
                trust_change += 0.1
            
            # Rate limiting violations
            if metadata.get("rate_limited", False):
                trust_change -= 0.2
        
        # Check for positive indicators
        if any(word in input_text.lower() for word in ["please", "thank", "help"]):
            trust_change += 0.02
        
        return trust_change
    
    def _calculate_new_trust(self, trust_impact: float) -> float:
        """Calculate new trust score with smoothing"""
        # Apply impact with diminishing returns
        impact_weight = 0.3  # How much new events affect trust
        
        # Use sigmoid function to prevent extreme changes
        adjusted_impact = math.tanh(trust_impact * 5) * impact_weight
        
        new_trust = self.current_trust + adjusted_impact
        
        # Ensure trust stays within bounds
        return max(self.min_trust, min(self.max_trust, new_trust))
    
    def _apply_time_decay(self, current_time: float):
        """Apply time-based decay to trust score"""
        time_elapsed = current_time - self.last_update
        
        # Don't decay if less than 5 minutes have passed
        if time_elapsed < 300:
            return
        
        # Decay factor based on time elapsed (hours)
        hours_elapsed = time_elapsed / 3600
        decay_factor = self.decay_rate ** hours_elapsed
        
        # Gradually return to baseline
        self.current_trust = (self.current_trust * decay_factor + 
                             self.baseline_trust * (1 - decay_factor))
    
    def _cleanup_old_events(self, current_time: float):
        """Remove old trust events outside the memory window"""
        cutoff_time = current_time - self.event_memory_window
        self.trust_events = [
            event for event in self.trust_events 
            if event.timestamp >= cutoff_time
        ]
        
        # Limit trust history size
        if len(self.trust_history) > 1000:
            self.trust_history = self.trust_history[-1000:]
    
    def record_policy_violation(self, policy_id: str, severity: str):
        """Record a policy violation event"""
        severity_impact = {
            "low": -0.05,
            "medium": -0.1,
            "high": -0.2,
            "critical": -0.3
        }
        
        impact = severity_impact.get(severity, -0.1)
        
        event = TrustEvent(
            timestamp=time.time(),
            event_type="policy_violation",
            impact=impact,
            description=f"Policy violation: {policy_id} (severity: {severity})",
            metadata={"policy_id": policy_id, "severity": severity}
        )
        
        self.trust_events.append(event)
        self.current_trust = self._calculate_new_trust(impact)
        self.trust_history.append(self.current_trust)
        
        self.logger.warning(f"Policy violation recorded: {policy_id}, trust: {self.current_trust:.3f}")
    
    def record_successful_interaction(self, confidence: float = 0.8):
        """Record a successful interaction"""
        # Positive reinforcement for successful interactions
        impact = 0.02 * confidence
        
        event = TrustEvent(
            timestamp=time.time(),
            event_type="successful_interaction",
            impact=impact,
            description=f"Successful interaction (confidence: {confidence:.3f})",
            metadata={"confidence": confidence}
        )
        
        self.trust_events.append(event)
        self.current_trust = self._calculate_new_trust(impact)
        self.trust_history.append(self.current_trust)
    
    def get_trust_level(self) -> str:
        """Get categorical trust level"""
        if self.current_trust >= 0.8:
            return "high"
        elif self.current_trust >= 0.6:
            return "medium"
        elif self.current_trust >= 0.3:
            return "low"
        else:
            return "critical"
    
    def get_trust_metrics(self) -> TrustMetrics:
        """Get comprehensive trust metrics"""
        confidence_level = self._calculate_confidence_level()
        recent_events = [
            event for event in self.trust_events 
            if event.timestamp >= time.time() - 3600  # Last hour
        ]
        
        return TrustMetrics(
            current_score=self.current_trust,
            baseline_score=self.baseline_trust,
            confidence_level=confidence_level,
            recent_events=recent_events,
            score_history=self.trust_history[-50:]  # Last 50 scores
        )
    
    def _calculate_confidence_level(self) -> float:
        """Calculate confidence in the current trust score"""
        # Base confidence on number of recent interactions
        recent_events = len([
            event for event in self.trust_events 
            if event.timestamp >= time.time() - 3600
        ])
        
        # More recent events = higher confidence
        base_confidence = min(recent_events / 10, 1.0)
        
        # Adjust based on trust stability
        if len(self.trust_history) > 5:
            recent_scores = self.trust_history[-5:]
            variance = sum((score - self.current_trust) ** 2 for score in recent_scores) / len(recent_scores)
            stability_bonus = max(0, 1 - variance * 10)
            base_confidence *= stability_bonus
        
        return base_confidence
    
    def reset_trust(self, new_baseline: Optional[float] = None):
        """Reset trust to baseline"""
        if new_baseline is not None:
            self.baseline_trust = max(0.0, min(1.0, new_baseline))
        
        self.current_trust = self.baseline_trust
        self.trust_history = [self.baseline_trust]
        self.trust_events = []
        self.last_update = time.time()
        
        self.logger.info(f"Trust reset to baseline: {self.baseline_trust:.3f}")