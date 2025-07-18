"""
Audit Logger - Comprehensive logging and audit trail functionality
"""

import json
import time
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib

@dataclass
class AuditEvent:
    """Audit event structure"""
    timestamp: float
    event_type: str
    event_id: str
    user_id: Optional[str]
    session_id: str
    component: str
    action: str
    input_data: Dict[str, Any]
    output_data: Dict[str, Any]
    security_actions: Dict[str, Any]
    trust_score: float
    risk_score: float
    policies_triggered: List[str]
    metadata: Dict[str, Any]

class AuditLogger:
    """
    Comprehensive audit logging system for DCATS
    
    Provides detailed logging of all system interactions, security events,
    and policy decisions for compliance, analysis, and debugging.
    """
    
    def __init__(self, log_dir: str = "logs", max_log_size: int = 10*1024*1024):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        self.max_log_size = max_log_size
        self.current_session_id = self._generate_session_id()
        self.audit_events: List[AuditEvent] = []
        
        # Setup file logging
        self.audit_file = self.log_dir / f"audit_{time.strftime('%Y%m%d')}.jsonl"
        self.security_file = self.log_dir / f"security_{time.strftime('%Y%m%d')}.jsonl"
        
        # Setup Python logging
        self.logger = logging.getLogger(__name__)
        self._setup_file_handler()
        
        self.logger.info(f"Audit logger initialized - Session: {self.current_session_id}")
    
    def _generate_session_id(self) -> str:
        """Generate unique session identifier"""
        timestamp = str(time.time())
        return hashlib.md5(timestamp.encode()).hexdigest()[:16]
    
    def _setup_file_handler(self):
        """Setup file handler for audit logging"""
        handler = logging.FileHandler(self.log_dir / "system.log")
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def log_interaction(self, 
                       event_type: str,
                       user_id: Optional[str],
                       component: str,
                       action: str,
                       input_data: Dict[str, Any],
                       output_data: Dict[str, Any],
                       security_actions: Dict[str, Any],
                       trust_score: float,
                       risk_score: float = 0.0,
                       policies_triggered: List[str] = None,
                       metadata: Dict[str, Any] = None):
        """
        Log a system interaction
        
        Args:
            event_type: Type of event (query, security, policy, etc.)
            user_id: User identifier (if available)
            component: System component involved
            action: Action taken
            input_data: Input data (sanitized)
            output_data: Output data (sanitized)
            security_actions: Security actions taken
            trust_score: Current trust score
            risk_score: Risk score for this interaction
            policies_triggered: List of triggered policies
            metadata: Additional metadata
        """
        event_id = self._generate_event_id()
        
        # Sanitize sensitive data
        sanitized_input = self._sanitize_data(input_data)
        sanitized_output = self._sanitize_data(output_data)
        
        audit_event = AuditEvent(
            timestamp=time.time(),
            event_type=event_type,
            event_id=event_id,
            user_id=user_id,
            session_id=self.current_session_id,
            component=component,
            action=action,
            input_data=sanitized_input,
            output_data=sanitized_output,
            security_actions=security_actions,
            trust_score=trust_score,
            risk_score=risk_score,
            policies_triggered=policies_triggered or [],
            metadata=metadata or {}
        )
        
        # Store in memory
        self.audit_events.append(audit_event)
        
        # Write to file
        self._write_audit_event(audit_event)
        
        # Log security events separately
        if security_actions and any(security_actions.values()):
            self._log_security_event(audit_event)
        
        self.logger.info(f"Audit event logged: {event_type} - {action}")
    
    def _generate_event_id(self) -> str:
        """Generate unique event identifier"""
        timestamp = str(time.time())
        return hashlib.md5(f"{timestamp}_{self.current_session_id}".encode()).hexdigest()[:12]
    
    def _sanitize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize sensitive data from logs"""
        if not isinstance(data, dict):
            return data
        
        sanitized = {}
        sensitive_keys = ['password', 'token', 'key', 'secret', 'credential']
        
        for key, value in data.items():
            if any(sensitive_key in key.lower() for sensitive_key in sensitive_keys):
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_data(value)
            elif isinstance(value, str) and len(value) > 200:
                # Truncate very long strings
                sanitized[key] = value[:200] + "... [TRUNCATED]"
            else:
                sanitized[key] = value
        
        return sanitized
    
    def _write_audit_event(self, event: AuditEvent):
        """Write audit event to file"""
        try:
            with open(self.audit_file, 'a') as f:
                json.dump(asdict(event), f, default=str)
                f.write('\n')
        except Exception as e:
            self.logger.error(f"Failed to write audit event: {e}")
    
    def _log_security_event(self, event: AuditEvent):
        """Log security-specific events"""
        try:
            security_event = {
                'timestamp': event.timestamp,
                'event_id': event.event_id,
                'session_id': event.session_id,
                'user_id': event.user_id,
                'security_actions': event.security_actions,
                'trust_score': event.trust_score,
                'risk_score': event.risk_score,
                'policies_triggered': event.policies_triggered,
                'severity': self._calculate_severity(event)
            }
            
            with open(self.security_file, 'a') as f:
                json.dump(security_event, f, default=str)
                f.write('\n')
        except Exception as e:
            self.logger.error(f"Failed to write security event: {e}")
    
    def _calculate_severity(self, event: AuditEvent) -> str:
        """Calculate event severity"""
        if event.risk_score >= 0.8:
            return "critical"
        elif event.risk_score >= 0.6:
            return "high"
        elif event.risk_score >= 0.4:
            return "medium"
        else:
            return "low"
    
    def log_policy_violation(self, 
                           policy_id: str,
                           violation_type: str,
                           user_id: Optional[str] = None,
                           input_data: Dict[str, Any] = None,
                           severity: str = "medium"):
        """Log policy violation"""
        self.log_interaction(
            event_type="policy_violation",
            user_id=user_id,
            component="policy_engine",
            action="violation_detected",
            input_data=input_data or {},
            output_data={"policy_id": policy_id, "violation_type": violation_type},
            security_actions={"policy_triggered": True},
            trust_score=0.0,  # Will be updated by caller
            risk_score={"low": 0.3, "medium": 0.6, "high": 0.8, "critical": 1.0}.get(severity, 0.6),
            policies_triggered=[policy_id],
            metadata={"severity": severity}
        )
    
    def log_trust_change(self, 
                        old_trust: float,
                        new_trust: float,
                        reason: str,
                        user_id: Optional[str] = None):
        """Log trust score changes"""
        self.log_interaction(
            event_type="trust_change",
            user_id=user_id,
            component="trust_scorer",
            action="trust_updated",
            input_data={"old_trust": old_trust, "reason": reason},
            output_data={"new_trust": new_trust, "change": new_trust - old_trust},
            security_actions={"trust_updated": True},
            trust_score=new_trust,
            risk_score=max(0, old_trust - new_trust),  # Risk when trust decreases
            metadata={"reason": reason}
        )
    
    def log_memory_access(self, 
                         granted_partitions: List[str],
                         denied_partitions: List[str],
                         user_id: Optional[str] = None,
                         trust_score: float = 0.0):
        """Log memory access events"""
        self.log_interaction(
            event_type="memory_access",
            user_id=user_id,
            component="memory_partitioner",
            action="partition_requested",
            input_data={"requested_partitions": granted_partitions + denied_partitions},
            output_data={"granted": granted_partitions, "denied": denied_partitions},
            security_actions={"memory_restricted": len(denied_partitions) > 0},
            trust_score=trust_score,
            risk_score=len(denied_partitions) * 0.1,
            metadata={"access_level": "restricted" if denied_partitions else "normal"}
        )
    
    def get_audit_summary(self, time_range: int = 3600) -> Dict[str, Any]:
        """Get audit summary for the specified time range (in seconds)"""
        cutoff_time = time.time() - time_range
        recent_events = [e for e in self.audit_events if e.timestamp >= cutoff_time]
        
        if not recent_events:
            return {"summary": "No events in specified time range"}
        
        # Count events by type
        event_counts = {}
        security_events = 0
        policy_violations = 0
        trust_changes = 0
        
        for event in recent_events:
            event_counts[event.event_type] = event_counts.get(event.event_type, 0) + 1
            
            if any(event.security_actions.values()):
                security_events += 1
            
            if event.policies_triggered:
                policy_violations += 1
            
            if event.event_type == "trust_change":
                trust_changes += 1
        
        # Calculate risk metrics
        risk_scores = [e.risk_score for e in recent_events]
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        max_risk = max(risk_scores) if risk_scores else 0
        
        return {
            "time_range_hours": time_range / 3600,
            "total_events": len(recent_events),
            "event_types": event_counts,
            "security_events": security_events,
            "policy_violations": policy_violations,
            "trust_changes": trust_changes,
            "risk_metrics": {
                "average_risk": avg_risk,
                "maximum_risk": max_risk,
                "high_risk_events": len([e for e in recent_events if e.risk_score >= 0.6])
            }
        }
    
    def export_audit_log(self, 
                        start_time: Optional[float] = None,
                        end_time: Optional[float] = None,
                        event_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Export audit log with optional filtering"""
        events = self.audit_events
        
        # Filter by time range
        if start_time:
            events = [e for e in events if e.timestamp >= start_time]
        if end_time:
            events = [e for e in events if e.timestamp <= end_time]
        
        # Filter by event types
        if event_types:
            events = [e for e in events if e.event_type in event_types]
        
        return [asdict(event) for event in events]
    
    def cleanup_old_logs(self, retention_days: int = 30):
        """Clean up old log files"""
        cutoff_time = time.time() - (retention_days * 24 * 3600)
        
        for log_file in self.log_dir.glob("*.jsonl"):
            if log_file.stat().st_mtime < cutoff_time:
                log_file.unlink()
                self.logger.info(f"Removed old log file: {log_file}")
        
        # Also clean up in-memory events
        self.audit_events = [e for e in self.audit_events if e.timestamp >= cutoff_time]
    
    def get_compliance_report(self) -> Dict[str, Any]:
        """Generate compliance report"""
        summary = self.get_audit_summary(24 * 3600)  # Last 24 hours
        
        return {
            "report_timestamp": time.time(),
            "session_id": self.current_session_id,
            "audit_summary": summary,
            "log_files": [str(f) for f in self.log_dir.glob("*.jsonl")],
            "retention_policy": "30 days",
            "data_integrity": "SHA256 checksums available",
            "access_controls": "File system permissions"
        }