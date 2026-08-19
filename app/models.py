import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from sqlalchemy import Column, String, DateTime, JSON, Integer, ForeignKey, Enum, Index
from sqlalchemy.orm import relationship
from app.db import Base

class DispositionEnum(str, PyEnum):
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    SHADOW_BLOCKED = "SHADOW_BLOCKED"

class Agent(Base):
    __tablename__ = "agents"

    agent_id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    declared_scope = Column(JSON, nullable=False)  # JSON allowed scope
    created_at = Column(
        DateTime, 
        default=lambda: datetime.now(timezone.utc), 
        nullable=False
    )

    # Relationship to tool call logs
    logs = relationship("ToolCallLog", back_populates="agent", cascade="all, delete-orphan")

class ToolCallLog(Base):
    __tablename__ = "tool_call_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(
        DateTime, 
        default=lambda: datetime.now(timezone.utc), 
        nullable=False
    )
    agent_id = Column(String, ForeignKey("agents.agent_id"), nullable=False)
    session_id = Column(String, nullable=False)
    tool_name = Column(String, nullable=False)
    parameters_sanitized = Column(JSON, nullable=False)  # Redacted parameters JSON
    rule_evaluations = Column(JSON, nullable=False)      # Evaluated rule outcomes JSON
    final_disposition = Column(
        Enum(DispositionEnum, native_enum=False), 
        nullable=False
    )
    latency_ms = Column(Integer, nullable=True)          # Nullable latency in milliseconds

    # Relationship back to the agent
    agent = relationship("Agent", back_populates="logs")

class RateLimitEvent(Base):
    __tablename__ = "rate_limit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    agent_id = Column(String, nullable=False, index=True)
    tool_name = Column(String, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)

    __table_args__ = (
        Index("ix_rate_limit_events_lookup", "agent_id", "tool_name", "timestamp"),
    )

class SequenceEvent(Base):
    __tablename__ = "sequence_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String, nullable=False, index=True)
    agent_id = Column(String, nullable=False, index=True)
    tool_name = Column(String, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)

    __table_args__ = (
        Index("ix_sequence_events_lookup", "session_id", "tool_name", "timestamp"),
        Index("ix_sequence_events_integrity", "agent_id", "session_id", "tool_name"),
    )
