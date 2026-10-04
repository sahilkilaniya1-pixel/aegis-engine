from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.sql import func
from app.database import Base

class Target(Base):
    __tablename__ = "targets"
    
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    scan_type = Column(String, nullable=False)  # e.g., 'recon', 'port_scan', 'vulnerability'
    status = Column(String, default="pending")   # pending, running, completed, failed
    results = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False)  # Low, Medium, High, Critical
    description = Column(Text)
    raw_evidence = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class OOBInteractionModel(Base):
    __tablename__ = "oob_interactions"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, index=True)
    source_ip = Column(String)
    method = Column(String)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    headers = Column(JSON, nullable=True)  # Headers ke liye JSON format behtar rahega
    body = Column(Text, nullable=True)