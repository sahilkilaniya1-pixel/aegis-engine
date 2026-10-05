from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON, Boolean
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
    cwe = Column(String, nullable=True, default="CWE-200")
    owasp_category = Column(String, nullable=True, default="A01:2021-Broken Access Control")
    description = Column(Text)
    remediation = Column(Text, nullable=True)
    poc = Column(Text, nullable=True)
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

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="tester")  # admin, tester, viewer
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())