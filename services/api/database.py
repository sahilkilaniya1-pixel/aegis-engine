import os
import datetime
from sqlalchemy import create_engine, Column, String, Float, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# PostgreSQL Connection URL from Environment Variable
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://aegis_user:aegis_password@postgres:5432/aegis_db")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ScanRecord(Base):
    __tablename__ = "scan_records"

    task_id = Column(String, primary_key=True, index=True)
    target_url = Column(String, index=True)
    status = Column(String, default="PENDING")
    confidence_score = Column(Float, nullable=True)
    reasoning = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

def init_db():
    """Create tables if they don't exist"""
    Base.metadata.create_all(bind=engine)