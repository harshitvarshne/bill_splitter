from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker

MYSQL_USER = "root"
MYSQL_PASSWORD = "1122"
MYSQL_HOST = "localhost"
MYSQL_DB = "bill_splitter"

DATABASE_URL = "postgresql://neondb_owner:npg_ZP5BlHyXWa7x@ep-spring-mud-aepgyzf5-pooler.c-2.us-east-2.aws.neon.tech/mydb?sslmode=require&channel_binding=require"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()
