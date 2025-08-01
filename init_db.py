from database import Base, engine
from models import PaymentSettlement

# This will create the table if it doesn't already exist
Base.metadata.create_all(bind=engine)
print("✅ Tables synced.")
