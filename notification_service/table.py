from notification_service.database import Base, engine

Base.metadata.create_all(bind=engine)
