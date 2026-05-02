# config.py
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    JWT_SECRET = os.getenv('JWT_SECRET', 'fraudshield-secret-key')
    JWT_ALGO = "HS256"
    JWT_EXPIRY_HOURS = 12
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024
    RATELIMIT_DEFAULT = "200 per day;50 per hour"
    RATELIMIT_STORAGE_URL = "memory://"
    DATABASE_PATH = "fraudshield.db"
    
    ALLOWED_IMAGE_TYPES = {'image/jpeg', 'image/png', 'image/jpg', 'image/gif', 'image/webp'}
    ALLOWED_DOC_TYPES = {'application/pdf', 'application/msword', 
                         'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                         'text/plain'}
    ALLOWED_VIDEO_TYPES = {'video/mp4', 'video/webm', 'video/quicktime', 'video/x-msvideo'}