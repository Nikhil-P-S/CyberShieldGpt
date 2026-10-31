# ============================================================
# CYBERSHIELD GPT
# CONFIGURATION
# ============================================================

import os
from dotenv import load_dotenv


# Load variables from .env
load_dotenv()


# ------------------------------------------------------------
# GROQ CONFIGURATION
# ------------------------------------------------------------

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

GROQ_MODEL = os.getenv("GROQ_MODEL")


# ------------------------------------------------------------
# PROJECT PATHS
# ------------------------------------------------------------

DATA_DIR = "data"

RAG_DIR = "rag"

DATABASE_DIR = "database"

SECURITY_LOG_FILE = os.path.join(
    DATA_DIR,
    "security_logs.csv"
)

DATABASE_PATH = os.path.join(
    DATABASE_DIR,
    "cyber_shield.db"
)


# ------------------------------------------------------------
# CREATE DIRECTORIES IF THEY DO NOT EXIST
# ------------------------------------------------------------

os.makedirs(DATA_DIR, exist_ok=True)

os.makedirs(RAG_DIR, exist_ok=True)

os.makedirs(DATABASE_DIR, exist_ok=True)















