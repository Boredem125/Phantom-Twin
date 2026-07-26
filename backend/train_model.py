"""
train_model.py — One-shot script to train the Isolation Forest after data generation.

Usage:
    python backend/train_model.py
"""

import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

from backend.models.detector import train_isolation_forest

if __name__ == "__main__":
    train_isolation_forest("backend/data/train.csv")
    print("✓ Model trained and saved to backend/models/iso_forest.pkl")
