"""Shared test fixtures for mcp-witness."""

import os
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio

from mcp_witness.storage import WitnessStorage


@pytest_asyncio.fixture
async def temp_storage():
    """Create a temporary storage instance for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_witness.db"
        storage = WitnessStorage(db_path)
        await storage.connect()
        yield storage
        await storage.close()


@pytest.fixture
def sample_input_data():
    """Sample input data for testing."""
    return {
        "query": "What is the capital of France?",
        "user_id": "user_123",
        "timestamp": "2026-03-01T12:00:00Z",
    }


@pytest.fixture
def sample_output_data():
    """Sample output data for testing."""
    return {
        "answer": "Paris",
        "confidence": 0.95,
        "sources": ["wikipedia", "britannica"],
    }


@pytest.fixture
def sample_context():
    """Sample context for testing."""
    return {
        "conversation_id": "conv_abc",
        "turn_number": 3,
        "previous_topics": ["geography", "europe"],
    }
