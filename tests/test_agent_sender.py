"""
Tests for AgentSender (agent/sender.py)
Uses unittest.mock to avoid real HTTP calls.
"""

import json
import os
import sys
import threading
import time
import unittest
from collections import deque
from unittest.mock import MagicMock, patch, call

# Ensure agent directory is on path
AGENT_DIR = os.path.join(os.path.dirname(__file__), "..", "agent")
sys.path.insert(0, AGENT_DIR)


class TestAgentSender(unittest.TestCase):
    """Unit tests for AgentSender event queuing and batch logic."""

    def _make_sender(self):
        """Import fresh sender each time to avoid module-level singleton state."""
        # We need to import inside the test to pick up mocks
        import importlib
        import sender as sender_mod
        importlib.reload(sender_mod)
        return sender_mod.AgentSender()

    @patch("sender.requests.Session")
    def test_enqueue_adds_to_queue(self, mock_session_cls):
        mock_session_cls.return_value = MagicMock()
        from sender import AgentSender
        s = AgentSender()
        s.enqueue("file", "modified", {"path": "/tmp/test.txt"})
        self.assertEqual(len(s._queue), 1)
        event = s._queue[0]
        self.assertEqual(event["type"], "file")
        self.assertEqual(event["action"], "modified")

    @patch("sender.requests.Session")
    def test_batch_flush_clears_queue(self, mock_session_cls):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_session = MagicMock()
        mock_session.post.return_value = mock_resp
        mock_session_cls.return_value = mock_session

        from sender import AgentSender
        s = AgentSender()

        for i in range(5):
            s.enqueue("file", "created", {"path": f"/tmp/file{i}.txt"})

        s._flush()  # call directly (no threads)
        self.assertEqual(len(s._queue), 0)

    @patch("sender.requests.Session")
    def test_failed_post_goes_to_retry_queue(self, mock_session_cls):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"
        mock_session = MagicMock()
        mock_session.post.return_value = mock_resp
        mock_session_cls.return_value = mock_session

        from sender import AgentSender
        s = AgentSender()
        s.enqueue("usb", "mounted", {"label": "BadDrive", "authorized": False})
        s._flush()
        # Event should be moved to retry queue
        self.assertEqual(len(s._retry_queue), 1)

    @patch("sender.requests.Session")
    def test_offline_buffer_written_on_failure(self, mock_session_cls):
        import tempfile
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_resp.text = "Unavailable"
        mock_session = MagicMock()
        mock_session.post.return_value = mock_resp
        mock_session_cls.return_value = mock_session

        import config as agent_config
        tmp_buf = tempfile.mktemp(suffix=".jsonl")
        original = agent_config.OFFLINE_BUFFER_PATH
        agent_config.OFFLINE_BUFFER_PATH = tmp_buf

        try:
            from sender import AgentSender
            s = AgentSender()
            s.enqueue("process", "started", {"name": "test.exe"})
            s._flush()

            self.assertTrue(os.path.exists(tmp_buf))
            with open(tmp_buf) as f:
                lines = [l.strip() for l in f if l.strip()]
            self.assertGreaterEqual(len(lines), 1)
            event = json.loads(lines[0])
            self.assertEqual(event["type"], "process")
        finally:
            agent_config.OFFLINE_BUFFER_PATH = original
            if os.path.exists(tmp_buf):
                os.remove(tmp_buf)

    @patch("sender.requests.Session")
    def test_offline_buffer_replayed_on_start(self, mock_session_cls):
        import tempfile
        import config as agent_config

        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_session = MagicMock()
        mock_session.post.return_value = mock_resp
        mock_session_cls.return_value = mock_session

        tmp_buf = tempfile.mktemp(suffix=".jsonl")
        agent_config.OFFLINE_BUFFER_PATH = tmp_buf

        # Pre-populate buffer
        buffered = {
            "device_id": "test-host",
            "type": "file",
            "action": "modified",
            "details": {"path": "/tmp/a.txt"},
        }
        with open(tmp_buf, "w") as f:
            f.write(json.dumps(buffered) + "\n")

        try:
            from sender import AgentSender
            s = AgentSender()
            s._replay_offline_buffer()
            # Buffer should be deleted after successful replay
            self.assertFalse(os.path.exists(tmp_buf))
        finally:
            agent_config.OFFLINE_BUFFER_PATH = original if 'original' in dir() else tmp_buf
            if os.path.exists(tmp_buf):
                os.remove(tmp_buf)


class TestBatchEndpointFallback(unittest.TestCase):
    """Test that sender falls back to individual POSTs when batch endpoint fails."""

    @patch("sender.requests.Session")
    def test_fallback_to_individual_posts(self, mock_session_cls):
        mock_session = MagicMock()

        batch_resp = MagicMock()
        batch_resp.status_code = 404  # batch endpoint not found

        individual_resp = MagicMock()
        individual_resp.status_code = 201

        # First call (batch) fails, subsequent calls (individual) succeed
        mock_session.post.side_effect = [batch_resp, individual_resp, individual_resp]
        mock_session_cls.return_value = mock_session

        from sender import AgentSender
        s = AgentSender()
        result = s._post_batch([
            {"device_id": "h", "type": "file", "action": "created", "details": {}},
            {"device_id": "h", "type": "file", "action": "deleted", "details": {}},
        ])
        self.assertTrue(result)
        # Should have called post 3 times: 1 batch + 2 individual
        self.assertEqual(mock_session.post.call_count, 3)


if __name__ == "__main__":
    unittest.main()
