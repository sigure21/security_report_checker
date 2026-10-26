"""Offline device-login cancellation checks."""

import threading
import time
import unittest
from unittest.mock import patch

from github_api import GitHubAPIError, poll_device_token


class DeviceFlowTests(unittest.TestCase):
    def test_cancel_during_wait_stops_before_next_network_request(self):
        cancelled = threading.Event()
        timer = threading.Timer(0.05, cancelled.set)
        timer.start()
        self.addCleanup(timer.cancel)

        started = time.monotonic()
        with patch("github_api.requests.post", side_effect=AssertionError("Unexpected OAuth request")) as post:
            with self.assertRaisesRegex(GitHubAPIError, "취소"):
                poll_device_token("client", "device", interval=5, expires_in=20,
                                  should_stop=cancelled.is_set)
        self.assertLess(time.monotonic() - started, 1.0)
        post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
