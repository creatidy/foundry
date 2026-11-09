"""Offline tests for the disabled host MI execution boundary."""

import unittest

from host_mi_provenance import require_verified_host_mi
import installed_mi_lifecycle_scenario as scenario


class HostMIProvenanceTests(unittest.TestCase):
    def test_unconditionally_refuses_host_execution(self):
        with self.assertRaisesRegex(RuntimeError, "host MI execution disabled"):
            require_verified_host_mi()

    def test_installed_scenario_cannot_bypass_gate(self):
        with self.assertRaisesRegex(RuntimeError, "host MI execution disabled"):
            scenario.controlled_cuts()


if __name__ == "__main__":
    unittest.main()
