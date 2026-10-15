"""Reject upstream route composition or read-visibility drift."""
import tempfile
import unittest
from pathlib import Path
import rpc_scrape

class CompositionTests(unittest.TestCase):
    def check(self, guard=True, extra=""):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "node_runtime").mkdir()
            groups = " @ ".join(rpc_scrape.EXPECTED_COMPOSITION)
            suffix = " |> guard_reads visibility" if guard else ""
            (root / "node_runtime/node_rpc_server.ml").write_text(
                f"let read_dispatch visibility =\n  {groups}{extra}{suffix}\n"
                "let dispatch visibility =\n  read_dispatch visibility\n")
            rpc_scrape.check_composition(root)

    def test_reviewed_visibility_guard(self):
        self.check()

    def test_missing_guard_rejected(self):
        with self.assertRaisesRegex(rpc_scrape.ScrapeError, "visibility guard"):
            self.check(guard=False)

    def test_new_unscraped_group_rejected(self):
        with self.assertRaisesRegex(rpc_scrape.ScrapeError, "not scrape"):
            self.check(extra=" @ secret_dispatch")

if __name__ == "__main__":
    unittest.main()
