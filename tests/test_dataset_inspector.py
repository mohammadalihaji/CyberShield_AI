import unittest
from ml.dataset_inspector import DatasetInspector
from ml.config import DATASET_DIR


class TestDatasetInspector(unittest.TestCase):

    def test_inspector_graceful_missing_dataset(self):
        inspector = DatasetInspector(DATASET_DIR)
        result = inspector.inspect()
        self.assertIn("status", result)
        # Without CompPhish V4 tabular data, should report cleanly without crash
        self.assertIn(result["status"], ("NOT_FOUND", "NO_TABULAR_DATA"))


if __name__ == "__main__":
    unittest.main()
