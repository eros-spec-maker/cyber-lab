import builtins
import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "keylogger_educacional.py"


def load_app():
    fake_pynput = types.ModuleType("pynput")
    fake_pynput.keyboard = types.SimpleNamespace(Key=object())
    previous = sys.modules.get("pynput")
    sys.modules["pynput"] = fake_pynput
    try:
        spec = importlib.util.spec_from_file_location("keylogger_educacional_test", MODULE_PATH)
        app = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(app)
        return app
    finally:
        if previous is None:
            sys.modules.pop("pynput", None)
        else:
            sys.modules["pynput"] = previous


app = load_app()


class KeyloggerConsentTests(unittest.TestCase):
    def test_consent_accepts_exact_word(self):
        with patch.object(builtins, "input", return_value="CONCORDO"):
            self.assertTrue(app._confirmar())

    def test_consent_rejects_other_answer(self):
        with patch.object(builtins, "input", return_value="NAO"):
            self.assertFalse(app._confirmar())

    def test_consent_ignores_whitespace_and_case(self):
        with patch.object(builtins, "input", return_value="  concordo  "):
            self.assertTrue(app._confirmar())

    def test_log_appends_one_line_to_temporary_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            logfile = Path(temporary) / "keylog_test.txt"
            with patch.object(app, "LOG_FILE", str(logfile)):
                app._log("evento sintético de teste")

            lines = logfile.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            self.assertIn("evento sintético de teste", lines[0])


if __name__ == "__main__":
    unittest.main()
