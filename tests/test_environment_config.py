import pytest
from config.environment_config import ask_log_level
from unittest.mock import patch

def test_cli_choice_valid(monkeypatch, capfd):
    for cli_input, expected in [("1", "DEBUG"), ("2", "INFO"), ("3", "WARNING")]:
        level = ask_log_level(cli_input)
        out, err = capfd.readouterr()
        assert level == expected
        assert f"Livello di log impostato su: {expected}" in out

def test_cli_choice_invalid(monkeypatch, capfd):
    level = ask_log_level("9")
    out, err = capfd.readouterr()
    assert level == "DEBUG"
    assert "Scelta da CLI non valida" in out

@patch("builtins.input", return_value="")
def test_input_empty_returns_default(mock_input, capfd):
    level = ask_log_level(None)
    out, err = capfd.readouterr()
    assert level == "DEBUG"
    assert "Nessuna scelta effettuata" in out

@patch("builtins.input", return_value="2")
def test_input_valid_choice(mock_input, capfd):
    level = ask_log_level(None)
    out, err = capfd.readouterr()
    assert level == "INFO"
    assert "Livello di log impostato su: INFO" in out

@patch("builtins.input", return_value="9")
def test_input_invalid_choice_returns_default(mock_input, capfd):
    level = ask_log_level(None)
    out, err = capfd.readouterr()
    assert level == "DEBUG"
    assert "Scelta non valida" in out
