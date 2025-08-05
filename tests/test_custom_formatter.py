import logging
import pytest
from logger import custom_formatter

def test_custom_formatter_formats_log_record():
    formatter = custom_formatter.CustomFormatter()

    # Crea un record di log simulato per ogni livello e verifica che la formattazione non sia vuota
    for level in [logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL]:
        record = logging.LogRecord(
            name="test",
            level=level,
            pathname="test_path",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        formatted = formatter.format(record)
        assert "Test message" in formatted
        # Verifica che il formato includa almeno il livello e il messaggio
        assert str(logging.getLevelName(level)) in formatted

def test_custom_formatter_handles_unknown_level():
    formatter = custom_formatter.CustomFormatter()
    # Livello non previsto nel dizionario FORMATS
    record = logging.LogRecord(
        name="test",
        level=9999,  # livello custom non previsto
        pathname="test_path",
        lineno=10,
        msg="Unknown level message",
        args=(),
        exc_info=None,
    )
    # Il formatter dovrebbe restituire None o usare un fallback (potrebbe alzare errore se non gestito)
    result = formatter.format(record)
    assert result is None or "Unknown level message" in result
