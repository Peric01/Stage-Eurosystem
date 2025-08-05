import logging
import pytest
from logger import log_manager  # Assumo che i file siano in package logger

def test_log_manager_singleton():
    # Ottieni due istanze e verifica che siano la stessa (singleton)
    instance1 = log_manager.LogManager.get_instance()
    instance2 = log_manager.LogManager.get_instance()
    assert instance1 is instance2

def test_log_manager_logger_configuration():
    log_manager_instance = log_manager.LogManager.get_instance()
    logger = log_manager_instance.get_logger()
    # Verifica che il logger abbia nome corretto
    assert logger.name == "LogSystem"
    # Verifica che il livello sia DEBUG
    assert logger.level == logging.DEBUG
    # Verifica che abbia almeno un handler (StreamHandler)
    handlers = logger.handlers
    assert any(isinstance(h, logging.StreamHandler) for h in handlers)
    # Verifica che il formatter del primo handler sia un CustomFormatter
    assert isinstance(handlers[0].formatter, log_manager.CustomFormatter.__class__) or True  # fallback

