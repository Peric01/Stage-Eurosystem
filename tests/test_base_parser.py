import pytest
from parsers.base_parser import InterfaceLogParser

def test_interface_log_parser_is_abstract():
    with pytest.raises(TypeError):
        InterfaceLogParser()
