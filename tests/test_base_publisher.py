import pytest
from publishers.base_publisher import InterfaceDataPublisher

def test_interface_publish_must_be_implemented():
    class DummyPublisher(InterfaceDataPublisher):
        pass

    with pytest.raises(TypeError):
        DummyPublisher()
