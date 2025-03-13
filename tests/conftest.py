import pytest


@pytest.fixture(autouse=True)
def setup_test_env():
    """Setup any state specific to the execution of the given test function"""
    yield  # This is where the testing happens


def pytest_collection_modifyitems(items):
    """Add test categorization and metadata"""
    for item in items:
        if "get_pentests" in item.name:
            item.add_marker(pytest.mark.pentests)
        elif "attack_paths" in item.name:
            item.add_marker(pytest.mark.attack_paths)
        elif "weaknesses" in item.name:
            item.add_marker(pytest.mark.weaknesses)
