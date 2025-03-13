import pytest
from connectors.core.connector import ConnectorError
from horizonAi.operations import operations
from tests.data import config, invalid_config


def test_check_health():
    """Test health check functionality"""
    health_check = operations.get('check_health')
    resp = health_check(config)
    assert resp == True


def test_failed_auth():
    """Test behavior with invalid credentials"""
    health_check = operations.get('check_health')
    with pytest.raises(ConnectorError) as exc_info:
        health_check(invalid_config)
    assert "Authentication failed" in str(exc_info.value)


def test_get_pentests():
    """Test retrieving pentest list"""
    get_pentests = operations.get('get_pentests')
    params = {
        "page_size": 10,
        "page_num": 1
    }
    resp = get_pentests(config, params)
    assert 'pentests_page' in resp
    pentests = resp['pentests_page'].get('pentests', [])
    assert isinstance(pentests, list)
    if pentests:
        assert 'op_id' in pentests[0]


def test_get_pentests_with_filters():
    """Test pentest retrieval with filters"""
    get_pentests = operations.get('get_pentests')
    params = {
        "page_size": 10,
        "state": "done",
        "order_by": "launched_at",
        "sort_order": "DESC"
    }
    resp = get_pentests(config, params)
    pentests = resp['pentests_page'].get('pentests', [])
    if pentests:
        assert all(p.get('state') == 'done' for p in pentests)


def test_get_pentests_with_attack_paths():
    """Test pentest retrieval including attack paths"""
    get_pentests = operations.get('get_pentests')
    params = {
        "page_size": 10,
        "include_attack_paths": True
    }
    resp = get_pentests(config, params)
    pentests = resp['pentests_page'].get('pentests', [])
    if pentests:
        assert 'attack_paths_page' in pentests[0]


def test_get_pentests_with_weaknesses():
    """Test pentest retrieval including weaknesses"""
    get_pentests = operations.get('get_pentests')
    params = {
        "page_size": 10,
        "include_weaknesses": True
    }
    resp = get_pentests(config, params)
    pentests = resp['pentests_page'].get('pentests', [])
    if pentests:
        assert 'weaknesses_page' in pentests[0]


def test_get_pentest_with_attacks_and_weaknesses():
    """Test pentest retrieval including attacks and weaknesses"""
    get_pentests = operations.get('get_pentests')
    params = {
        "date_to": "",
        "page_num": "",
        "date_from": "",
        "page_size": "",
        "client_name": "",
        "text_search": "",
        "include_attack_paths": True,
        "include_weaknesses": True
    }
    resp = get_pentests(config, params)
    pentests = resp['pentests_page'].get('pentests', [])
    if pentests:
        assert 'attack_paths_page' in pentests[0]
        assert 'weaknesses_page' in pentests[0]


def test_get_attack_paths():
    """Test retrieving attack paths for a specific pentest"""
    # First get a pentest ID
    get_pentests = operations.get('get_pentests')
    pentests_resp = get_pentests(config, {"page_size": 1})
    pentests = pentests_resp['pentests_page'].get('pentests', [])

    if pentests:
        op_id = pentests[0]['op_id']
        get_paths = operations.get('get_attack_paths')
        params = {
            "op_id": op_id,
            "page_size": 10
        }
        resp = get_paths(config, params)
        assert 'attack_paths_page' in resp


def test_get_weaknesses():
    """Test retrieving weaknesses for a specific pentest"""
    # First get a pentest ID
    get_pentests = operations.get('get_pentests')
    pentests_resp = get_pentests(config, {"page_size": 1})
    pentests = pentests_resp['pentests_page'].get('pentests', [])

    if pentests:
        op_id = pentests[0]['op_id']
        get_weaknesses = operations.get('get_weaknesses')
        params = {
            "op_id": op_id,
            "page_size": 10
        }
        resp = get_weaknesses(config, params)
        assert 'weaknesses_page' in resp


def test_missing_required_params():
    """Test behavior when required parameters are missing"""
    get_paths = operations.get('get_attack_paths')
    with pytest.raises(Exception) as exc_info:
        get_paths(config, {})
    assert "op_id is required" in str(exc_info.value)


def test_invalid_parameters():
    """Test behavior with invalid parameter values"""
    get_pentests = operations.get('get_pentests')
    params = {
        "page_size": "invalid",  # Should be integer
        "order_by": "INVALID",  # Should be one of the valid fields
        "sort_order": "INVALID"  # Should be ASC or DESC
    }
    with pytest.raises(Exception):
        get_pentests(config, params)


def test_pagination():
    """Test pagination functionality"""
    get_pentests = operations.get('get_pentests')
    # Get first page
    page1_params = {
        "page_size": 2,
        "page_num": 1
    }
    page1_resp = get_pentests(config, page1_params)
    page1_pentests = page1_resp['pentests_page'].get('pentests', [])

    # Get second page
    page2_params = {
        "page_size": 2,
        "page_num": 2
    }
    page2_resp = get_pentests(config, page2_params)
    page2_pentests = page2_resp['pentests_page'].get('pentests', [])

    # Verify pages are different
    if page1_pentests and page2_pentests:
        assert page1_pentests[0]['op_id'] != page2_pentests[0]['op_id']
