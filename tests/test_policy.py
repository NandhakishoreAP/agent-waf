import os
import tempfile
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import load_policy_yaml, settings
from app.schemas import WAFPolicy

@pytest.fixture
def create_temp_policy():
    temp_files = []
    
    def _create(content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".yaml")
        with os.fdopen(fd, "w") as f:
            f.write(content)
        temp_files.append(path)
        return path

    yield _create

    for p in temp_files:
        try:
            os.remove(p)
        except OSError:
            pass

def test_valid_policy_loads():
    # 1. Valid policy loads successfully.
    # 2. policy_version is v1.
    # 3. mode=enforce is accepted.
    policy = load_policy_yaml("app/policies/waf_policy.yaml")
    assert isinstance(policy, WAFPolicy)
    assert policy.policy_version == "v1"
    assert policy.mode == "enforce"
    assert len(policy.rate_limits) == 2

def test_mode_shadow_accepted(create_temp_policy):
    # 4. mode=shadow is accepted.
    path = create_temp_policy("""
policy_version: "v1"
mode: shadow
rate_limits: []
parameter_validation: []
data_scope: []
sequence_rules: []
""")
    policy = load_policy_yaml(path)
    assert policy.mode == "shadow"

def test_invalid_mode_rejected(create_temp_policy):
    # 5. Invalid mode is rejected.
    path = create_temp_policy("""
policy_version: "v1"
mode: enforce_shadow
""")
    with pytest.raises(ValueError):
        load_policy_yaml(path)

def test_invalid_max_calls_rejected(create_temp_policy):
    # 6. Invalid max_calls is rejected.
    path = create_temp_policy("""
policy_version: "v1"
mode: enforce
rate_limits:
  - tool: "crm.read"
    max_calls: 0
    window_seconds: 60
""")
    with pytest.raises(ValueError):
        load_policy_yaml(path)

def test_invalid_window_seconds_rejected(create_temp_policy):
    # 7. Invalid window_seconds is rejected.
    path = create_temp_policy("""
policy_version: "v1"
mode: enforce
rate_limits:
  - tool: "crm.read"
    max_calls: 5
    window_seconds: -10
""")
    with pytest.raises(ValueError):
        load_policy_yaml(path)

def test_invalid_max_param_length_rejected(create_temp_policy):
    # 8. Invalid max_param_length is rejected.
    path = create_temp_policy("""
policy_version: "v1"
mode: enforce
parameter_validation:
  - tool: "*"
    blocklist_patterns: ["DROP TABLE"]
    max_param_length: 0
""")
    with pytest.raises(ValueError):
        load_policy_yaml(path)

def test_empty_sequence_requires_prior_rejected(create_temp_policy):
    # 9. Empty sequence requires_prior is rejected.
    path = create_temp_policy("""
policy_version: "v1"
mode: enforce
sequence_rules:
  - tool: "email.send"
    requires_prior: []
""")
    with pytest.raises(ValueError):
        load_policy_yaml(path)

def test_missing_policy_file_handled():
    # 10. Missing policy file is handled.
    with pytest.raises(FileNotFoundError):
        load_policy_yaml("app/policies/non_existent_policy.yaml")

def test_invalid_yaml_handled(create_temp_policy):
    # 11. Invalid YAML is handled.
    path = create_temp_policy("invalid: : : yaml")
    with pytest.raises(ValueError):
        load_policy_yaml(path)

def test_get_policy_endpoint():
    # 13. GET /api/policy returns the active policy.
    with TestClient(app) as client:
        response = client.get("/api/policy")
        assert response.status_code == 200
        data = response.json()
        assert data["policy_version"] == "v1"
        assert data["mode"] == "enforce"

def test_get_health_endpoint():
    # 14. GET /health reports policy=ok when valid.
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["checks"]["policy"] == "ok"
        assert data["checks"]["database"] == "ok"

def test_atomic_reload(create_temp_policy):
    # 12. Invalid reload does not replace the previous valid policy.
    orig_policy_file = settings.POLICY_FILE
    
    # Write a valid first-version policy
    valid_path = create_temp_policy("""
policy_version: "v_temp_1"
mode: enforce
rate_limits: []
parameter_validation: []
data_scope: []
sequence_rules: []
""")
    settings.POLICY_FILE = valid_path
    
    with TestClient(app) as client:
        # Load the valid temp YAML policy
        reload_resp = client.post("/api/policy/reload")
        assert reload_resp.status_code == 200
        assert reload_resp.json()["policy_version"] == "v_temp_1"
        
        # Verify it has been activated
        get_resp = client.get("/api/policy")
        assert get_resp.json()["policy_version"] == "v_temp_1"
        
        # Write an invalid policy back to the file (invalid key or values)
        with open(valid_path, "w") as f:
            f.write("""
policy_version: "v_temp_invalid"
mode: invalid_mode
""")
        
        # Attempt reloading: it must fail with 400
        reload_fail_resp = client.post("/api/policy/reload")
        assert reload_fail_resp.status_code == 400
        assert reload_fail_resp.json()["detail"] == "Policy validation failed"
        
        # Verify that the active policy was NOT replaced and still holds v_temp_1
        get_check_resp = client.get("/api/policy")
        assert get_check_resp.json()["policy_version"] == "v_temp_1"
        
    # Restore original setting
    settings.POLICY_FILE = orig_policy_file
