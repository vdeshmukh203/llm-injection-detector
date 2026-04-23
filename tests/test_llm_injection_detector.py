import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

def test_import():
    import llm_injection_detector as lid
    assert hasattr(lid, 'InjectionDetector')

def test_rule():
    import llm_injection_detector as lid
    assert hasattr(lid, 'Rule')

def test_detection_result():
    import llm_injection_detector as lid
    assert hasattr(lid, 'DetectionResult')

def test_detector_init():
    import llm_injection_detector as lid
    det = lid.InjectionDetector()
    assert det is not None

def test_clean_text():
    import llm_injection_detector as lid
    det = lid.InjectionDetector()
    r = det.detect('This is a normal sentence.')
    assert r is not None
