"""
Initial test to confirm the circular import issue.
"""
def test_import_cli():
    """
    This test will fail if the circular import exists.
    """
    try:
        from core import cli
        assert True
    except ImportError as e:
        assert False, f"Circular import detected: {e}"
