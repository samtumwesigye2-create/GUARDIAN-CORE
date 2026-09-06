from app.main import PROTECTED

def test_protected_categories_include_tax_and_code():
    assert 'tax_filing' in PROTECTED
    assert 'code_patch' in PROTECTED
    assert 'infrastructure_config' in PROTECTED
