#!/usr/bin/env python3
"""Tests for the enhanced suggestion engine"""

import pytest
import tempfile
import json
from pathlib import Path
from core.cli.suggestor import EnhancedSuggester, UsagePatternTracker, SuggestionResult


@pytest.fixture
def temp_db():
    """Create temporary database for testing"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    yield temp_path
    Path(temp_path).unlink(missing_ok=True)


@pytest.fixture
def sample_modules():
    """Sample module configuration"""
    return {
        'sqli': {
            'name': 'SQL Injection Scanner',
            'description': 'Scan for SQL injection vulnerabilities',
            'options': {
                'URL': {'required': True, 'description': 'Target URL'},
                'METHOD': {'required': False, 'default': 'GET', 'choices': ['GET', 'POST']}
            }
        },
        'xss': {
            'name': 'XSS Scanner',
            'description': 'Cross-site scripting vulnerability scanner',
            'options': {
                'URL': {'required': True, 'description': 'Target URL'},
                'SMART_MODE': {'required': False, 'default': False}
            }
        },
        'subdomain': {
            'name': 'Subdomain Enumerator',
            'description': 'Enumerate subdomains for a domain',
            'options': {
                'DOMAIN': {'required': True, 'description': 'Target domain'}
            }
        }
    }


@pytest.fixture
def suggester(sample_modules, temp_db):
    """Create suggester instance"""
    suggester = EnhancedSuggester(sample_modules)
    suggester.pattern_tracker.db_path = Path(temp_db)
    return suggester


class TestUsagePatternTracker:
    """Test usage pattern tracking"""
    
    def test_record_module_use(self, temp_db):
        tracker = UsagePatternTracker(temp_db)
        tracker.record_module_use('sqli')
        tracker.record_module_use('sqli')
        tracker.record_module_use('xss')
        
        frequent = tracker.get_frequent_modules(2)
        assert len(frequent) == 2
        assert frequent[0][0] == 'sqli'
        assert frequent[0][1] == 2
    
    def test_record_option_value(self, temp_db):
        tracker = UsagePatternTracker(temp_db)
        tracker.record_option_value('sqli', 'URL', 'https://example.com')
        tracker.record_option_value('sqli', 'URL', 'https://test.com')
        
        history = tracker.get_option_history('sqli', 'URL')
        assert len(history) == 2
        assert 'https://example.com' in history
    
    def test_save_and_load(self, temp_db):
        tracker = UsagePatternTracker(temp_db)
        tracker.record_module_use('sqli')
        tracker.save()
        
        tracker2 = UsagePatternTracker(temp_db)
        assert 'sqli' in tracker2.patterns['module_usage']


class TestEnhancedSuggester:
    """Test enhanced suggester functionality"""
    
    def test_suggest_module_exact_match(self, suggester):
        results = suggester.suggest_module('sqli')
        assert len(results) > 0
        assert results[0][0] == 'sqli'
        assert results[0][1] == 1.0
    
    def test_suggest_module_prefix_match(self, suggester):
        results = suggester.suggest_module('sql')
        assert len(results) > 0
        assert results[0][0] == 'sqli'
        assert results[0][1] >= 0.9
    
    def test_suggest_module_fuzzy_match(self, suggester):
        results = suggester.suggest_module('sqil')
        assert len(results) > 0
        assert 'sqli' in [r[0] for r in results]
    
    def test_suggest_module_empty_query(self, suggester):
        results = suggester.suggest_module('')
        assert len(results) > 0
    
    def test_suggest_module_threshold(self, suggester):
        results = suggester.suggest_module('xyz', threshold=0.8)
        assert all(score >= 0.8 for _, score in results)
    
    def test_suggest_command(self, suggester):
        results = suggester.suggest_command('us')
        assert len(results) > 0
        assert 'use' in [r[0] for r in results]
    
    def test_suggest_options(self, suggester):
        options = suggester.suggest_options('sqli', '')
        assert 'URL' in options
        assert 'METHOD' in options
    
    def test_suggest_options_partial(self, suggester):
        options = suggester.suggest_options('sqli', 'ur')
        assert 'URL' in options
    
    def test_suggest_option_values_with_choices(self, suggester):
        values = suggester.suggest_option_values('sqli', 'METHOD', '')
        assert 'GET' in values
        assert 'POST' in values
    
    def test_suggest_contextual_use(self, suggester):
        suggestions = suggester.suggest_contextual('use', '', 'sq')
        assert 'sqli' in suggestions
    
    def test_suggest_contextual_set(self, suggester):
        suggestions = suggester.suggest_contextual('set', 'sqli', 'ur')
        assert 'URL' in suggestions
    
    def test_suggest_contextual_show(self, suggester):
        suggestions = suggester.suggest_contextual('show', '', 'mod')
        assert 'modules' in suggestions
    
    def test_record_usage(self, suggester):
        suggester.record_usage(module='sqli', option='URL', value='https://test.com')
        history = suggester.pattern_tracker.get_option_history('sqli', 'URL')
        assert 'https://test.com' in history
    
    def test_similarity_computation(self, suggester):
        score1 = suggester._compute_similarity('sqli', 'sqli')
        assert score1 == 1.0
        
        score2 = suggester._compute_similarity('sql', 'sqli')
        assert score2 > 0.8
        
        score3 = suggester._compute_similarity('xyz', 'sqli')
        assert score3 < 0.5
    
    def test_levenshtein_distance(self, suggester):
        dist = suggester._levenshtein_distance('sqli', 'sqli')
        assert dist == 0
        
        dist = suggester._levenshtein_distance('sqli', 'sqil')
        assert dist == 2
    
    def test_jaro_winkler_similarity(self, suggester):
        sim = suggester._jaro_winkler_similarity('sqli', 'sqli')
        assert sim == 1.0
        
        sim = suggester._jaro_winkler_similarity('sqli', 'sql')
        assert sim > 0.8
    
    def test_caching(self, suggester):
        results1 = suggester.suggest_module('sqli')
        results2 = suggester.suggest_module('sqli')
        assert results1 == results2
    
    def test_get_module_description(self, suggester):
        desc = suggester.get_module_description('sqli')
        assert 'sql injection' in desc.lower()
    
    def test_get_module_option_info(self, suggester):
        info = suggester.get_module_option_info('sqli', 'URL')
        assert info['name'] == 'URL'
        assert info['required'] is True


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
