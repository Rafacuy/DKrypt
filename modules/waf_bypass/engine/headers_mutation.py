import re
import time
import itertools
import urllib.parse
import sys
import random
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict

sys.path.append("..")
from waf_utils import MutationPriority, HeaderMutation, HEADER_PACKS

class MutationEngine:
    """Stage 2: Generate headers combination and variations"""
    
    def __init__(self, max_mutations: int = 200, max_combinations_per_pack: int = 5):
        self.max_mutations = max_mutations
        self.max_combinations_per_pack = max_combinations_per_pack
        self.seen_hashes: Set[str] = set()
        self.mutation_counter = 1
        
        # Define technique priorities based on common WAF behaviors
        self.technique_priorities = {
            'ip_spoofing': MutationPriority(
                'ip_spoofing', 8.0,
                {'cloudflare': 2.0, 'incapsula': 1.5, 'akamai': 1.0},
                {'blocking': 2.0, 'rate-limit': 1.5, 'challenge': 1.0}
            ),
            'host_manipulation': MutationPriority(
                'host_manipulation', 7.5,
                {'cloudflare': 2.5, 'aws-waf': 2.0, 'f5-bigip': 1.5},
                {'redirect': 2.0, 'blocking': 1.5}
            ),
            'method_override': MutationPriority(
                'method_override', 6.0,
                {'mod_security': 2.0, 'imperva': 1.5},
                {'blocking': 2.0, 'challenge': 1.0}
            ),
            'encoding_tricks': MutationPriority(
                'encoding_tricks', 7.0,
                {'mod_security': 2.5, 'barracuda': 2.0, 'sucuri': 1.5},
                {'blocking': 2.0, 'challenge': 1.5}
            ),
            'content_type_confusion': MutationPriority(
                'content_type_confusion', 6.5,
                {'imperva': 2.0, 'fortinet': 1.5, 'radware': 1.0},
                {'blocking': 2.0, 'pass-through': -0.5}
            ),
            'case_manipulation': MutationPriority(
                'case_manipulation', 5.0,
                {'mod_security': 1.5, 'barracuda': 1.0},
                {'blocking': 1.5, 'challenge': 1.0}
            )
        }
    
    def generate_mutations(self, 
                          selected_packs: List[str] = None,
                          custom_headers: List[Dict[str, str]] = None,
                          waf_fingerprint = None,
                          factory = None,
                          method: str = "GET") -> List[Dict[str, Any]]:
        """Generate intelligent mutations based on WAF fingerprinting"""
        
        mutations = []
        base_headers = factory.get_headers() if factory else {}
        
        # Extract WAF context for prioritization
        vendor = waf_fingerprint.vendor if waf_fingerprint else None
        behavior = waf_fingerprint.blocking_behavior if waf_fingerprint else None
        
        # Generate base mutations from packs
        if selected_packs:
            mutations.extend(self._generate_pack_mutations(
                selected_packs, base_headers, vendor, behavior
            ))
        
        # Add custom headers
        if custom_headers:
            mutations.extend(self._generate_custom_mutations(
                custom_headers, base_headers, vendor, behavior
            ))
        
        # Generate encoding variations
        mutations.extend(self._generate_encoding_mutations(
            mutations[:20], vendor, behavior  # Apply to top mutations only
        ))
        
        # POST-specific mutations
        if method.upper() == "POST":
            mutations.extend(self._generate_post_mutations(
                base_headers, vendor, behavior
            ))
        
        # Smart combinations (strategic, not explosive)
        mutations.extend(self._generate_smart_combinations(
            mutations, vendor, behavior
        ))
        
        # Advanced case variations
        mutations.extend(self._generate_case_mutations(
            mutations[:30], vendor, behavior
        ))
        
        # Deduplicate and prioritize
        unique_mutations = self._deduplicate_mutations(mutations)
        prioritized = sorted(unique_mutations, key=lambda m: m.priority_score, reverse=True)
        
        # Apply rotation strategy for stealth
        final_mutations = self._apply_rotation_strategy(prioritized[:self.max_mutations])
        
        return [self._mutation_to_dict(m) for m in final_mutations]
    
    def _generate_pack_mutations(self, packs: List[str], base_headers: Dict[str, str],
                                vendor: Optional[str], behavior: Optional[str]) -> List[HeaderMutation]:
        """Generate mutations from header packs with WAF awareness"""
        mutations = []
        
        for pack_name in packs:
            if pack_name not in HEADER_PACKS:
                continue
            
            technique = self._map_pack_to_technique(pack_name)
            priority_score = self.technique_priorities.get(technique, 
                MutationPriority(technique, 5.0, {}, {})).calculate_score(vendor, behavior)
            
            for headers in HEADER_PACKS[pack_name]:
                merged_headers = self._merge_headers_safely(base_headers, headers)
                
                mutation = HeaderMutation.create(
                    self.mutation_counter,
                    f"{pack_name} - {list(headers.keys())[0]}",
                    merged_headers,
                    pack_name,
                    priority_score,
                    [technique]
                )
                
                if mutation.hash_key not in self.seen_hashes:
                    mutations.append(mutation)
                    self.seen_hashes.add(mutation.hash_key)
                    self.mutation_counter += 1
        
        return mutations
    
    def _generate_custom_mutations(self, custom_headers: List[Dict[str, str]],
                                  base_headers: Dict[str, str], vendor: Optional[str], 
                                  behavior: Optional[str]) -> List[HeaderMutation]:
        """Generate mutations from custom headers"""
        mutations = []
        base_score = 6.0  # Custom headers get medium priority
        
        for custom in custom_headers:
            merged_headers = self._merge_headers_safely(base_headers, custom)
            
            mutation = HeaderMutation.create(
                self.mutation_counter,
                f"Custom - {list(custom.keys())[0]}",
                merged_headers,
                "custom",
                base_score,
                ["custom"]
            )
            
            if mutation.hash_key not in self.seen_hashes:
                mutations.append(mutation)
                self.seen_hashes.add(mutation.hash_key)
                self.mutation_counter += 1
        
        return mutations
    
    def _generate_encoding_mutations(self, base_mutations: List[HeaderMutation],
                                    vendor: Optional[str], behavior: Optional[str]) -> List[HeaderMutation]:
        """Generate encoding variations for high-value mutations"""
        mutations = []
        encoding_priority = self.technique_priorities['encoding_tricks'].calculate_score(vendor, behavior)
        
        for base_mutation in base_mutations:
            # URL encoding variations
            for header_name, value in base_mutation.headers.items():
                if header_name.startswith('X-') or header_name in ['Host', 'User-Agent']:
                    # Double URL encoding
                    double_encoded = urllib.parse.quote(urllib.parse.quote(value))
                    encoded_headers = base_mutation.headers.copy()
                    encoded_headers[header_name] = double_encoded
                    
                    mutation = HeaderMutation.create(
                        self.mutation_counter,
                        f"DoubleURL - {base_mutation.name}",
                        encoded_headers,
                        "encoding",
                        encoding_priority * 0.8,
                        base_mutation.techniques + ["double_url_encoding"]
                    )
                    
                    if mutation.hash_key not in self.seen_hashes:
                        mutations.append(mutation)
                        self.seen_hashes.add(mutation.hash_key)
                        self.mutation_counter += 1
                    
                    # Unicode normalization tricks
                    if any(char.isalpha() for char in value):
                        unicode_value = self._apply_unicode_tricks(value)
                        unicode_headers = base_mutation.headers.copy()
                        unicode_headers[header_name] = unicode_value
                        
                        mutation = HeaderMutation.create(
                            self.mutation_counter,
                            f"Unicode - {base_mutation.name}",
                            unicode_headers,
                            "encoding",
                            encoding_priority * 0.7,
                            base_mutation.techniques + ["unicode_normalization"]
                        )
                        
                        if mutation.hash_key not in self.seen_hashes:
                            mutations.append(mutation)
                            self.seen_hashes.add(mutation.hash_key)
                            self.mutation_counter += 1
        
        return mutations
    
    def _generate_post_mutations(self, base_headers: Dict[str, str],
                                vendor: Optional[str], behavior: Optional[str]) -> List[HeaderMutation]:
        """Generate POST-specific mutations with Content-Type focus"""
        mutations = []
        ct_priority = self.technique_priorities['content_type_confusion'].calculate_score(vendor, behavior)
        
        # Advanced Content-Type variations
        content_types = [
            "application/json",
            "application/json; charset=utf-8",
            "application/x-www-form-urlencoded",
            "text/plain",
            "text/xml",
            "application/xml",
            "multipart/form-data; boundary=----WebKitFormBoundary",
            "application/json; charset=utf-8; boundary=something",
            "application/x-www-form-urlencoded; charset=iso-8859-1",
            "application/json\r\nX-Injected: header",  # CRLF injection attempt
            "application/json;application/x-www-form-urlencoded",  # Multiple types
        ]
        
        for ct in content_types:
            headers = base_headers.copy()
            headers["Content-Type"] = ct
            
            # Add complementary headers based on content type
            if "json" in ct.lower():
                headers["Accept"] = "application/json, */*"
                headers["X-Requested-With"] = "XMLHttpRequest"
            elif "form" in ct.lower():
                headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            
            mutation = HeaderMutation.create(
                self.mutation_counter,
                f"POST-CT - {ct.split(';')[0]}",
                headers,
                "post_specific",
                ct_priority,
                ["content_type_confusion", "post_specific"]
            )
            
            if mutation.hash_key not in self.seen_hashes:
                mutations.append(mutation)
                self.seen_hashes.add(mutation.hash_key)
                self.mutation_counter += 1
        
        # Method override combinations for POST
        method_overrides = [
            {"X-HTTP-Method-Override": "GET"},
            {"X-Method-Override": "PUT"},
            {"X-HTTP-Method": "DELETE"},
            {"_method": "PATCH"}  # Form parameter style
        ]
        
        for override in method_overrides:
            headers = {**base_headers, **override, "Content-Type": "application/x-www-form-urlencoded"}
            
            mutation = HeaderMutation.create(
                self.mutation_counter,
                f"POST-Override - {list(override.keys())[0]}",
                headers,
                "post_specific",
                self.technique_priorities['method_override'].calculate_score(vendor, behavior),
                ["method_override", "post_specific"]
            )
            
            if mutation.hash_key not in self.seen_hashes:
                mutations.append(mutation)
                self.seen_hashes.add(mutation.hash_key)
                self.mutation_counter += 1
        
        return mutations
    
    def _generate_smart_combinations(self, mutations: List[HeaderMutation],
                                    vendor: Optional[str], behavior: Optional[str]) -> List[HeaderMutation]:
        """Generate strategic combinations, not explosive ones"""
        combinations = []
        
        # Group mutations by pack for strategic combining
        pack_groups = defaultdict(list)
        for mutation in mutations:
            pack_groups[mutation.pack].append(mutation)
        
        # Only combine complementary techniques
        complementary_pairs = [
            ('identity_spoof', 'routing_path'),
            ('parser_tricks', 'tool_evasion'),
            ('advanced_evasion', 'api_gateway'),
            ('cdn_headers', 'protocol_anomalies')
        ]
        
        for pack1, pack2 in complementary_pairs:
            if pack1 in pack_groups and pack2 in pack_groups:
                # Sample best mutations from each pack
                pack1_best = sorted(pack_groups[pack1], key=lambda x: x.priority_score, reverse=True)[:3]
                pack2_best = sorted(pack_groups[pack2], key=lambda x: x.priority_score, reverse=True)[:3]
                
                for mut1, mut2 in itertools.product(pack1_best, pack2_best):
                    if len(combinations) >= self.max_combinations_per_pack * 4:
                        break
                    
                    combined_headers = self._merge_headers_safely(mut1.headers, mut2.headers)
                    combined_score = (mut1.priority_score + mut2.priority_score) * 0.6  # Slight penalty for complexity
                    
                    mutation = HeaderMutation.create(
                        self.mutation_counter,
                        f"Combo - {mut1.pack}/{mut2.pack}",
                        combined_headers,
                        "combination",
                        combined_score,
                        mut1.techniques + mut2.techniques
                    )
                    
                    if mutation.hash_key not in self.seen_hashes:
                        combinations.append(mutation)
                        self.seen_hashes.add(mutation.hash_key)
                        self.mutation_counter += 1
        
        return combinations
    
    def _generate_case_mutations(self, mutations: List[HeaderMutation],
                                         vendor: Optional[str], behavior: Optional[str]) -> List[HeaderMutation]:
        """Generate sophisticated case variations"""
        case_mutations = []
        case_priority = self.technique_priorities['case_manipulation'].calculate_score(vendor, behavior)
        
        important_headers = {
            "X-Forwarded-For", "X-Real-IP", "Host", "User-Agent", 
            "Content-Type", "Authorization", "X-Original-URL"
        }
        
        for mutation in mutations:
            for header_name in mutation.headers:
                if header_name in important_headers:
                    case_variations = self._generate_case_variations(header_name)
                    
                    for variant in case_variations:
                        if variant != header_name:
                            new_headers = mutation.headers.copy()
                            value = new_headers.pop(header_name)
                            new_headers[variant] = value
                            
                            case_mutation = HeaderMutation.create(
                                self.mutation_counter,
                                f"Case - {variant}",
                                new_headers,
                                "case_variant",
                                case_priority * 0.8,
                                mutation.techniques + ["case_manipulation"]
                            )
                            
                            if case_mutation.hash_key not in self.seen_hashes:
                                case_mutations.append(case_mutation)
                                self.seen_hashes.add(case_mutation.hash_key)
                                self.mutation_counter += 1
        
        return case_mutations
      
    def _apply_rotation_strategy(self, mutations: List[HeaderMutation]) -> List[HeaderMutation]:
        """Apply header rotation to avoid detection patterns"""
        # Shuffle mutations while preserving top priorities
        top_tier = mutations[:20]  # Keep top 20 in order
        mid_tier = mutations[20:100]  # Shuffle middle tier
        low_tier = mutations[100:]  # Shuffle low tier
        
        random.shuffle(mid_tier)
        random.shuffle(low_tier)
        
        # Distribute high-priority mutations throughout the list
        rotated = []
        for i, mutation in enumerate(top_tier + mid_tier + low_tier):
            # Add some entropy to avoid pattern detection
            if i > 0 and i % 15 == 0:  # Every 15 requests
                # Insert a low-priority "noise" request
                if low_tier:
                    rotated.append(low_tier.pop(0))
            rotated.append(mutation)
        
        return rotated
    
    def _merge_headers_safely(self, base: Dict[str, str], new: Dict[str, str]) -> Dict[str, str]:
        """Safely merge headers with conflict detection"""
        merged = base.copy()
        for key, value in new.items():
            if key in merged and merged[key] != value:
                # Handle header conflicts intelligently
                if key.lower() in ['x-forwarded-for', 'x-real-ip']:
                    # Combine IP headers
                    merged[key] = f"{merged[key]}, {value}"
                else:
                    # Override with new value but preserve in name
                    merged[key] = value
            else:
                merged[key] = value
        return merged
    
    def _map_pack_to_technique(self, pack_name: str) -> str:
        """Map pack names to technique categories"""
        mapping = {
            'identity_spoof': 'ip_spoofing',
            'routing_path': 'host_manipulation', 
            'parser_tricks': 'content_type_confusion',
            'tool_evasion': 'case_manipulation',
            'advanced_evasion': 'encoding_tricks',
            'api_gateway': 'method_override',
            'cdn_headers': 'host_manipulation',
            'protocol_anomalies': 'encoding_tricks',
            'mobile_headers': 'case_manipulation'
        }
        return mapping.get(pack_name, 'generic')
    
    def _generate_case_variations(self, header_name: str) -> List[str]:
        """Generate sophisticated case variations"""
        variations = [
            header_name.lower(),
            header_name.upper(), 
            header_name.title(),
            header_name.replace('-', '_'),
            header_name.replace('-', ''),
            header_name.replace('-', '.'),
            ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(header_name)),
            header_name.swapcase()
        ]
        
        # Add zero-width character variations for advanced evasion
        if len(header_name) > 3:
            variations.extend([
                header_name[:2] + '\u200b' + header_name[2:],  # Zero-width space
                header_name + '\u200c',  # Zero-width non-joiner
            ])
        
        return list(set(variations))  # Remove duplicates
    
    def _apply_unicode_tricks(self, value: str) -> str:
        """Apply Unicode normalization tricks"""
        # Punycode for domain-like values
        if '.' in value and not value.startswith('http'):
            try:
                return value.encode('idna').decode('ascii')
            except:
                pass
        
        # Unicode escape sequences for IP-like values  
        if value.count('.') == 3:  # Looks like IP
            return '\\u' + '\\u'.join(f'{ord(c):04x}' for c in value[:4])
        
        # Mixed case Unicode for text values
        return ''.join(c + '\u0300' if c.isalpha() and random.random() > 0.7 else c for c in value)
    
    def _deduplicate_mutations(self, mutations: List[HeaderMutation]) -> List[HeaderMutation]:
        """Remove duplicate mutations based on hash keys"""
        seen = set()
        unique = []
        for mutation in mutations:
            if mutation.hash_key not in seen:
                seen.add(mutation.hash_key)
                unique.append(mutation)
        return unique
    
    def _mutation_to_dict(self, mutation: HeaderMutation) -> Dict[str, Any]:
        """Convert HeaderMutation back to dict format for compatibility"""
        return {
            "id": mutation.id,
            "name": mutation.name,
            "headers": mutation.headers,
            "pack": mutation.pack,
            "priority_score": mutation.priority_score,
            "techniques": mutation.techniques
        }
