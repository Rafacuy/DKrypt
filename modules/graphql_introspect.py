#modules/grapql_introspect.py

import json
import csv
import sys
import os
import re
import requests
import argparse
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse
from datetime import datetime
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich.text import Text
from core.utils import clear_console, header_banner

try:
    from core.randomizer import HeaderFactory, get_default_factory
except ImportError:
    # Fallback if the import fails
    print("Warning: Could not import HeaderFactory from core.randomizer. Using basic headers.")
    HeaderFactory = None
    get_default_factory = None

console = Console()
EXPORT_DIR = "report/graphql_vuln"

class GraphQLIntrospector:
    """
    Main class for GraphQL introspection and vulnerability analysis
    """
    
    def __init__(self, use_header_factory: bool = True, header_pool_size: int = None):
        """
        Initialize the GraphQL introspector
        
        Args:
            use_header_factory: Whether to use HeaderFactory for realistic headers
            header_pool_size: Size of header pool for HeaderFactory (None = use default)
        """
        self.results = {
            'endpoint': '',
            'timestamp': '',
            'introspection_enabled': False,
            'schema': {},
            'queries': [],
            'mutations': [],
            'subscriptions': [],
            'sensitive_fields': [],
            'types': [],
            'vulnerabilities': [],
            'raw_response': ''
        }
        self.session = requests.Session()
        
        # Initialize HeaderFactory if available and requested
        self.use_header_factory = use_header_factory and HeaderFactory is not None
        self.header_factory = None
        
        if self.use_header_factory:
            try:
                if header_pool_size:
                    self.header_factory = HeaderFactory(pool_size=header_pool_size)
                else:
                    self.header_factory = get_default_factory()
                console.print("[blue]Using HeaderFactory for realistic request headers[/blue]")
            except Exception as e:
                console.print(f"[yellow]Warning: Failed to initialize HeaderFactory: {e}[/yellow]")
                console.print("[yellow]Falling back to basic headers[/yellow]")
                self.use_header_factory = False
        
        # Set default headers
        self._update_session_headers()
        
        # Sensitive field patterns
        self.sensitive_patterns = [
            r'password', r'passwd', r'pwd', r'secret', r'key', r'token',
            r'auth', r'credential', r'login', r'email', r'phone', r'ssn',
            r'social.*security', r'credit.*card', r'card.*number', r'cvv',
            r'pin', r'private', r'confidential', r'sensitive', r'admin',
            r'root', r'hash', r'salt', r'signature', r'certificate'
        ]
    
    def _update_session_headers(self):
        """Update session headers using HeaderFactory or fallback headers"""
        if self.use_header_factory and self.header_factory:
            try:
                headers = self.header_factory.get_headers()
                self.session.headers.update(headers)
                # Ensure Content-Type and Accept are set for GraphQL
                self.session.headers.update({
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                })
            except Exception as e:
                console.print(f"[yellow]Warning: Failed to get headers from factory: {e}[/yellow]")
                self._set_fallback_headers()
        else:
            self._set_fallback_headers()
    
    def _set_fallback_headers(self):
        """Set basic fallback headers"""
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache'
        })
        
    def introspection_query(self) -> str:
        return """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
            directives {
              name
              description
              locations
              args {
                ...InputValue
              }
            }
          }
        }

        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              ...InputValue
            }
            type {
              ...TypeRef
            }
            isDeprecated
            deprecationReason
          }
          inputFields {
            ...InputValue
          }
          interfaces {
            ...TypeRef
          }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
          possibleTypes {
            ...TypeRef
          }
        }

        fragment InputValue on __InputValue {
          name
          description
          type { ...TypeRef }
          defaultValue
        }

        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """
    
    def send_introspection_query(self, endpoint: str, headers: Dict = None, timeout: int = 30, 
                                rotate_headers: bool = False) -> Tuple[bool, Dict]:
        """
        Send introspection query to GraphQL endpoint
        
        Args:
            endpoint: GraphQL endpoint URL
            headers: Additional headers to send
            timeout: Request timeout in seconds
            rotate_headers: Whether to rotate headers using HeaderFactory
            
        Returns:
            Tuple of (success, response_data)
        """
        query_payload = {
            "query": self.introspection_query()
        }
        
        # Rotate headers if requested and available
        if rotate_headers and self.use_header_factory and self.header_factory:
            try:
                new_headers = self.header_factory.get_headers()
                self.session.headers.update(new_headers)
                # Ensure GraphQL-specific headers are maintained
                self.session.headers.update({
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                })
                console.print("[blue]Rotated to new header set[/blue]")
            except Exception as e:
                console.print(f"[yellow]Warning: Failed to rotate headers: {e}[/yellow]")
        
        request_headers = self.session.headers.copy()
        if headers:
            request_headers.update(headers)
        
        try:
            console.print(f"[blue]Sending introspection query to: {endpoint}[/blue]")
            
            response = self.session.post(
                endpoint,
                json=query_payload,
                headers=request_headers,
                timeout=timeout,
                verify=False  # For pentesting, we might encounter self-signed certs
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and '__schema' in data['data']:
                    return True, data
                elif 'errors' in data:
                    console.print(f"[yellow]GraphQL errors in response: {data['errors']}[/yellow]")
                    return False, data
                else:
                    console.print(f"[red]Unexpected response format[/red]")
                    return False, {'raw_response': response.text}
            else:
                console.print(f"[red]HTTP {response.status_code}: {response.text}[/red]")
                return False, {'error': f'HTTP {response.status_code}', 'raw_response': response.text}
                
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Request failed: {str(e)}[/red]")
            return False, {'error': str(e)}
    
    def analyze_schema(self, schema_data: Dict) -> None:
        """
        Analyze the GraphQL schema for structure and vulnerabilities
        
        Args:
            schema_data: The schema data from introspection response
        """
        schema = schema_data['data']['__schema']
        self.results['schema'] = schema
        self.results['introspection_enabled'] = True
        
        # Extract types
        for type_info in schema.get('types', []):
            if not type_info['name'].startswith('__'):  # Skip introspection types
                self.results['types'].append({
                    'name': type_info['name'],
                    'kind': type_info['kind'],
                    'description': type_info.get('description', ''),
                    'fields': type_info.get('fields', [])
                })
        
        # Extract queries
        query_type = schema.get('queryType', {})
        if query_type:
            query_type_name = query_type['name']
            query_type_def = next((t for t in schema['types'] if t['name'] == query_type_name), None)
            if query_type_def and query_type_def.get('fields'):
                for field in query_type_def['fields']:
                    self.results['queries'].append({
                        'name': field['name'],
                        'description': field.get('description', ''),
                        'args': field.get('args', []),
                        'type': self._extract_type(field.get('type', {}))
                    })
        
        # Extract mutations
        mutation_type = schema.get('mutationType', {})
        if mutation_type:
            mutation_type_name = mutation_type['name']
            mutation_type_def = next((t for t in schema['types'] if t['name'] == mutation_type_name), None)
            if mutation_type_def and mutation_type_def.get('fields'):
                for field in mutation_type_def['fields']:
                    self.results['mutations'].append({
                        'name': field['name'],
                        'description': field.get('description', ''),
                        'args': field.get('args', []),
                        'type': self._extract_type(field.get('type', {}))
                    })
        
        # Extract subscriptions
        subscription_type = schema.get('subscriptionType', {})
        if subscription_type:
            subscription_type_name = subscription_type['name']
            subscription_type_def = next((t for t in schema['types'] if t['name'] == subscription_type_name), None)
            if subscription_type_def and subscription_type_def.get('fields'):
                for field in subscription_type_def['fields']:
                    self.results['subscriptions'].append({
                        'name': field['name'],
                        'description': field.get('description', ''),
                        'args': field.get('args', []),
                        'type': self._extract_type(field.get('type', {}))
                    })
    
    def _extract_type(self, type_info: Dict) -> str:
        """
        Extract human-readable type information from GraphQL type object
        
        Args:
            type_info: Type information dictionary
            
        Returns:
            String representation of the type
        """
        if not type_info:
            return "Unknown"
        
        if type_info.get('kind') == 'NON_NULL':
            return f"{self._extract_type(type_info.get('ofType', {}))}!"
        elif type_info.get('kind') == 'LIST':
            return f"[{self._extract_type(type_info.get('ofType', {}))}]"
        else:
            return type_info.get('name', 'Unknown')
    
    def detect_sensitive_fields(self) -> None:
        """
        Detect potentially sensitive fields in the schema
        """
        console.print("[blue]Scanning for sensitive fields...[/blue]")
        
        all_fields = []
        
        # Collect all fields from types
        for type_info in self.results['types']:
            if type_info.get('fields'):
                for field in type_info['fields']:
                    all_fields.append({
                        'type': type_info['name'],
                        'field': field['name'],
                        'description': field.get('description', ''),
                        'field_type': self._extract_type(field.get('type', {}))
                    })
        
        # Collect fields from queries, mutations, and subscriptions
        for operation_type, operations in [
            ('Query', self.results['queries']),
            ('Mutation', self.results['mutations']),
            ('Subscription', self.results['subscriptions'])
        ]:
            for operation in operations:
                all_fields.append({
                    'type': operation_type,
                    'field': operation['name'],
                    'description': operation.get('description', ''),
                    'field_type': operation.get('type', 'Unknown')
                })
                
                # Check arguments too
                for arg in operation.get('args', []):
                    all_fields.append({
                        'type': f"{operation_type}.{operation['name']}",
                        'field': arg['name'],
                        'description': arg.get('description', ''),
                        'field_type': self._extract_type(arg.get('type', {}))
                    })
        
        # Check each field against sensitive patterns
        for field_info in all_fields:
            field_name = field_info['field'].lower()
            field_desc = (field_info['description'] or '').lower()
            
            for pattern in self.sensitive_patterns:
                if re.search(pattern, field_name) or re.search(pattern, field_desc):
                    sensitivity_score = self._calculate_sensitivity_score(field_name, field_desc)
                    
                    self.results['sensitive_fields'].append({
                        'type': field_info['type'],
                        'field': field_info['field'],
                        'description': field_info['description'],
                        'field_type': field_info['field_type'],
                        'pattern_matched': pattern,
                        'sensitivity_score': sensitivity_score,
                        'reason': f"Matches pattern: {pattern}"
                    })
                    break
    
    def _calculate_sensitivity_score(self, field_name: str, description: str) -> int:
        """
        Calculate sensitivity score (1-10) based on field name and description
        
        Args:
            field_name: The field name (lowercase)
            description: The field description (lowercase)
            
        Returns:
            Sensitivity score from 1 (low) to 10 (critical)
        """
        high_risk_patterns = ['password', 'secret', 'key', 'token', 'private', 'ssn', 'credit']
        medium_risk_patterns = ['email', 'phone', 'login', 'auth', 'admin', 'hash']
        
        text_to_check = f"{field_name} {description}"
        
        for pattern in high_risk_patterns:
            if pattern in text_to_check:
                return 9  # High risk
        
        for pattern in medium_risk_patterns:
            if pattern in text_to_check:
                return 6  # Medium risk
        
        return 3  # Low risk
    
    def detect_vulnerabilities(self) -> None:
        """
        Detect potential vulnerabilities in the GraphQL schema
        """
        console.print("[blue]Analyzing for potential vulnerabilities...[/blue]")
        
        vulnerabilities = []
        
        # Check for introspection enabled (already detected)
        if self.results['introspection_enabled']:
            vulnerabilities.append({
                'type': 'Information Disclosure',
                'severity': 'Medium',
                'title': 'GraphQL Introspection Enabled',
                'description': 'The GraphQL endpoint allows introspection, which exposes the entire schema structure.',
                'recommendation': 'Disable introspection in production environments.',
                'cwe': 'CWE-200'
            })
        
        # Check for debug fields
        debug_fields = []
        for query in self.results['queries']:
            if any(debug_term in query['name'].lower() for debug_term in ['debug', 'test', 'dev', 'internal']):
                debug_fields.append(query['name'])
        
        if debug_fields:
            vulnerabilities.append({
                'type': 'Information Disclosure',
                'severity': 'Low',
                'title': 'Debug/Test Fields Exposed',
                'description': f'Potential debug/test fields found: {", ".join(debug_fields)}',
                'recommendation': 'Remove debug and test fields from production schemas.',
                'cwe': 'CWE-489'
            })
        
        # Check for admin operations
        admin_operations = []
        all_operations = self.results['queries'] + self.results['mutations']
        for operation in all_operations:
            if any(admin_term in operation['name'].lower() for admin_term in ['admin', 'root', 'super', 'delete', 'drop']):
                admin_operations.append(operation['name'])
        
        if admin_operations:
            vulnerabilities.append({
                'type': 'Privilege Escalation',
                'severity': 'High',
                'title': 'Administrative Operations Exposed',
                'description': f'Potentially dangerous administrative operations found: {", ".join(admin_operations)}',
                'recommendation': 'Ensure proper authorization checks are implemented for administrative operations.',
                'cwe': 'CWE-269'
            })
        
        # Check for file operations
        file_operations = []
        for operation in all_operations:
            if any(file_term in operation['name'].lower() for file_term in ['file', 'upload', 'download', 'read', 'write']):
                file_operations.append(operation['name'])
        
        if file_operations:
            vulnerabilities.append({
                'type': 'File Operation Risk',
                'severity': 'Medium',
                'title': 'File Operations Exposed',
                'description': f'File-related operations found: {", ".join(file_operations)}',
                'recommendation': 'Validate file operations for path traversal and unauthorized access vulnerabilities.',
                'cwe': 'CWE-22'
            })
        
        self.results['vulnerabilities'] = vulnerabilities
    
    def run_introspection(self, endpoint: str, headers: Dict = None, timeout: int = 30, 
                         rotate_headers: bool = False) -> bool:
        """
        Run complete introspection analysis
        
        Args:
            endpoint: GraphQL endpoint URL
            headers: Additional headers
            timeout: Request timeout
            rotate_headers: Whether to rotate headers using HeaderFactory
            
        Returns:
            True if successful, False otherwise
        """
        self.results['endpoint'] = endpoint
        self.results['timestamp'] = datetime.now().isoformat()
        
        # Send introspection query
        success, response_data = self.send_introspection_query(endpoint, headers, timeout, rotate_headers)
        
        if not success:
            self.results['raw_response'] = str(response_data)
            if 'errors' in response_data:
                console.print("[red]Introspection appears to be disabled or restricted[/red]")
                self.results['introspection_enabled'] = False
                
                # Check if it's truly disabled or just has errors
                errors = response_data.get('errors', [])
                for error in errors:
                    message = error.get('message', '').lower()
                    if 'introspection' in message and ('disabled' in message or 'not allowed' in message):
                        console.print(f"[yellow]Introspection explicitly disabled: {error['message']}[/yellow]")
                        break
            return False
        
        self.results['raw_response'] = json.dumps(response_data, indent=2)
        
        # Analyze the schema
        self.analyze_schema(response_data)
        
        # Detect sensitive fields
        self.detect_sensitive_fields()
        
        # Detect vulnerabilities
        self.detect_vulnerabilities()
        
        return True
    
    def export_json(self, filename: str = None) -> str:
        """
        Export results to JSON format
        
        Args:
            filename: Output filename (optional)
            
        Returns:
            Filename where data was saved
        """
        os.makedirs(EXPORT_DIR, exist_ok=True)    
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            parsed_url = urlparse(self.results['endpoint'])
            hostname = parsed_url.netloc.replace(':', '_')
            filename = f"graphql_introspection_{hostname}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        return filename
    
    def export_csv(self, filename: str = None) -> str:
        """
        Export results to CSV format
        
        Args:
            filename: Output filename (optional)
            
        Returns:
            Filename where data was saved
        """
        os.makedirs(EXPORT_DIR, exist_ok=True)
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            parsed_url = urlparse(self.results['endpoint'])
            hostname = parsed_url.netloc.replace(':', '_')
            filename = f"graphql_introspection_{hostname}_{timestamp}.csv"
        
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write summary information
            writer.writerow(['Summary Information'])
            writer.writerow(['Endpoint', self.results['endpoint']])
            writer.writerow(['Timestamp', self.results['timestamp']])
            writer.writerow(['Introspection Enabled', self.results['introspection_enabled']])
            writer.writerow(['Total Queries', len(self.results['queries'])])
            writer.writerow(['Total Mutations', len(self.results['mutations'])])
            writer.writerow(['Total Subscriptions', len(self.results['subscriptions'])])
            writer.writerow(['Total Types', len(self.results['types'])])
            writer.writerow(['Sensitive Fields Found', len(self.results['sensitive_fields'])])
            writer.writerow(['Vulnerabilities Found', len(self.results['vulnerabilities'])])
            writer.writerow([])
            
            # Write queries
            if self.results['queries']:
                writer.writerow(['Queries'])
                writer.writerow(['Name', 'Description', 'Return Type', 'Arguments'])
                for query in self.results['queries']:
                    args_str = ', '.join([f"{arg['name']}: {self._extract_type(arg.get('type', {}))}" 
                                        for arg in query.get('args', [])])
                    writer.writerow([
                        query['name'],
                        query.get('description', ''),
                        query.get('type', ''),
                        args_str
                    ])
                writer.writerow([])
            
            # Write mutations
            if self.results['mutations']:
                writer.writerow(['Mutations'])
                writer.writerow(['Name', 'Description', 'Return Type', 'Arguments'])
                for mutation in self.results['mutations']:
                    args_str = ', '.join([f"{arg['name']}: {self._extract_type(arg.get('type', {}))}" 
                                        for arg in mutation.get('args', [])])
                    writer.writerow([
                        mutation['name'],
                        mutation.get('description', ''),
                        mutation.get('type', ''),
                        args_str
                    ])
                writer.writerow([])
            
            # Write sensitive fields
            if self.results['sensitive_fields']:
                writer.writerow(['Sensitive Fields'])
                writer.writerow(['Type', 'Field Name', 'Field Type', 'Description', 'Pattern Matched', 'Sensitivity Score', 'Reason'])
                for field in self.results['sensitive_fields']:
                    writer.writerow([
                        field['type'],
                        field['field'],
                        field['field_type'],
                        field['description'],
                        field['pattern_matched'],
                        field['sensitivity_score'],
                        field['reason']
                    ])
                writer.writerow([])
            
            # Write vulnerabilities
            if self.results['vulnerabilities']:
                writer.writerow(['Vulnerabilities'])
                writer.writerow(['Type', 'Severity', 'Title', 'Description', 'Recommendation', 'CWE'])
                for vuln in self.results['vulnerabilities']:
                    writer.writerow([
                        vuln['type'],
                        vuln['severity'],
                        vuln['title'],
                        vuln['description'],
                        vuln['recommendation'],
                        vuln.get('cwe', '')
                    ])
        
        return filename
    
    def export_txt(self, filename: str = None) -> str:
        """
        Export results to TXT format
        
        Args:
            filename: Output filename (optional)
            
        Returns:
            Filename where data was saved
        """
        os.makedirs(EXPORT_DIR, exist_ok=True)
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            parsed_url = urlparse(self.results['endpoint'])
            hostname = parsed_url.netloc.replace(':', '_')
            filename = f"graphql_introspection_{hostname}_{timestamp}.txt"
        
        with open(filename, 'w') as f:
            f.write("=== Scanned by DKrypt ===")
            f.write("GraphQL Introspection Report\n")
            f.write("=" * 50 + "\n\n")
            
            f.write(f"Endpoint: {self.results['endpoint']}\n")
            f.write(f"Timestamp: {self.results['timestamp']}\n")
            f.write(f"Introspection Enabled: {self.results['introspection_enabled']}\n\n")
            
            # Summary
            f.write("SUMMARY\n")
            f.write("-" * 20 + "\n")
            f.write(f"Total Queries: {len(self.results['queries'])}\n")
            f.write(f"Total Mutations: {len(self.results['mutations'])}\n")
            f.write(f"Total Subscriptions: {len(self.results['subscriptions'])}\n")
            f.write(f"Total Types: {len(self.results['types'])}\n")
            f.write(f"Sensitive Fields Found: {len(self.results['sensitive_fields'])}\n")
            f.write(f"Vulnerabilities Found: {len(self.results['vulnerabilities'])}\n\n")
            
            # Queries
            if self.results['queries']:
                f.write("QUERIES\n")
                f.write("-" * 20 + "\n")
                for i, query in enumerate(self.results['queries'], 1):
                    f.write(f"{i}. {query['name']}\n")
                    if query.get('description'):
                        f.write(f"   Description: {query['description']}\n")
                    f.write(f"   Return Type: {query.get('type', 'Unknown')}\n")
                    if query.get('args'):
                        f.write("   Arguments:\n")
                        for arg in query['args']:
                            arg_type = self._extract_type(arg.get('type', {}))
                            f.write(f"     - {arg['name']}: {arg_type}\n")
                            if arg.get('description'):
                                f.write(f"       Description: {arg['description']}\n")
                    f.write("\n")
                f.write("\n")
            
            # Mutations
            if self.results['mutations']:
                f.write("MUTATIONS\n")
                f.write("-" * 20 + "\n")
                for i, mutation in enumerate(self.results['mutations'], 1):
                    f.write(f"{i}. {mutation['name']}\n")
                    if mutation.get('description'):
                        f.write(f"   Description: {mutation['description']}\n")
                    f.write(f"   Return Type: {mutation.get('type', 'Unknown')}\n")
                    if mutation.get('args'):
                        f.write("   Arguments:\n")
                        for arg in mutation['args']:
                            arg_type = self._extract_type(arg.get('type', {}))
                            f.write(f"     - {arg['name']}: {arg_type}\n")
                            if arg.get('description'):
                                f.write(f"       Description: {arg['description']}\n")
                    f.write("\n")
                f.write("\n")
            
            # Sensitive Fields
            if self.results['sensitive_fields']:
                f.write("SENSITIVE FIELDS\n")
                f.write("-" * 20 + "\n")
                for i, field in enumerate(self.results['sensitive_fields'], 1):
                    f.write(f"{i}. {field['type']}.{field['field']}\n")
                    f.write(f"   Field Type: {field['field_type']}\n")
                    f.write(f"   Sensitivity Score: {field['sensitivity_score']}/10\n")
                    f.write(f"   Pattern Matched: {field['pattern_matched']}\n")
                    if field.get('description'):
                        f.write(f"   Description: {field['description']}\n")
                    f.write(f"   Reason: {field['reason']}\n\n")
                f.write("\n")
            
            # Vulnerabilities
            if self.results['vulnerabilities']:
                f.write("VULNERABILITIES\n")
                f.write("-" * 20 + "\n")
                for i, vuln in enumerate(self.results['vulnerabilities'], 1):
                    f.write(f"{i}. {vuln['title']} ({vuln['severity']})\n")
                    f.write(f"   Type: {vuln['type']}\n")
                    f.write(f"   Description: {vuln['description']}\n")
                    f.write(f"   Recommendation: {vuln['recommendation']}\n")
                    if vuln.get('cwe'):
                        f.write(f"   CWE: {vuln['cwe']}\n")
                    f.write("\n")
        
        return filename
    
    def display_results(self) -> None:
        """
        Display results in the console using Rich formatting
        """
        console.print("\n[bold green]GraphQL Introspection Results[/bold green]")
        console.print("=" * 50)
        
        # Basic info
        info_table = Table(show_header=False)
        info_table.add_column("Property", style="cyan")
        info_table.add_column("Value", style="white")
        
        info_table.add_row("Endpoint", self.results['endpoint'])
        info_table.add_row("Timestamp", self.results['timestamp'])
        info_table.add_row("Introspection Enabled", 
                          "[green]Yes[/green]" if self.results['introspection_enabled'] else "[red]No[/red]")
        info_table.add_row("Total Queries", str(len(self.results['queries'])))
        info_table.add_row("Total Mutations", str(len(self.results['mutations'])))
        info_table.add_row("Total Subscriptions", str(len(self.results['subscriptions'])))
        info_table.add_row("Sensitive Fields", str(len(self.results['sensitive_fields'])))
        info_table.add_row("Vulnerabilities", str(len(self.results['vulnerabilities'])))
        
        console.print(info_table)
        console.print()
        
        # Queries
        if self.results['queries']:
            console.print("[bold blue]Queries:[/bold blue]")
            query_table = Table()
            query_table.add_column("Name", style="cyan")
            query_table.add_column("Return Type", style="yellow")
            query_table.add_column("Arguments", style="white")
            query_table.add_column("Description", style="dim")
            
            for query in self.results['queries'][:10]:  # Limit display for readability
                args_str = ', '.join([f"{arg['name']}" for arg in query.get('args', [])])
                query_table.add_row(
                    query['name'],
                    query.get('type', 'Unknown'),
                    args_str[:50] + "..." if len(args_str) > 50 else args_str,
                    (query.get('description', '') or '')[:50] + "..." if len(query.get('description', '') or '') > 50 else query.get('description', '')
                )
            
            console.print(query_table)
            if len(self.results['queries']) > 10:
                console.print(f"[dim]... and {len(self.results['queries']) - 10} more queries[/dim]")
            console.print()
        
        # Mutations
        if self.results['mutations']:
            console.print("[bold blue]Mutations:[/bold blue]")
            mutation_table = Table()
            mutation_table.add_column("Name", style="cyan")
            mutation_table.add_column("Return Type", style="yellow")
            mutation_table.add_column("Arguments", style="white")
            mutation_table.add_column("Description", style="dim")
            
            for mutation in self.results['mutations'][:10]:
                args_str = ', '.join([f"{arg['name']}" for arg in mutation.get('args', [])])
                mutation_table.add_row(
                    mutation['name'],
                    mutation.get('type', 'Unknown'),
                    args_str[:50] + "..." if len(args_str) > 50 else args_str,
                    (mutation.get('description', '') or '')[:50] + "..." if len(mutation.get('description', '') or '') > 50 else mutation.get('description', '')
                )
            
            console.print(mutation_table)
            if len(self.results['mutations']) > 10:
                console.print(f"[dim]... and {len(self.results['mutations']) - 10} more mutations[/dim]")
            console.print()
        
        # Sensitive fields
        if self.results['sensitive_fields']:
            console.print("[bold red]Sensitive Fields:[/bold red]")
            sensitive_table = Table()
            sensitive_table.add_column("Type", style="cyan")
            sensitive_table.add_column("Field", style="red")
            sensitive_table.add_column("Score", style="yellow")
            sensitive_table.add_column("Pattern", style="white")
            sensitive_table.add_column("Description", style="dim")
            
            # Sort by sensitivity score (highest first)
            sorted_fields = sorted(self.results['sensitive_fields'], 
                                 key=lambda x: x['sensitivity_score'], reverse=True)
            
            for field in sorted_fields:
                score_color = "red" if field['sensitivity_score'] >= 8 else "yellow" if field['sensitivity_score'] >= 5 else "green"
                sensitive_table.add_row(
                    field['type'],
                    field['field'],
                    f"[{score_color}]{field['sensitivity_score']}/10[/{score_color}]",
                    field['pattern_matched'],
                    (field.get('description', '') or '')[:40] + "..." if len(field.get('description', '') or '') > 40 else field.get('description', '')
                )
            
            console.print(sensitive_table)
            console.print()
        
        # Vulnerabilities
        if self.results['vulnerabilities']:
            console.print("[bold red]Vulnerabilities:[/bold red]")
            for vuln in self.results['vulnerabilities']:
                severity_color = "red" if vuln['severity'] == 'High' else "yellow" if vuln['severity'] == 'Medium' else "green"
                
                panel_content = f"[bold]Type:[/bold] {vuln['type']}\n"
                panel_content += f"[bold]Description:[/bold] {vuln['description']}\n"
                panel_content += f"[bold]Recommendation:[/bold] {vuln['recommendation']}\n"
                if vuln.get('cwe'):
                    panel_content += f"[bold]CWE:[/bold] {vuln['cwe']}"
                
                console.print(Panel(
                    panel_content,
                    title=f"[{severity_color}]{vuln['severity']}[/{severity_color}] - {vuln['title']}",
                    border_style=severity_color
                ))
            console.print()
    
    def get_factory_statistics(self) -> Dict:
        """Get HeaderFactory statistics if available"""
        if self.use_header_factory and self.header_factory:
            try:
                return self.header_factory.get_statistics()
            except Exception as e:
                console.print(f"[yellow]Warning: Failed to get factory statistics: {e}[/yellow]")
                return {}
        return {}

def run_tui():
    """
    Run the Text User Interface mode
    """
    clear_console()
    header_banner(tool_name="GraphQL Introspector")
    
    # HeaderFactory configuration
    use_header_factory = True
    header_pool_size = None
    
    if HeaderFactory is not None:
        if Confirm.ask("[cyan]Use HeaderFactory for realistic headers?[/cyan]", default=True):
            pool_size_str = Prompt.ask(
                "[cyan]Header pool size (or press Enter for default)[/cyan]",
                default=""
            )
            if pool_size_str.strip():
                try:
                    header_pool_size = int(pool_size_str)
                except ValueError:
                    console.print("[yellow]Invalid pool size, using default[/yellow]")
        else:
            use_header_factory = False
    else:
        console.print("[yellow]HeaderFactory not available, using basic headers[/yellow]")
        use_header_factory = False
    
    introspector = GraphQLIntrospector(
        use_header_factory=use_header_factory,
        header_pool_size=header_pool_size
    )
    
    # Get endpoint URL
    endpoint = Prompt.ask(
        "[cyan]Enter GraphQL endpoint URL[/cyan]",
        default="https://example.com/graphql"
    )
    
    # Get custom headers
    custom_headers = {}
    if Confirm.ask("[cyan]Add custom headers?[/cyan]", default=False):
        while True:
            header_name = Prompt.ask(
                "[cyan]Header name (or press Enter to finish)[/cyan]",
                default=""
            )
            if not header_name:
                break
            header_value = Prompt.ask(f"[cyan]Value for {header_name}[/cyan]")
            custom_headers[header_name] = header_value
    
    # Get timeout
    timeout = int(Prompt.ask("[cyan]Request timeout (seconds)[/cyan]", default="30"))
    
    # Header rotation option
    rotate_headers = False
    if use_header_factory and HeaderFactory is not None:
        rotate_headers = Confirm.ask("[cyan]Enable header rotation during request?[/cyan]", default=False)
    
    # Run introspection
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Running GraphQL introspection...", total=None)
        
        success = introspector.run_introspection(endpoint, custom_headers, timeout, rotate_headers)
        
        progress.remove_task(task)
    
    if success:
        # Display results
        introspector.display_results()
        
        # Show HeaderFactory statistics if available
        if use_header_factory:
            stats = introspector.get_factory_statistics()
            if stats:
                console.print("\n[bold cyan]HeaderFactory Statistics:[/bold cyan]")
                console.print(f"Pool size: {stats.get('pool_size', 'N/A')}/{stats.get('configured_size', 'N/A')}")
                console.print(f"Lazy mode: {stats.get('lazy_mode', 'N/A')}")
        
        # Export options
        if Confirm.ask("[cyan]Export results?[/cyan]", default=True):
            export_formats = []
            
            if Confirm.ask("[cyan]Export as JSON?[/cyan]", default=True):
                export_formats.append('json')
            if Confirm.ask("[cyan]Export as CSV?[/cyan]", default=True):
                export_formats.append('csv')
            if Confirm.ask("[cyan]Export as TXT?[/cyan]", default=True):
                export_formats.append('txt')
            
            for fmt in export_formats:
                if fmt == 'json':
                    filename = introspector.export_json()
                    console.print(f"[green]Results exported to: {filename}[/green]")
                elif fmt == 'csv':
                    filename = introspector.export_csv()
                    console.print(f"[green]Results exported to: {filename}[/green]")
                elif fmt == 'txt':
                    filename = introspector.export_txt()
                    console.print(f"[green]Results exported to: {filename}[/green]")
    else:
        console.print("[red]Introspection failed. Check the endpoint URL and try again.[/red]")
        
        # Still offer to export raw response if available
        if introspector.results.get('raw_response'):
            if Confirm.ask("[cyan]Export raw response for analysis?[/cyan]", default=False):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"graphql_failed_response_{timestamp}.txt"
                with open(filename, 'w') as f:
                    f.write(f"GraphQL Introspection Failed Response\n")
                    f.write(f"Endpoint: {endpoint}\n")
                    f.write(f"Timestamp: {datetime.now().isoformat()}\n")
                    f.write(f"Custom Headers: {custom_headers}\n\n")
                    f.write("Raw Response:\n")
                    f.write(introspector.results['raw_response'])
                console.print(f"[green]Raw response saved to: {filename}[/green]")

def run_cli(args):
    """
    Run the Command Line Interface mode
    
    Args:
        args: Parsed command line arguments
    """
    # Initialize introspector with HeaderFactory settings
    use_header_factory = getattr(args, 'use_header_factory', True)
    header_pool_size = getattr(args, 'header_pool_size', None)
    
    introspector = GraphQLIntrospector(
        use_header_factory=use_header_factory,
        header_pool_size=header_pool_size
    )
    
    # Parse custom headers if provided
    custom_headers = {}
    if hasattr(args, 'headers') and args.headers:
        try:
            custom_headers = json.loads(args.headers)
        except json.JSONDecodeError:
            console.print("[red]Invalid JSON format for headers[/red]")
            return False
    
    # Run introspection
    console.print(f"[blue]Starting GraphQL introspection on: {args.url}[/blue]")
    
    rotate_headers = getattr(args, 'rotate_headers', False)
    
    success = introspector.run_introspection(
        args.url, 
        custom_headers, 
        getattr(args, 'timeout', 30),
        rotate_headers
    )
    
    if success:
        # Display results if verbose
        if getattr(args, 'verbose', False):
            introspector.display_results()
        else:
            # Display summary
            console.print(f"[green]Introspection successful![/green]")
            console.print(f"Queries found: {len(introspector.results['queries'])}")
            console.print(f"Mutations found: {len(introspector.results['mutations'])}")
            console.print(f"Sensitive fields: {len(introspector.results['sensitive_fields'])}")
            console.print(f"Vulnerabilities: {len(introspector.results['vulnerabilities'])}")
        
        # Show HeaderFactory statistics if available and verbose
        if getattr(args, 'verbose', False) and use_header_factory:
            stats = introspector.get_factory_statistics()
            if stats:
                console.print(f"\nHeaderFactory Statistics:")
                console.print(f"  Pool size: {stats.get('pool_size', 'N/A')}/{stats.get('configured_size', 'N/A')}")
                console.print(f"  Success rate: {stats.get('generation_stats', {}).get('success', 0)} successful")
                console.print(f"  Lazy mode: {stats.get('lazy_mode', 'N/A')}")
        
        # Export results
        export_formats = getattr(args, 'export', 'json,csv,txt').lower().split(',')
        
        for fmt in export_formats:
            fmt = fmt.strip()
            if fmt == 'json':
                filename = introspector.export_json(getattr(args, 'output', None))
                console.print(f"[green]JSON results exported to: {filename}[/green]")
            elif fmt == 'csv':
                filename = introspector.export_csv(getattr(args, 'output', None))
                console.print(f"[green]CSV results exported to: {filename}[/green]")
            elif fmt == 'txt':
                filename = introspector.export_txt(getattr(args, 'output', None))
                console.print(f"[green]TXT results exported to: {filename}[/green]")
        
        return True
    else:
        console.print("[red]Introspection failed.[/red]")
        
        # Export raw response if requested
        if getattr(args, 'export_raw', False) and introspector.results.get('raw_response'):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"graphql_failed_response_{timestamp}.txt"
            with open(filename, 'w') as f:
                f.write(f"GraphQL Introspection Failed Response\n")
                f.write(f"Endpoint: {args.url}\n")
                f.write(f"Timestamp: {datetime.now().isoformat()}\n\n")
                f.write("Raw Response:\n")
                f.write(introspector.results['raw_response'])
            console.print(f"[green]Raw response saved to: {filename}[/green]")
        
        return False

def main():
    if len(sys.argv) == 1:
        run_tui()
    else:
        # Arguments provided, run CLI
        parser = argparse.ArgumentParser(
            description="GraphQL Introspection Tool for Penetration Testing",
            formatter_class=argparse.RawTextHelpFormatter
        )
        
        parser.add_argument(
            "--url",
            help="GraphQL endpoint URL to introspect",
            required=True
        )
        parser.add_argument(
            "--headers",
            help="Custom headers as JSON string (e.g., '{\"Authorization\": \"Bearer token\"}')",
            default="{}"
        )
        parser.add_argument(
            "--timeout",
            help="Request timeout in seconds (default: 30)",
            type=int,
            default=30
        )
        parser.add_argument(
            "--export",
            help="Export formats (comma-separated): json,csv,txt (default: json,csv,txt)",
            default="json,csv,txt"
        )
        parser.add_argument(
            "--output",
            help="Output filename prefix (optional)"
        )
        parser.add_argument(
            "--verbose",
            help="Display detailed results in console",
            action="store_true"
        )
        parser.add_argument(
            "--export-raw",
            help="Export raw response even on failure",
            action="store_true"
        )
        
        # HeaderFactory specific arguments
        parser.add_argument(
            "--no-header-factory",
            help="Disable HeaderFactory and use basic headers instead",
            action="store_true"
        )
        parser.add_argument(
            "--header-pool-size",
            help="Size of HeaderFactory pool for generating realistic headers (default: use config)",
            type=int
        )
        parser.add_argument(
            "--rotate-headers",
            help="Rotate headers during the request using HeaderFactory",
            action="store_true"
        )
        
        args = parser.parse_args()
        
        args.use_header_factory = not args.no_header_factory
        
        success = run_cli(args)
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()