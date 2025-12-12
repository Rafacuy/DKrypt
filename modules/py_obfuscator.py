#modules/py_obfuscator

import os
import sys
import time
import marshal
import zlib
import base64
import hashlib
import random
import string
import ast
import types
import struct
import hmac
from pathlib import Path
from datetime import datetime
import importlib.util
import builtins

from core.utils import header_banner, clear_console
import sys
import os

# Check if Colorama is available
try:
    from colorama import init, Fore, Back, Style
    init()
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    class Fore:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Back:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''


class PyObfuscator:
    """Python obfuscator with multiple protection layers"""
    
    MAGIC_BYTES = b'\xDE\xAD\xBE\xEF'
    
    def __init__(self):
        self.input_file = ""
        self.output_file = ""
        self.encryption_key = None
        self.processing_time = 0
        self.checksum = ""
        self.salt = os.urandom(16)
        self.iterations = random.randint(10000, 20000)
        self.obfuscation_layers = []
        self.import_mapping = {}
        self.string_pool = []
        self.code_chunks = []
        self.protection_level = 2  # Default protection level
    
    def get_user_input(self):
        """user input with validation"""
        print(f"\n{Fore.GREEN}[?]{Style.RESET_ALL} Enter Python file to obfuscate: ", end="")
        self.input_file = input().strip().strip('"\'')
        
        if not self.input_file:
            print(f"{Fore.RED}Error: No input file specified.{Style.RESET_ALL}")
            return False
        
        if not os.path.isfile(self.input_file):
            print(f"{Fore.RED}Error: File '{self.input_file}' does not exist.{Style.RESET_ALL}")
            return False
        
        # Validate Python syntax
        try:
            with open(self.input_file, 'r', encoding='utf-8') as f:
                source = f.read()
                compile(source, self.input_file, 'exec')
        except SyntaxError as e:
            print(f"{Fore.RED}Error: Invalid Python syntax in input file: {e}{Style.RESET_ALL}")
            return False
        
        # Output file setup
        input_path = Path(self.input_file)
        default_output = f"obfuscated_{input_path.stem}_{int(time.time())}.py"
        print(f"{Fore.GREEN}[?]{Style.RESET_ALL} Output file [{default_output}]: ", end="")
        user_output = input().strip()
        
        self.output_file = user_output if user_output else default_output
        
        # Create output directory
        output_dir = os.path.dirname(self.output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        
        # Advanced encryption key setup
        print(f"{Fore.GREEN}[?]{Style.RESET_ALL} Custom encryption passphrase (press Enter for auto-generated): ", end="")
        key_input = input().strip()
        
        if key_input:
            self.encryption_key = self.derive_key(key_input.encode(), self.salt, self.iterations)
        else:
            # Generate strong random key
            self.encryption_key = os.urandom(32)
            print(f"{Fore.YELLOW}[!] Using auto-generated secure key{Style.RESET_ALL}")
        
        # Ask for protection level
        print(f"\n{Fore.CYAN}Protection Levels:{Style.RESET_ALL}")
        print("  1. Basic (Fast, moderate protection)")
        print("  2. Standard (Balanced speed and protection)")
        print("  3. Maximum (Slow, highest protection)")
        print(f"{Fore.GREEN}[?]{Style.RESET_ALL} Select protection level [2]: ", end="")

        level_input = input().strip()
        try:
            level_num = int(level_input) if level_input.strip() else 2
            self.protection_level = level_num if 1 <= level_num <= 3 else 2
        except (ValueError, TypeError):
            self.protection_level = 2  # Default to standard if invalid input
        
        return True
    
    def derive_key(self, password, salt, iterations):
        """Derive encryption key using PBKDF2"""
        return hashlib.pbkdf2_hmac('sha256', password, salt, iterations, 32)
    
    def advanced_xor_encrypt(self, data, key):
        """Multi-round XOR encryption with key scheduling"""
        encrypted = bytearray(data)
        key_length = len(key)
        
        # Multiple rounds based on protection level
        rounds = self.protection_level * 2
        
        for round_num in range(rounds):
            # Key scheduling - rotate key each round
            round_key = key[round_num % key_length:] + key[:round_num % key_length]
            
            for i in range(len(encrypted)):
                # Complex XOR pattern
                encrypted[i] ^= round_key[i % len(round_key)]
                encrypted[i] = (encrypted[i] + round_num) % 256
                
        return bytes(encrypted)
    
    def obfuscate_strings(self, code):
        """Extract and obfuscate string literals"""
        tree = ast.parse(code)
        string_map = {}
        
        class StringObfuscator(ast.NodeTransformer):
            def visit_Str(self, node):  # Python < 3.8
                if isinstance(node.s, str) and len(node.s) > 0:
                    obf_name = f'_s{len(string_map)}'
                    string_map[obf_name] = base64.b64encode(node.s.encode()).decode()
                    return ast.Name(id=obf_name, ctx=ast.Load())
                return node
            
            def visit_Constant(self, node):  # Python >= 3.8
                if isinstance(node.value, str) and len(node.value) > 0:
                    obf_name = f'_s{len(string_map)}'
                    string_map[obf_name] = base64.b64encode(node.value.encode()).decode()
                    return ast.Name(id=obf_name, ctx=ast.Load())
                return node
            
            def visit_JoinedStr(self, node):
                return node
        
        if self.protection_level >= 2:
            transformer = StringObfuscator()
            tree = transformer.visit(tree)
            
            # Generate string decoding header
            string_header = "import base64\n"
            for name, encoded in string_map.items():
                string_header += f"{name} = base64.b64decode('{encoded}').decode()\n"
            
            return string_header + ast.unparse(tree) if hasattr(ast, 'unparse') else string_header + compile(tree, '<string>', 'exec')
        
        return code
    
    def add_control_flow_obfuscation(self, code):
        """Add control flow obfuscation"""
        if self.protection_level < 3:
            return code
        
        # Add dummy conditional branches
        flow_obf = """
_x = lambda: __import__('random').randint(1, 100)
_y = lambda a, b: a if _x() > 50 else b
"""
        return flow_obf + code
    
    def chunk_code(self, code):
        """Split code into encrypted chunks"""
        if self.protection_level < 2:
            return [code]
        
        # Split code into random chunks
        chunk_size = random.randint(500, 1500)
        chunks = []
        
        for i in range(0, len(code), chunk_size):
            chunk = code[i:i + chunk_size]
            # Encrypt each chunk separately
            encrypted_chunk = self.advanced_xor_encrypt(chunk.encode(), self.encryption_key)
            chunks.append(base64.b64encode(encrypted_chunk).decode())
        
        return chunks
    
    def generate_anti_debug_code(self):
        """Generate comprehensive anti-debugging code"""
        return '''
def _anti_debug():
    import sys, os, ctypes, platform
    if hasattr(sys, 'gettrace') and sys.gettrace():
        os._exit(1)
    
    debug_vars = ['PYTHONDEBUG', 'PYTHONINSPECT', 'PYTHONBREAKPOINT']
    if any(os.environ.get(var) for var in debug_vars):
        os._exit(1)
    
    if platform.system() == 'Windows':
        try:
            kernel32 = ctypes.windll.kernel32
            if kernel32.IsDebuggerPresent():
                os._exit(1)
        except:
            pass
    elif platform.system() in ['Linux', 'Darwin']:
        try:
            # Check for ptrace
            import signal
            signal.signal(signal.SIGTRAP, lambda *args: os._exit(1))
        except:
            pass
    
    import time
    _t = time.time()
    sum([i**2 for i in range(1000)])
    if time.time() - _t > 0.5:  # Suspicious delay
        os._exit(1)

_anti_debug()
'''
    
    def generate_integrity_check(self, code_hash):
        """Generate code integrity verification"""
        return f'''
def _verify_integrity():
    import hashlib, sys
    expected = "{code_hash}"
    # Self-verification would go here in production
    # This is a simplified version for demonstration
    return True

if not _verify_integrity():
    print("Code integrity check failed!")
    sys.exit(1)
'''
    
    def obfuscate_code(self, code):
        """Apply multi-layer obfuscation"""
        try:
            print(f"{Fore.YELLOW}[+] Applying protection layers...{Style.RESET_ALL}")
            
            # Layer 1: String obfuscation
            if self.protection_level >= 2:
                print(f"  {Fore.CYAN}→ String obfuscation{Style.RESET_ALL}")
                code = self.obfuscate_strings(code)
            
            # Layer 2: Control flow obfuscation
            if self.protection_level >= 3:
                print(f"  {Fore.CYAN}→ Control flow obfuscation{Style.RESET_ALL}")
                code = self.add_control_flow_obfuscation(code)
            
            # Layer 3: Compile to bytecode
            print(f"  {Fore.CYAN}→ Bytecode compilation{Style.RESET_ALL}")
            bytecode = compile(code, '<obfuscated>', 'exec')
            
            # Layer 4: Marshal
            print(f"  {Fore.CYAN}→ Marshal serialization{Style.RESET_ALL}")
            marshaled = marshal.dumps(bytecode)
            
            # Layer 5: Compression
            print(f"  {Fore.CYAN}→ Compression{Style.RESET_ALL}")
            compressed = zlib.compress(marshaled, 9)
            
            # Layer 6: Add magic bytes and metadata
            metadata = struct.pack('!I', self.protection_level)
            payload = self.MAGIC_BYTES + metadata + self.salt + compressed
            
            # Layer 7: Encryption
            print(f"  {Fore.CYAN}→ Multi-round encryption{Style.RESET_ALL}")
            encrypted = self.advanced_xor_encrypt(payload, self.encryption_key)
            
            # Layer 8: Final encoding
            print(f"  {Fore.CYAN}→ Final encoding{Style.RESET_ALL}")
            encoded = base64.b85encode(encrypted)
            
            # Calculate checksum
            self.checksum = hmac.new(self.encryption_key, compressed, hashlib.sha256).hexdigest()
            
            return encoded.decode('ascii')
            
        except Exception as e:
            print(f"{Fore.RED}Error during obfuscation: {str(e)}{Style.RESET_ALL}")
            return None
    
    def generate_loader_code(self, obfuscated_code):
        """Generate sophisticated loader with multiple protection layers"""
        
        # Randomize function and variable names
        func_names = {
            'loader': ''.join(random.choices(string.ascii_letters, k=8)),
            'decrypt': ''.join(random.choices(string.ascii_letters, k=8)),
            'verify': ''.join(random.choices(string.ascii_letters, k=8)),
            'execute': ''.join(random.choices(string.ascii_letters, k=8)),
        }
        
        loader = f'''#!/usr/bin/env python3
# -*- Protected by DKrypt | Obfuscated by DKrypt -+- 
# Check it out: https://github.com/Rafacuy/DKrypt
# Checksum: {self.checksum[:16]}...
# Timestamp: {datetime.now().isoformat()}
# Protection Level: {self.protection_level}

import marshal, zlib, base64, struct, hmac, hashlib, sys, os

{self.generate_anti_debug_code() if self.protection_level >= 2 else ""}

class _{func_names['loader']}:
    def __init__(self):
        self._d = "{obfuscated_code}"
        self._k = {repr(self.encryption_key)}
        self._s = {repr(self.salt)}
        self._i = {self.iterations}
        self._m = b'\\xDE\\xAD\\xBE\\xEF'
        
    def _{func_names['decrypt']}(self, data, key):
        decrypted = bytearray(data)
        rounds = {self.protection_level * 2}
        
        for round_num in range(rounds - 1, -1, -1):
            round_key = key[round_num % len(key):] + key[:round_num % len(key)]
            for i in range(len(decrypted)):
                decrypted[i] = (decrypted[i] - round_num) % 256
                decrypted[i] ^= round_key[i % len(round_key)]
        
        return bytes(decrypted)
    
    def _{func_names['verify']}(self, data):
        expected = "{self.checksum}"
        actual = hmac.new(self._k, data, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, actual)
    
    def _{func_names['execute']}(self):
        try:
            decoded = base64.b85decode(self._d)      
            decrypted = self._{func_names['decrypt']}(decoded, self._k)
            if decrypted[:4] != self._m:
                raise ValueError("Invalid file format")
        
            protection_level = struct.unpack('!I', decrypted[4:8])[0]
            salt = decrypted[8:24]
            compressed = decrypted[24:]
            if not self._{func_names['verify']}(compressed):
                raise ValueError("Integrity check failed")
            
            decompressed = zlib.decompress(compressed)
            
            code = marshal.loads(decompressed)
            
            namespace = {{
                '__name__': '__main__',
                '__file__': __file__,
                '__builtins__': __builtins__,
            }}
            
            exec(code, namespace)
            
        except Exception as e:
            print(f"Error: Protected code execution failed")
            sys.exit(1)

if __name__ == '__main__':
    try:
        _l = _{func_names['loader']}()
        _l._{func_names['execute']}()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception:
        sys.exit(1)
'''
        return loader
    
    def process_file(self):
        """Process input file withobfuscation"""
        start_time = time.time()
        
        print(f"\n{Fore.YELLOW}[+] Processing file: {self.input_file}{Style.RESET_ALL}")
        
        try:
            with open(self.input_file, 'r', encoding='utf-8') as f:
                source_code = f.read()
            
            self.analyze_dependencies(source_code)
            
            # Apply obfuscation
            obfuscated_code = self.obfuscate_code(source_code)
            
            if obfuscated_code is None:
                return False
            
            # generate loader
            output_script = self.generate_loader_code(obfuscated_code)
            
            #write output
            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write(output_script)
            
            # maje executable on Unix-like systems
            if os.name != 'nt':
                os.chmod(self.output_file, 0o755)
            
            self.processing_time = time.time() - start_time
            return True
            
        except Exception as e:
            print(f"{Fore.RED}Error processing file: {str(e)}{Style.RESET_ALL}")
            return False
    
    def analyze_dependencies(self, code):
        """Analyze and warn about external dependencies"""
        tree = ast.parse(code)
        imports = set()
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split('.')[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split('.')[0])
        
        # Standard library modules that are safe
        stdlib_modules = {
            'os', 'sys', 'time', 'datetime', 'random', 'math', 'json', 
            're', 'urllib', 'http', 'socket', 'threading', 'subprocess',
            'pathlib', 'collections', 'itertools', 'functools', 'hashlib'
        }
        
        external_imports = imports - stdlib_modules
        
        if external_imports:
            print(f"\n{Fore.YELLOW}[!] Warning: External dependencies detected:{Style.RESET_ALL}")
            for imp in external_imports:
                print(f"    • {imp}")
            print(f"{Fore.YELLOW}    These must be available in the target environment{Style.RESET_ALL}")
    
    def display_results(self):
        """Display obfuscation results"""
        print(f"\n{Fore.GREEN}{'═' * 60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[✓] Obfuscation completed successfully!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[i] Output file: {Style.BRIGHT}{self.output_file}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[i] File size: {Style.BRIGHT}{os.path.getsize(self.output_file)} bytes{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[i] Processing time: {Style.BRIGHT}{self.processing_time:.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[i] Protection level: {Style.BRIGHT}{self.protection_level}/3{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[i] Checksum: {Style.BRIGHT}{self.checksum[:32]}...{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'═' * 60}{Style.RESET_ALL}")
        
    def run(self):
        """Main execution method"""
        clear_console()
        header_banner(tool_name="Py Obfuscator")
        
        if not self.get_user_input():
            return
        
        if self.process_file():
            self.display_results()
        else:
            print(f"\n{Fore.RED}[-] Obfuscation failed!{Style.RESET_ALL}")


def main(*args, **kwargs):
    """Entry point - supports both new args-object style and legacy positional args style"""
    if not COLORAMA_AVAILABLE:
        print("Notice: Install 'colorama' for enhanced display (pip install colorama)")
        print("Continuing without colors...\n")

    # Define helper functions first
    def run_with_args(args):
        try:
            obfuscator = PyObfuscator()
            obfuscator.input_file = args.input
            obfuscator.output_file = args.output
            if args.key:
                obfuscator.encryption_key = obfuscator.derive_key(args.key.encode(), obfuscator.salt, obfuscator.iterations)
            else:
                obfuscator.encryption_key = os.urandom(32)
            # Ensure protection_level is an integer to prevent type errors
            try:
                obfuscator.protection_level = int(args.level) if args.level is not None else 2
            except (ValueError, TypeError):
                print(f"{Fore.RED}Error: Protection level must be a number between 1 and 3{Style.RESET_ALL}")
                return
            if obfuscator.process_file():
                obfuscator.display_results()
            else:
                print(f"\n{Fore.RED}[-] Obfuscation failed!{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Operation cancelled by user{Style.RESET_ALL}")
            time.sleep(2)
        except Exception as e:
            print(f"\n{Fore.RED}[!] Unexpected error: {e}{Style.RESET_ALL}")
            time.sleep(5)

    def run_with_legacy_args(input_file=None, output_file=None, level=None, rename_vars=None, rename_funcs=None, flow_obfuscation=None):
        try:
            obfuscator = PyObfuscator()
            obfuscator.input_file = input_file
            obfuscator.output_file = output_file
            obfuscator.encryption_key = os.urandom(32)  # Default for legacy
            # Ensure protection_level is an integer to prevent type errors
            try:
                obfuscator.protection_level = int(level) if level is not None else 2
            except (ValueError, TypeError):
                print(f"{Fore.RED}Error: Protection level must be a number between 1 and 3{Style.RESET_ALL}")
                return
            if obfuscator.process_file():
                obfuscator.display_results()
            else:
                print(f"\n{Fore.RED}[-] Obfuscation failed!{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Operation cancelled by user{Style.RESET_ALL}")
            time.sleep(2)
        except Exception as e:
            print(f"\n{Fore.RED}[!] Unexpected error: {e}{Style.RESET_ALL}")
            time.sleep(5)

    def run_interactive():
        try:
            obfuscator = PyObfuscator()
            obfuscator.run()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Operation cancelled by user{Style.RESET_ALL}")
            time.sleep(2)
        except Exception as e:
            print(f"\n{Fore.RED}[!] Unexpected error: {e}{Style.RESET_ALL}")
            time.sleep(5)

    # Handle both the new args-object style and legacy style
    if args and (hasattr(args[0], 'input') or len(args) > 1):
        # New style: args object passed as first argument or multiple args suggest legacy style
        if hasattr(args[0], 'input'):  # New args object style
            arg_obj = args[0]
            run_with_args(arg_obj)
        else:  # Legacy style with positional arguments: input, output, level, ...
            run_with_legacy_args(*args)
    else:  # Interactive mode when no args
        run_interactive()