# core/randomizer.py
"""
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import asyncio
import json
import logging
import os
import random
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional, Union
from urllib.parse import urlparse
import yaml

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# ==============================================================================
# CONFIGURATION MANAGEMENT
# ==============================================================================

class ConfigManager:
    """Manages configuration loading from JSON/YAML files with fallback to defaults."""

    def __init__(self, config_path: Optional[Union[str, Path]] = None):
        """
        Initialize configuration manager.

        Args:
            config_path: Path to configuration file (JSON or YAML)
        """
        # If no config path is provided, try to get the default from the configuration
        if config_path is None:
            # Load using the default path temporarily to get the config path from settings
            default_path = Path("config/headers_schema.json")
            if default_path.exists():
                self.config_path = default_path
            else:
                self.config_path = None
        else:
            self.config_path = Path(config_path) if config_path else None

        self._config = self._load_config()
        logger.info(f"Configuration loaded from {'file' if self.config_path else 'defaults'}")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or return defaults."""
        if self.config_path and self.config_path.exists():
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    if self.config_path.suffix.lower() in ['.yaml', '.yml']:
                        return yaml.safe_load(f)
                    else:
                        return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load config from {self.config_path}: {e}")
                
        return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Return comprehensive default configuration."""
        return {
            "referer_categories": {
                "search_engine": {
                    "urls": [
                        "https://www.google.com/", "https://www.bing.com/", 
                        "https://search.yahoo.com/", "https://duckduckgo.com/",
                        "https://www.ecosia.org/", "https://yandex.com/",
                        "https://www.baidu.com/", "https://www.ask.com/"
                    ],
                    "weight": 0.35
                },
                "social_media": {
                    "urls": [
                        "https://www.facebook.com/", "https://www.twitter.com/",
                        "https://t.co/", "https://www.reddit.com/",
                        "https://www.instagram.com/", "https://www.linkedin.com/",
                        "https://www.tiktok.com/", "https://www.pinterest.com/"
                    ],
                    "weight": 0.25
                },
                "tech_edu": {
                    "urls": [
                        "https://stackoverflow.com/", "https://github.com/",
                        "https://news.ycombinator.com/", "https://medium.com/",
                        "https://www.quora.com/", "https://dev.to/",
                        "https://www.coursera.org/", "https://www.udemy.com/"
                    ],
                    "weight": 0.15
                },
                "news": {
                    "urls": [
                        "https://www.bbc.com/", "https://www.nytimes.com/",
                        "https://www.cnn.com/", "https://www.theguardian.com/",
                        "https://www.reuters.com/", "https://www.npr.org/",
                        "https://www.aljazeera.com/"
                    ],
                    "weight": 0.15
                },
                "ecommerce": {
                    "urls": [
                        "https://www.amazon.com/", "https://www.ebay.com/",
                        "https://www.alibaba.com/", "https://www.shopify.com/",
                        "https://www.etsy.com/", "https://www.walmart.com/"
                    ],
                    "weight": 0.10
                }
            },
            "geo_ip_ranges": {
                "north_america": [["63.0.0.0", "76.255.255.255"], ["184.0.0.0", "191.255.255.255"]],
                "europe": [["77.0.0.0", "95.255.255.255"], ["176.0.0.0", "188.255.255.255"]],
                "asia_pacific": [["101.0.0.0", "126.255.255.255"], ["202.0.0.0", "223.255.255.255"]],
                "africa": [["41.0.0.0", "41.255.255.255"], ["196.0.0.0", "197.255.255.255"]],
                "south_america": [["189.0.0.0", "191.255.255.255"], ["200.0.0.0", "201.255.255.255"]],
                "middle_east": [["37.0.0.0", "37.255.255.255"], ["185.0.0.0", "185.255.255.255"]]
            },
            "ipv6_prefixes": [
                "2001", "2002", "2003", "2400", "2600", "2800", "2a00", "2c00"
            ],
            "browser_profiles": [
                {
                    "name": "Chrome_Windows",
                    "headers": {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Sec-CH-UA": '"Not_A Brand";v="8", "Chromium";v="{version}", "Google Chrome";v="{version}"',
                        "Sec-CH-UA-Mobile": "?0",
                        "Sec-CH-UA-Platform": '"Windows"'
                    },
                    "versions": ["120", "121", "122", "123", "124"],
                    "weight": 0.35
                },
                {
                    "name": "Firefox_Windows",
                    "headers": {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/{version}.0",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.5"
                    },
                    "versions": ["119", "120", "121", "122", "123"],
                    "weight": 0.20
                },
                {
                    "name": "Edge_Windows",
                    "headers": {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36 Edg/{version}.0.0.0",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Sec-CH-UA": '"Not_A Brand";v="8", "Chromium";v="{version}", "Microsoft Edge";v="{version}"',
                        "Sec-CH-UA-Mobile": "?0",
                        "Sec-CH-UA-Platform": '"Windows"'
                    },
                    "versions": ["120", "121", "122", "123"],
                    "weight": 0.15
                },
                {
                    "name": "Safari_macOS",
                    "headers": {
                        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version}.1 Safari/605.1.15",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.9"
                    },
                    "versions": ["16", "17", "18"],
                    "weight": 0.10
                },
                {
                    "name": "Chrome_Android",
                    "headers": {
                        "User-Agent": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Mobile Safari/537.36",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Sec-CH-UA": '"Not_A Brand";v="8", "Chromium";v="{version}", "Google Chrome";v="{version}"',
                        "Sec-CH-UA-Mobile": "?1",
                        "Sec-CH-UA-Platform": '"Android"'
                    },
                    "versions": ["120", "121", "122", "123"],
                    "weight": 0.08
                },
                {
                    "name": "Safari_iOS",
                    "headers": {
                        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version}.0 Mobile/15E148 Safari/604.1",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.9"
                    },
                    "versions": ["16", "17"],
                    "weight": 0.07
                },
                {
                    "name": "Opera_Windows",
                    "headers": {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_ver}.0.0.0 Safari/537.36 OPR/{version}.0.0.0",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.9"
                    },
                    "versions": ["105", "106", "107"],
                    "chrome_versions": ["119", "120", "121"],
                    "weight": 0.05
                }
            ],
            "pool_settings": {
                "default_size": 2000,
                "lazy_generation": True,
                "parallel_workers": 4,
                "generation_timeout": 30
            }
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key."""
        return self._config.get(key, default)

    def get_path(self, path_key: str, default: str = "") -> str:
        """Get a path from the paths configuration section."""
        paths = self._config.get("paths", {})
        path_value = paths.get(path_key, default)

        # If the path starts with './', make it relative to the current working directory
        if path_value.startswith('./'):
            return os.path.abspath(path_value)
        return path_value

    def reload(self):
        """Reload configuration from file."""
        self._config = self._load_config()
        logger.info("Configuration reloaded")

# Global configuration instance - loads config from the path specified in the configuration
config_manager = ConfigManager()

# ==============================================================================
# IP GENERATION
# ==============================================================================

def _ip_to_int(ip: str) -> int:
    """Converts a string IPv4 address to its integer representation."""
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def _int_to_ip(ip_int: int) -> str:
    """Converts an integer to its string IPv4 address representation."""
    return socket.inet_ntoa(struct.pack("!I", ip_int))

def generate_random_ipv4() -> str:
    try:
        geo_ranges = config_manager.get("geo_ip_ranges", {})
        if not geo_ranges:
            logger.warning("No geo IP ranges configured, using fallback")
            return "203.0.113.1"  
        
        # Select random region and range
        region = random.choice(list(geo_ranges.keys()))
        start_ip_str, end_ip_str = random.choice(geo_ranges[region])
        
        # Generate random IP in range
        start_ip_int = _ip_to_int(start_ip_str)
        end_ip_int = _ip_to_int(end_ip_str)
        random_ip_int = random.randint(start_ip_int, end_ip_int)
        
        generated_ip = _int_to_ip(random_ip_int)
        logger.debug(f"Generated IPv4: {generated_ip} from region: {region}")
        return generated_ip
        
    except Exception as e:
        logger.error(f"Failed to generate random IPv4: {e}")
        return "203.0.113.1"  # RFC5737 fallback

def generate_random_ipv6() -> str:
    try:
        prefixes = config_manager.get("ipv6_prefixes", ["2001"])
        prefix = random.choice(prefixes)
        
        # Generate remaining 7 hextets with proper zero-padding
        hextets = [prefix] + [f"{random.randint(0, 0xFFFF):04x}" for _ in range(7)]
        generated_ipv6 = ":".join(hextets)
        
        logger.debug(f"Generated IPv6: {generated_ipv6}")
        return generated_ipv6
        
    except Exception as e:
        logger.error(f"Failed to generate random IPv6: {e}")
        return "2001:0db8:85a3:0000:0000:8a2e:0370:7334"  # RFC3849 fallback

def generate_random_ip() -> str:
    """
    Generates either a random IPv4 or IPv6 address.
    IPv4 has 80% probability to match real-world distribution.
    """
    try:
        return generate_random_ipv4() if random.random() < 0.8 else generate_random_ipv6()
    except Exception as e:
        logger.error(f"Failed to generate random IP: {e}")
        return "203.0.113.1"

# ==============================================================================
# REFERER GENERATION
# ==============================================================================

def get_random_referer() -> str:
    """
    Selects a random referer URL using weighted categories.
    Now supports configurable categories and weights.
    """
    try:
        referer_categories = config_manager.get("referer_categories", {})
        if not referer_categories:
            logger.warning("No referer categories configured")
            return "https://www.google.com/"
        
        # Extract categories and weights
        categories = list(referer_categories.keys())
        weights = [referer_categories[cat].get("weight", 0.1) for cat in categories]
        
        # Choose category and URL
        chosen_category = random.choices(categories, weights, k=1)[0]
        urls = referer_categories[chosen_category].get("urls", [])
        
        if not urls:
            logger.warning(f"No URLs in category {chosen_category}")
            return "https://www.google.com/"
        
        selected_referer = random.choice(urls)
        logger.debug(f"Selected referer: {selected_referer} from category: {chosen_category}")
        return selected_referer
        
    except Exception as e:
        logger.error(f"Failed to generate random referer: {e}")
        return "https://www.google.com/"

# ==============================================================================
#  BROWSER PROFILE GENERATION
# ==============================================================================

def _add_modern_headers(headers: Dict[str, str], is_mobile: bool = False) -> Dict[str, str]:
    """
    Add modern HTTP headers including Sec-Fetch-* and other contemporary fields.
    
    Args:
        headers: Base headers dictionary
        is_mobile: Whether this is a mobile browser
        
    Returns:
        headers dictionary
    """
    modern_headers = {
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": random.choice(["document", "empty"]),
        "Sec-Fetch-Mode": random.choice(["navigate", "cors"]),
        "Sec-Fetch-Site": random.choice(["none", "same-origin", "cross-site"]),
        "DNT": random.choice(["1", ""]),  # Sometimes empty for realism
        "Accept-Encoding": random.choice([
            "gzip, deflate, br",
            "gzip, deflate",
            "gzip, deflate, br, zstd"
        ]),
        "Connection": "keep-alive",
        "Cache-Control": random.choice(["no-cache", "max-age=0"]),
        "Pragma": "no-cache" if random.random() < 0.5 else "",
    }
    
    # Add mobile-specific headers
    if is_mobile:
        modern_headers["Sec-Fetch-User"] = "?1" if random.random() < 0.3 else ""
    
    # Merge with existing headers (don't override)
    for key, value in modern_headers.items():
        if key not in headers and value:  # Only add non-empty values
            headers[key] = value
    
    return headers

def get_random_browser_profile() -> Dict[str, str]:
    """
    Selects a random browser profile with weighted selection and modern headers.
    Now supports more browsers and proper version handling.
    """
    try:
        browser_profiles = config_manager.get("browser_profiles", [])
        if not browser_profiles:
            logger.warning("No browser profiles configured, using fallback")
            return _create_fallback_headers()
        
        # Select profile using weights
        profiles = []
        weights = []
        for profile in browser_profiles:
            profiles.append(profile)
            weights.append(profile.get("weight", 0.1))
        
        selected_profile = random.choices(profiles, weights, k=1)[0]
        
        # Get random version
        versions = selected_profile.get("versions", ["1.0"])
        version = random.choice(versions)
        
        # Handle special cases (like Opera with Chrome version)
        chrome_version = version
        if "chrome_versions" in selected_profile:
            chrome_version = random.choice(selected_profile["chrome_versions"])
        
        # Format headers
        formatted_headers = {}
        for key, value in selected_profile["headers"].items():
            formatted_value = value.format(
                version=version,
                chrome_ver=chrome_version
            )
            formatted_headers[key] = formatted_value
        
        # Detect mobile and add modern headers
        is_mobile = "Mobile" in formatted_headers.get("User-Agent", "")
        formatted_headers = _add_modern_headers(formatted_headers, is_mobile)
        
        # Add additional standard headers
        formatted_headers.update({
            "Referer": get_random_referer(),
            "X-Client-IP": generate_random_ip(),
        })
        
        logger.debug(f"Generated profile: {selected_profile['name']} v{version}")
        return formatted_headers
        
    except Exception as e:
        logger.error(f"Failed to generate browser profile: {e}")
        return _create_fallback_headers()

def _create_fallback_headers() -> Dict[str, Any]:
    """
    Creates a comprehensive fallback header set with modern fields.
    Enhanced with contemporary headers and proper error recovery.
    """
    return {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'Upgrade-Insecure-Requests': '1',
        'Sec-CH-UA': '"Not_A Brand";v="8", "Chromium";v="121", "Google Chrome";v="121"',
        'Sec-CH-UA-Mobile': '?0',
        'Sec-CH-UA-Platform': '"Windows"',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'DNT': '1',
        'Referer': 'https://www.google.com/',
        'X-Client-IP': generate_random_ip(),
    }

# ==============================================================================
# OPTIMIZED HEADER FACTORY CLASS
# ==============================================================================

class HeaderFactory:
    """
    An optimized factory for generating realistic header sets with lazy evaluation,
    parallel generation, and comprehensive error handling.
    """
    
    def __init__(self, pool_size: Optional[int] = None, lazy: Optional[bool] = None):
        """
        Initialize the factory with configurable settings.
        
        Args:
            pool_size: Number of headers to pre-generate (None = use config)
            lazy: Whether to use lazy generation (None = use config)
        """
        pool_settings = config_manager.get("pool_settings", {})
        
        self.pool_size = pool_size or pool_settings.get("default_size", 2000)
        self.lazy = lazy if lazy is not None else pool_settings.get("lazy_generation", True)
        self.parallel_workers = pool_settings.get("parallel_workers", 4)
        self.generation_timeout = pool_settings.get("generation_timeout", 30)
        
        self.pool: List[Dict[str, Any]] = []
        self._pool_lock = threading.RLock()
        self._generation_stats = {"success": 0, "failure": 0, "total_time": 0}
        
        if not self.lazy:
            self._generate_pool_sync()
    
    def _generate_single_header(self, index: int) -> Optional[Dict[str, Any]]:
        """Generate a single header set with error handling."""
        try:
            return get_random_browser_profile()
        except Exception as e:
            logger.debug(f"Failed to generate header set {index}: {e}")
            return None
    
    def _generate_pool_parallel(self) -> List[Dict[str, Any]]:
        """Generate header pool using parallel workers."""
        start_time = time.time()
        headers = []
        
        with ThreadPoolExecutor(max_workers=self.parallel_workers) as executor:
            # Submit all tasks
            future_to_index = {
                executor.submit(self._generate_single_header, i): i 
                for i in range(self.pool_size)
            }
            
            # Collect results with timeout
            try:
                for future in as_completed(future_to_index, timeout=self.generation_timeout):
                    result = future.result()
                    if result:
                        headers.append(result)
                        self._generation_stats["success"] += 1
                    else:
                        self._generation_stats["failure"] += 1
                        
            except TimeoutError:
                logger.warning(f"Header generation timed out after {self.generation_timeout}s")
        
        self._generation_stats["total_time"] = time.time() - start_time
        return headers
    
    def _generate_pool_sync(self):
        """Synchronously generate the header pool."""
        logger.info(f"Generating header pool of size {self.pool_size} (parallel={self.parallel_workers} workers)")
        
        try:
            self.pool = self._generate_pool_parallel()
            
            success_rate = (self._generation_stats["success"] / self.pool_size) * 100
            logger.info(
                f"Header pool generated: {len(self.pool)} headers in "
                f"{self._generation_stats['total_time']:.2f}s "
                f"(success rate: {success_rate:.1f}%)"
            )
            
            if success_rate < 90:
                logger.warning(f"Low success rate in header generation: {success_rate:.1f}%")
                
        except Exception as e:
            logger.error(f"Critical failure in header pool generation: {e}")
            self.pool = []
    
    async def _generate_pool_async(self):
        """Asynchronously generate the header pool."""
        loop = asyncio.get_event_loop()
        
        with ThreadPoolExecutor(max_workers=self.parallel_workers) as executor:
            tasks = [
                loop.run_in_executor(executor, self._generate_single_header, i)
                for i in range(self.pool_size)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            headers = []
            for result in results:
                if isinstance(result, dict):
                    headers.append(result)
                    self._generation_stats["success"] += 1
                else:
                    self._generation_stats["failure"] += 1
            
            return headers
    
    def get_headers(self) -> Dict[str, Any]:
        """
        Get a random header set from the pool or generate on-demand.
        Thread-safe with lazy loading support.
        """
        with self._pool_lock:
            # Lazy generation if pool is empty
            if not self.pool and self.lazy:
                logger.info("Lazy-loading header pool")
                self._generate_pool_sync()
            
            # Return from pool if available
            if self.pool:
                return random.choice(self.pool)
            
            # Fallback to on-demand generation
            logger.warning("Pool empty, generating headers on-demand")
            try:
                return get_random_browser_profile()
            except Exception as e:
                logger.error(f"On-demand header generation failed: {e}")
                return _create_fallback_headers()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get generation statistics for monitoring."""
        with self._pool_lock:
            return {
                "pool_size": len(self.pool),
                "configured_size": self.pool_size,
                "generation_stats": self._generation_stats.copy(),
                "lazy_mode": self.lazy
            }
    
    def refresh_pool(self):
        """Refresh the entire header pool."""
        logger.info("Refreshing header pool")
        with self._pool_lock:
            self._generation_stats = {"success": 0, "failure": 0, "total_time": 0}
            self._generate_pool_sync()

# ==============================================================================
# BACKWARDS COMPATIBILITY WRAPPERS
# ==============================================================================

def get_random_user_agent() -> str:
    """
    Selects and returns a random User-Agent string.
    Maintained for backward compatibility.
    """
    try:
        profile_headers = get_random_browser_profile()
        user_agent = profile_headers.get("User-Agent", "")
        if user_agent:
            logger.debug(f"Generated User-Agent: {user_agent[:50]}...")
            return user_agent
        else:
            fallback_ua = _create_fallback_headers()["User-Agent"]
            logger.warning("Using fallback User-Agent")
            return fallback_ua
    except Exception as e:
        logger.error(f"Failed to generate User-Agent: {e}")
        return _create_fallback_headers()["User-Agent"]

def get_random_origin() -> str:
    """
    Selects and returns a random Origin URL.
    Enhanced with better URL parsing and error handling.
    """
    try:
        referer_url = get_random_referer()
        parsed = urlparse(referer_url)
        
        if parsed.scheme and parsed.netloc:
            origin = f"{parsed.scheme}://{parsed.netloc}"
            logger.debug(f"Generated origin: {origin}")
            return origin
        else:
            logger.warning(f"Invalid referer URL format: {referer_url}")
            return referer_url.rstrip('/')
            
    except Exception as e:
        logger.error(f"Failed to parse referer URL: {e}")
        return "https://www.google.com"

# ==============================================================================
# MODULE INITIALIZATION AND TESTING
# ==============================================================================

# Initialize default factory instance
default_factory = None

def get_default_factory() -> HeaderFactory:
    """Get or create the default HeaderFactory instance."""
    global default_factory
    if default_factory is None:
        default_factory = HeaderFactory()
    return default_factory

def configure_from_file(config_path: Union[str, Path]):
    """
    Configure the module from an external configuration file.

    Args:
        config_path: Path to JSON or YAML configuration file
    """
    global config_manager, default_factory
    config_manager = ConfigManager(config_path)
    default_factory = None  # Reset factory to use new config
    logger.info(f"Module reconfigured from {config_path}")

def configure_from_config_path():
    """
    Configure the module from the config path specified in the configuration.
    """
    global config_manager, default_factory
    config_path = config_manager.get_path("config_path", "config/headers_schema.json")
    config_manager = ConfigManager(config_path)
    default_factory = None  # Reset factory to use new config
    logger.info(f"Module reconfigured from config path: {config_path}")

# ==============================================================================
# MAIN EXECUTION AND TESTING
# ==============================================================================

if __name__ == '__main__':
    # Demo and testing
    print("=== Enhanced Randomizer Module Demo ===\n")
    
    # Test IP generation
    print("IP Generation:")
    for _ in range(3):
        ipv4 = generate_random_ipv4()
        ipv6 = generate_random_ipv6()
        print(f"  IPv4: {ipv4}")
        print(f"  IPv6: {ipv6}")
    
    print(f"\nRandom IP: {generate_random_ip()}")
    
    # Test referer generation
    print(f"\nReferer Generation:")
    for _ in range(3):
        referer = get_random_referer()
        origin = get_random_origin()
        print(f"  Referer: {referer}")
        print(f"  Origin: {origin}")
    
    # Test browser profiles
    print(f"\nBrowser Profile Generation:")
    for _ in range(2):
        headers = get_random_browser_profile()
        print(f"  User-Agent: {headers.get('User-Agent', 'N/A')[:80]}...")
        print(f"  Accept: {headers.get('Accept', 'N/A')[:60]}...")
        print(f"  Modern Headers: Sec-Fetch-Dest={headers.get('Sec-Fetch-Dest')}, "
              f"Upgrade-Insecure-Requests={headers.get('Upgrade-Insecure-Requests')}")
        print()
    
    # Test HeaderFactory
    print("HeaderFactory Demo:")
    factory = HeaderFactory(pool_size=100)  # Small pool for demo
    
    # Generate some headers
    print("Sample headers from factory:")
    sample_headers = factory.get_headers()
    for key, value in list(sample_headers.items()):  
        print(f"  {key}: {value}")
    
    # Show statistics
    stats = factory.get_statistics()
    print(f"\nFactory Statistics:")
    print(f"  Pool size: {stats['pool_size']}/{stats['configured_size']}")
    print(f"  Success rate: {stats['generation_stats']['success']/(stats['generation_stats']['success']+stats['generation_stats']['failure'])*100:.1f}%")
    print(f"  Generation time: {stats['generation_stats']['total_time']:.2f}s")
    print(f"  Lazy mode: {stats['lazy_mode']}")
    
    # Test backward compatibility
    print(f"\nBackward Compatibility:")
    print(f"  get_random_user_agent(): {get_random_user_agent()[:60]}...")
    print(f"  get_random_origin(): {get_random_origin()}")
    
    print("\n=== Demo Complete ===")
    
    # Example configuration file content for reference
    sample_config = {
        "referer_categories": {
            "custom_search": {
                "urls": ["https://www.custom-search.com/", "https://search.custom.org/"],
                "weight": 0.5
            },
            "custom_social": {
                "urls": ["https://custom-social.com/", "https://social.custom.net/"],
                "weight": 0.5
            }
        },
        "pool_settings": {
            "default_size": 500,
            "lazy_generation": False,
            "parallel_workers": 8
        }
    }
    
    print(f"\nSample configuration structure:")
    print(json.dumps(sample_config, indent=2))
