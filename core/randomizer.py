# core/randomizer.py

import random
import socket
import struct
from typing import Dict, Any, List, Tuple

# ==============================================================================
# DATA DEFINITIONS
# ==============================================================================

# --- Referer Categories & Weights ---
# Weights are chosen to simulate real-world traffic distribution, where search
# engines are the most common source of referrals.
REFERER_CATEGORIES = {
    "search_engine": ([
        "https://www.google.com/", "https://www.bing.com/", "https://search.yahoo.com/",
        "https://duckduckgo.com/", "https://www.ecosia.org/", "https://yandex.com/"
    ], 0.45),  # 45% chance
    "social_media": ([
        "https://www.facebook.com/", "https://www.twitter.com/", "https://t.co/",
        "https://www.reddit.com/", "https://www.instagram.com/", "https://www.linkedin.com/"
    ], 0.25),  # 25% chance
    "tech_edu": ([
        "https://stackoverflow.com/", "https://github.com/", "https://news.ycombinator.com/",
        "https://medium.com/", "https://www.quora.com/"
    ], 0.15),  # 15% chance
    "news": ([
        "https://www.bbc.com/", "https://www.nytimes.com/", "https://www.cnn.com/",
        "https://www.theguardian.com/", "https://www.reuters.com/"
    ], 0.10),  # 10% chance
    "ecommerce": ([
        "https://www.amazon.com/", "https://www.ebay.com/", "https://www.alibaba.com/",
        "https://www.shopify.com/"
    ], 0.05),  # 5% chance
}

# --- Geolocation-based IPv4 Ranges (for simulation) ---
# These are large, non-reserved CIDR blocks associated with major regions.
# This makes generated IPs appear more geographically plausible.
GEO_IP_RANGES = {
    "north_america": [("63.0.0.0", "76.255.255.255")],
    "europe": [("77.0.0.0", "95.255.255.255")],
    "asia_pacific": [("101.0.0.0", "126.255.255.255")],
}

# --- Browser Profiles ---
# Each profile contains a consistent set of headers for a specific browser.
# This includes User-Agent Client Hints (Sec-CH-UA) for modern browsers.
BROWSER_PROFILES = [
    {
        "name": "Chrome_Windows",
        "headers": {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-CH-UA": '"Not_A Brand";v="8", "Chromium";v="{version}", "Google Chrome";v="{version}"',
            "Sec-CH-UA-Mobile": "?0",
            "Sec-CH-UA-Platform": '"Windows"',
        },
        "versions": ["120", "121", "122"]
    },
    {
        "name": "Firefox_Linux",
        "headers": {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/{version}.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        },
        "versions": ["119", "120", "121"]
    },
    {
        "name": "Safari_macOS",
        "headers": {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version}.1 Safari/605.1.15",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        },
        "versions": ["16", "17"]
    },
    {
        "name": "Chrome_Android",
        "headers": {
            "User-Agent": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Mobile Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-CH-UA": '"Not_A Brand";v="8", "Chromium";v="{version}", "Google Chrome";v="{version}"',
            "Sec-CH-UA-Mobile": "?1",
            "Sec-CH-UA-Platform": '"Android"',
        },
        "versions": ["120", "121", "122"]
    }
]

# ==============================================================================
# CORE RANDOMIZATION FUNCTIONS
# ==============================================================================

def _ip_to_int(ip: str) -> int:
    """Converts a string IPv4 address to its integer representation."""
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def _int_to_ip(ip_int: int) -> str:
    """Converts an integer to its string IPv4 address representation."""
    return socket.inet_ntoa(struct.pack("!I", ip_int))

def generate_random_ipv4() -> str:
    """
    Generates a random, plausible public IPv4 from a simulated geo-range.
    """
    # Select a random region and its corresponding IP ranges
    region = random.choice(list(GEO_IP_RANGES.keys()))
    start_ip_str, end_ip_str = random.choice(GEO_IP_RANGES[region])

    # Convert to integers and pick a random one in the range
    start_ip_int = _ip_to_int(start_ip_str)
    end_ip_int = _ip_to_int(end_ip_str)
    random_ip_int = random.randint(start_ip_int, end_ip_int)

    return _int_to_ip(random_ip_int)

def generate_random_ipv6() -> str:
    """
    Generates a random, plausible public IPv6 address.
    This focuses on the 2000::/3 range for globally routable addresses.
    """
    # Start with the global unicast prefix (2001:: to be specific and common)
    # 2001:0db8 is for documentation, but we'll use a more general prefix.
    # We generate 7 more hextets (16-bit groups).
    return "2001:" + ":".join(f"{random.randint(0, 0xFFFF):x}" for _ in range(7))

def generate_random_ip() -> str:
    """
    Generates either a random IPv4 or IPv6 address, with a higher chance for IPv4.
    """
    return generate_random_ipv4() if random.random() < 0.8 else generate_random_ipv6()

def get_random_referer() -> str:
    """
    Selects a random referer URL using weighted categories for realism.
    """
    categories = list(REFERER_CATEGORIES.keys())
    weights = [REFERER_CATEGORIES[cat][1] for cat in categories]

    # Choose a category based on the weights
    chosen_category_name = random.choices(categories, weights, k=1)[0]
    
    # Choose a random referer from the selected category's list
    referer_list = REFERER_CATEGORIES[chosen_category_name][0]
    return random.choice(referer_list)

def get_random_browser_profile() -> Dict[str, str]:
    """
    Selects a random browser profile and returns a complete, consistent
    set of headers with a randomized version number.

    Returns:
        A dictionary containing a consistent set of HTTP headers.
    """
    profile = random.choice(BROWSER_PROFILES)
    version = random.choice(profile["versions"])
    
    # Create a new dictionary to hold the formatted headers
    formatted_headers = {}
    for key, value in profile["headers"].items():
        if "{version}" in value:
            formatted_headers[key] = value.format(version=version)
        else:
            formatted_headers[key] = value

        
    return formatted_headers

# ==============================================================================
# HEADER FACTORY CLASS
# ==============================================================================

class HeaderFactory:
    """
    A factory to pre-compute and store a pool of realistic header sets.

    This class is designed to be initialized once at the start of an application.
    Workers can then quickly fetch fully-formed, randomized, and consistent
    header dictionaries from the pool, minimizing per-request overhead.

    Attributes:
        pool (List[Dict[str, Any]]): A list of pre-generated header dictionaries.
    """
    def __init__(self, pool_size: int = 2000):
        """
        Initializes the factory and pre-computes the header pool.

        Args:
            pool_size (int): The number of header sets to pre-generate.
        """
        self.pool: List[Dict[str, Any]] = []
        self._generate_pool(pool_size)

    def _generate_pool(self, size: int):
        """Internal method to create the pool of headers."""
        print(f"Pre-computing {size} header sets for the factory pool...")
        try:
            for _ in range(size):
                # 1. Get a base set of consistent browser headers
                headers = get_random_browser_profile()

                # 2. Add randomized, non-profile-specific headers
                headers['Referer'] = get_random_referer()
                headers['X-Forwarded-For'] = generate_random_ip()
                
                # 3. Add other common headers
                headers.update({
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                    'Cache-Control': 'no-cache',
                    'Pragma': 'no-cache',
                })
                
                self.pool.append(headers)
            print("Header pool generation complete.")
        except Exception as e:
            print(f"CRITICAL: Failed to generate header pool: {e}", flush=True)


    def get_headers(self) -> Dict[str, Any]:
        """
        Provides a random, pre-computed header set from the pool.
        This version includes a safeguard against an empty pool.
        """
        if not self.pool:
            # This is a fallback in case pool generation fails.
            return {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache',
            }
        return random.choice(self.pool)

# ==============================================================================
# BACKWARDS COMPATIBILITY WRAPPERS 
# ==============================================================================

def get_random_user_agent() -> str:
    """
    Selects and returns a random User-Agent string.
    Note: For full consistency, use get_random_browser_profile() or HeaderFactory.
    """
    profile = random.choice(BROWSER_PROFILES)
    version = random.choice(profile["versions"])
    return profile["headers"]["User-Agent"].format(version=version)

def get_random_origin() -> str:
    """
    Selects and returns a random Origin URL from the referer list.
    """
    return get_random_referer().rstrip('/')