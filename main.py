#!/usr/bin/env python3

import argparse
import logging
import requests
from urllib.parse import urlparse
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class CookieSecurityAnalyzer:
    """
    A class to analyze cookies for security flags (HttpOnly, Secure, SameSite) and report potential vulnerabilities.
    """

    def __init__(self, url):
        """
        Initializes the CookieSecurityAnalyzer with the target URL.

        Args:
            url (str): The URL to analyze.
        """
        self.url = url
        self.cookies = {}
        self.domain = urlparse(url).netloc
        if not self.domain:
            raise ValueError(f"Invalid URL: {url}")
        self.session = requests.Session()  # Use a session to persist cookies

    def fetch_cookies(self):
        """
        Fetches cookies from the target URL.
        """
        try:
            response = self.session.get(self.url, allow_redirects=True)  # Allow redirects
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

            self.cookies = response.cookies
            if not self.cookies:
                logging.warning(f"No cookies found for {self.url}")
            return True

        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching cookies from {self.url}: {e}")
            return False

    def analyze_cookies(self):
        """
        Analyzes the fetched cookies for security flags.
        """
        if not self.cookies:
            logging.warning("No cookies to analyze.  Run fetch_cookies() first.")
            return []
        
        vulnerabilities = []
        for name, value in self.cookies.items():
            cookie = self.cookies.get(name)  # Use get to avoid KeyError

            if cookie is None:
                logging.warning(f"Cookie {name} is unexpectedly None.")
                continue

            http_only = cookie.has_nonstandard_attr('httponly')
            secure = cookie.secure
            same_site = cookie.get('samesite')

            if not http_only:
                vulnerabilities.append(f"Cookie '{name}' is missing HttpOnly flag.  Potential risk of XSS attacks.")
            if not secure and self.url.startswith('https'): #Only warn if using HTTPS
                vulnerabilities.append(f"Cookie '{name}' is missing Secure flag.  Potential risk of man-in-the-middle attacks over non-HTTPS connections.")
            if not same_site:
                vulnerabilities.append(f"Cookie '{name}' is missing SameSite attribute.  Potential risk of CSRF attacks.")
            elif same_site.lower() == 'none' and not secure:
                vulnerabilities.append(f"Cookie '{name}' has SameSite=None but is missing Secure flag. This is insecure and may be rejected by browsers.")

        return vulnerabilities
    
    def report_vulnerabilities(self, vulnerabilities):
        """
        Reports the identified vulnerabilities.

        Args:
            vulnerabilities (list): A list of vulnerability strings.
        """
        if vulnerabilities:
            print("Vulnerabilities found:")
            for vulnerability in vulnerabilities:
                print(f"  - {vulnerability}")
        else:
            print("No cookie security vulnerabilities found.")


def setup_argparse():
    """
    Sets up the command-line argument parser.

    Returns:
        argparse.ArgumentParser: The argument parser.
    """
    parser = argparse.ArgumentParser(description="Analyze cookies for security flags.")
    parser.add_argument("url", help="The URL to analyze.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    return parser

def main():
    """
    Main function to execute the cookie security analyzer.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        analyzer = CookieSecurityAnalyzer(args.url)
        if not analyzer.fetch_cookies():
            sys.exit(1)

        vulnerabilities = analyzer.analyze_cookies()
        analyzer.report_vulnerabilities(vulnerabilities)

    except ValueError as e:
        logging.error(f"Invalid input: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

#Example usage:
# To run the tool:  python vuln_cookie_security_analyzer.py https://example.com
# To run with verbose logging: python vuln_cookie_security_analyzer.py -v https://example.com