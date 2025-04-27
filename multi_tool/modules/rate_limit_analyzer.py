#!/usr/bin/env python3
"""Module for analyzing server rate limiting configurations and thresholds."""

import logging
import time
import json
import statistics
import requests
import validators
import concurrent.futures
from urllib.parse import urlparse
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def analyze_rate_limits(target, test_intensity='medium', endpoint_path=None):
    """
    Analyze rate limiting implementations on a target server.
    
    Args:
        target (str): The URL to analyze
        test_intensity (str): The intensity of testing - 'low', 'medium', or 'high'
        endpoint_path (str, optional): Specific endpoint to test. Defaults to None (uses root path).
        
    Returns:
        dict: Rate limiting analysis results
    """
    logger.debug(f"Starting rate limit analysis on {target} with {test_intensity} intensity")
    
    # Validate target
    if not validators.url(target):
        # Try to convert to URL if it's a domain
        if validators.domain(target):
            target = f"https://{target}"
        else:
            return {
                "error": "Invalid target. Please provide a valid URL or domain.",
                "target": target
            }
    
    # Normalize target and determine endpoint
    parsed_url = urlparse(target)
    domain = parsed_url.netloc
    
    if endpoint_path:
        if not endpoint_path.startswith('/'):
            endpoint_path = '/' + endpoint_path
        if parsed_url.path and parsed_url.path != '/':
            test_url = f"{parsed_url.scheme}://{domain}{parsed_url.path}{endpoint_path}"
        else:
            test_url = f"{parsed_url.scheme}://{domain}{endpoint_path}"
    else:
        test_url = target
    
    # Determine test parameters based on intensity
    if test_intensity == 'low':
        burst_sizes = [5, 10, 20]
        delays = [0.5, 0.2, 0.1]
        max_requests = 20
    elif test_intensity == 'high':
        burst_sizes = [10, 30, 50, 100]
        delays = [0.1, 0.05, 0.02, 0.01]
        max_requests = 100
    else:  # medium (default)
        burst_sizes = [10, 20, 30]
        delays = [0.2, 0.1, 0.05]
        max_requests = 50
    
    # Initialize results
    results = {
        "target": target,
        "test_url": test_url,
        "domain": domain,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "test_intensity": test_intensity,
        "rate_limiting_detected": False,
        "rate_limit_threshold": None,
        "rate_limit_window": None,
        "rate_limit_headers": {},
        "test_results": [],
        "response_time_degradation": None,
        "blocked_indicators": [],
        "implementation_type": "unknown",
        "recommendations": []
    }
    
    try:
        # Initial test to check if the endpoint is accessible
        initial_response = requests.get(
            test_url, 
            headers={"User-Agent": "Multi-Tool Rate Limit Analyzer/1.0"},
            timeout=10
        )
        
        initial_status = initial_response.status_code
        
        if initial_status >= 400:
            results["error"] = f"Initial test failed with status code {initial_status}"
            return results
            
        # Check for rate limiting headers in the initial response
        check_rate_limit_headers(initial_response, results)
        
        # Perform burst tests with different intensities
        for i, (burst_size, delay) in enumerate(zip(burst_sizes, delays)):
            if i > 0 and results["rate_limiting_detected"]:
                # If rate limiting already detected, don't perform higher intensity tests
                break
                
            burst_result = perform_burst_test(test_url, burst_size, delay, max_requests)
            results["test_results"].append(burst_result)
            
            # Check if rate limiting was detected in this test
            if burst_result["rate_limiting_detected"]:
                results["rate_limiting_detected"] = True
                results["rate_limit_threshold"] = burst_result["estimated_threshold"]
                results["rate_limit_window"] = burst_result["estimated_window"]
                results["blocked_indicators"].extend(burst_result["block_indicators"])
                
        # Determine implementation type based on test results and headers
        determine_implementation_type(results)
        
        # Calculate response time degradation
        calculate_response_degradation(results)
        
        # Generate recommendations
        generate_recommendations(results)
        
    except Exception as e:
        logger.error(f"Error during rate limit analysis: {str(e)}")
        results["error"] = f"Analysis error: {str(e)}"
    
    return results

def check_rate_limit_headers(response, results):
    """
    Check for common rate limiting headers in the response.
    
    Args:
        response: The HTTP response object
        results (dict): The results dictionary to update
    """
    # Common rate limit headers to check
    rate_limit_headers = [
        # Standard headers
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-RateLimit-Reset",
        "Retry-After",
        
        # Vendor-specific headers
        "X-Rate-Limit-Limit",
        "X-Rate-Limit-Remaining",
        "X-Rate-Limit-Reset",
        "RateLimit-Limit",
        "RateLimit-Remaining",
        "RateLimit-Reset",
        
        # Cloudflare
        "cf-chl-bypass",
        
        # Akamai
        "X-Akamai-API-Limit"
    ]
    
    for header in rate_limit_headers:
        if header.lower() in [h.lower() for h in response.headers]:
            for h, v in response.headers.items():
                if h.lower() == header.lower():
                    results["rate_limit_headers"][h] = v
                    
    # If rate limit headers found, mark as detected
    if results["rate_limit_headers"]:
        results["rate_limiting_detected"] = True
        
        # Try to extract threshold and window from headers
        if "X-RateLimit-Limit" in results["rate_limit_headers"]:
            try:
                results["rate_limit_threshold"] = int(results["rate_limit_headers"]["X-RateLimit-Limit"])
            except (ValueError, TypeError):
                pass
                
        # Alternative headers for threshold
        if not results["rate_limit_threshold"]:
            for header in ["RateLimit-Limit", "X-Rate-Limit-Limit"]:
                if header in results["rate_limit_headers"]:
                    try:
                        results["rate_limit_threshold"] = int(results["rate_limit_headers"][header])
                        break
                    except (ValueError, TypeError):
                        pass

def perform_burst_test(url, burst_size, delay, max_requests):
    """
    Perform a burst test with the given parameters.
    
    Args:
        url (str): The URL to test
        burst_size (int): Number of requests in each burst
        delay (float): Delay between requests in seconds
        max_requests (int): Maximum total requests to send
        
    Returns:
        dict: Results of the burst test
    """
    logger.debug(f"Performing burst test on {url}: size={burst_size}, delay={delay}s")
    
    burst_result = {
        "burst_size": burst_size,
        "request_delay": delay,
        "total_requests": 0,
        "successful_requests": 0,
        "rate_limiting_detected": False,
        "estimated_threshold": None,
        "estimated_window": None,
        "response_times": [],
        "status_codes": {},
        "block_indicators": []
    }
    
    # Headers to use
    headers = {
        "User-Agent": "Multi-Tool Rate Limit Analyzer/1.0",
        "Accept": "text/html,application/json",
        "Cache-Control": "no-cache"
    }
    
    # Variables to track state
    consecutive_errors = 0
    last_success_time = time.time()
    
    # Use a session to maintain cookies
    with requests.Session() as session:
        try:
            # Make initial request to establish baseline
            initial_response = session.get(url, headers=headers, timeout=10)
            burst_result["response_times"].append(initial_response.elapsed.total_seconds())
            
            status_code = initial_response.status_code
            burst_result["status_codes"][status_code] = burst_result["status_codes"].get(status_code, 0) + 1
            burst_result["total_requests"] += 1
            
            if 200 <= status_code < 400:
                burst_result["successful_requests"] += 1
                last_success_time = time.time()
            
            # Track state for rate limiting detection
            initial_cookies = {k: v for k, v in session.cookies.items()}
            
            # Parallel requests for burst
            with concurrent.futures.ThreadPoolExecutor(max_workers=burst_size) as executor:
                while burst_result["total_requests"] < max_requests:
                    # Submit burst of requests
                    futures = []
                    for _ in range(min(burst_size, max_requests - burst_result["total_requests"])):
                        futures.append(executor.submit(session.get, url, headers=headers, timeout=10))
                    
                    # Process results
                    for future in concurrent.futures.as_completed(futures):
                        try:
                            response = future.result()
                            
                            # Update stats
                            burst_result["total_requests"] += 1
                            burst_result["response_times"].append(response.elapsed.total_seconds())
                            
                            status_code = response.status_code
                            burst_result["status_codes"][status_code] = burst_result["status_codes"].get(status_code, 0) + 1
                            
                            # Check if this is a successful response
                            if 200 <= status_code < 400:
                                burst_result["successful_requests"] += 1
                                last_success_time = time.time()
                                consecutive_errors = 0
                            else:
                                consecutive_errors += 1
                                
                                # Check for rate limiting indicators in the response
                                if status_code in [429, 503]:
                                    burst_result["rate_limiting_detected"] = True
                                    indicator = f"Status code {status_code} detected"
                                    if indicator not in burst_result["block_indicators"]:
                                        burst_result["block_indicators"].append(indicator)
                                        
                                    # If we have a Retry-After header, use it to estimate the window
                                    if "Retry-After" in response.headers:
                                        try:
                                            retry_after = int(response.headers["Retry-After"])
                                            burst_result["estimated_window"] = retry_after
                                        except (ValueError, TypeError):
                                            pass
                                
                                # Check response body for rate limiting messages
                                if response.text:
                                    if any(phrase in response.text.lower() for phrase in 
                                           ["rate limit", "too many requests", "throttled"]):
                                        burst_result["rate_limiting_detected"] = True
                                        indicator = "Rate limiting message in response body"
                                        if indicator not in burst_result["block_indicators"]:
                                            burst_result["block_indicators"].append(indicator)
                                
                                # Check if cookies changed, which might indicate rate limiting
                                current_cookies = {k: v for k, v in session.cookies.items()}
                                if current_cookies != initial_cookies:
                                    for k, v in current_cookies.items():
                                        if k not in initial_cookies or initial_cookies[k] != v:
                                            if any(term in k.lower() for term in ["rate", "limit", "block", "captcha"]):
                                                burst_result["rate_limiting_detected"] = True
                                                indicator = f"Rate limiting cookie detected: {k}"
                                                if indicator not in burst_result["block_indicators"]:
                                                    burst_result["block_indicators"].append(indicator)
                            
                            # If we've detected rate limiting and have enough data, break out
                            if burst_result["rate_limiting_detected"] and burst_result["total_requests"] >= 10:
                                break
                                
                        except requests.RequestException as e:
                            # Connection error could indicate rate limiting
                            burst_result["total_requests"] += 1
                            consecutive_errors += 1
                            logger.debug(f"Request error: {str(e)}")
                            
                            # Check if it might be rate limiting
                            if consecutive_errors > 3:
                                burst_result["rate_limiting_detected"] = True
                                indicator = f"Connection errors after {burst_result['successful_requests']} successful requests"
                                if indicator not in burst_result["block_indicators"]:
                                    burst_result["block_indicators"].append(indicator)
                    
                    # Break if rate limiting detected
                    if burst_result["rate_limiting_detected"]:
                        # Estimate the threshold based on successful requests before blocking
                        burst_result["estimated_threshold"] = burst_result["successful_requests"]
                        
                        # If we don't have a window estimate from Retry-After, estimate based on test
                        if not burst_result["estimated_window"]:
                            # Wait to see when we can make requests again
                            for wait_time in [5, 10, 15, 30]:
                                time.sleep(wait_time - (time.time() - last_success_time))
                                try:
                                    test_response = session.get(url, headers=headers, timeout=10)
                                    if 200 <= test_response.status_code < 400:
                                        burst_result["estimated_window"] = wait_time
                                        break
                                except requests.RequestException:
                                    pass
                        break
                        
                    # Add delay before next burst
                    time.sleep(delay)
                    
            # If we didn't detect rate limiting but have performance degradation, check that too
            if not burst_result["rate_limiting_detected"] and len(burst_result["response_times"]) > 5:
                # Check for significant response time increase
                initial_avg = statistics.mean(burst_result["response_times"][:3])
                final_avg = statistics.mean(burst_result["response_times"][-3:])
                
                if final_avg > initial_avg * 3 and final_avg > 1.0:  # 3x slower and more than 1 second
                    burst_result["rate_limiting_detected"] = True
                    burst_result["block_indicators"].append("Significant response time degradation")
                    burst_result["estimated_threshold"] = burst_result["successful_requests"]
                
        except Exception as e:
            logger.error(f"Error during burst test: {str(e)}")
    
    return burst_result

def determine_implementation_type(results):
    """
    Determine the type of rate limiting implementation based on results.
    
    Args:
        results (dict): The analysis results dictionary to update
    """
    # Check headers first for clear indicators
    headers = results["rate_limit_headers"]
    
    if headers:
        # Check for specific header patterns
        if any("cloudflare" in h.lower() for h in headers):
            results["implementation_type"] = "Cloudflare rate limiting"
        elif any("akamai" in h.lower() for h in headers):
            results["implementation_type"] = "Akamai rate limiting"
        elif any("nginx" in h.lower() for h in headers.values()):
            results["implementation_type"] = "Nginx rate limiting"
        elif any("aws" in h.lower() or "amazon" in h.lower() for h in headers.values()):
            results["implementation_type"] = "AWS WAF rate limiting"
        elif "X-RateLimit-Limit" in headers and "X-RateLimit-Remaining" in headers:
            results["implementation_type"] = "Standard API rate limiting"
    
    # Check block indicators for more clues
    for indicator in results["blocked_indicators"]:
        indicator_lower = indicator.lower()
        
        if "captcha" in indicator_lower:
            results["implementation_type"] = "CAPTCHA-based rate limiting"
            break
        elif "block" in indicator_lower and "ip" in indicator_lower:
            results["implementation_type"] = "IP-based blocking"
            break
    
    # If still unknown, use test results to make a best guess
    if results["implementation_type"] == "unknown" and results["test_results"]:
        for test in results["test_results"]:
            if test["rate_limiting_detected"]:
                if 429 in test["status_codes"]:
                    results["implementation_type"] = "Standard API rate limiting (429 response)"
                elif 503 in test["status_codes"]:
                    results["implementation_type"] = "Server protection rate limiting (503 response)"
                break

def calculate_response_degradation(results):
    """
    Calculate the response time degradation across tests.
    
    Args:
        results (dict): The analysis results dictionary to update
    """
    if not results["test_results"]:
        return
    
    # Find the first test with enough responses
    initial_times = None
    for test in results["test_results"]:
        if len(test["response_times"]) > 5:
            initial_times = test["response_times"][:3]
            break
    
    if not initial_times:
        return
    
    # Find the last test with enough responses
    final_times = None
    for test in reversed(results["test_results"]):
        if len(test["response_times"]) > 5:
            final_times = test["response_times"][-3:]
            break
    
    if not final_times:
        return
    
    # Calculate degradation
    initial_avg = statistics.mean(initial_times)
    final_avg = statistics.mean(final_times)
    
    if initial_avg > 0:
        degradation_factor = final_avg / initial_avg
        degradation_percent = (degradation_factor - 1) * 100
        
        results["response_time_degradation"] = {
            "initial_avg_response": initial_avg,
            "final_avg_response": final_avg,
            "degradation_factor": degradation_factor,
            "degradation_percent": degradation_percent
        }

def generate_recommendations(results):
    """
    Generate recommendations based on the rate limiting analysis.
    
    Args:
        results (dict): The analysis results dictionary to update
    """
    if results["rate_limiting_detected"]:
        results["recommendations"].append({
            "title": "Rate limiting detected",
            "description": f"The server implements rate limiting with an estimated threshold of {results['rate_limit_threshold']} requests.",
            "priority": "Informational"
        })
        
        # Implementation-specific recommendations
        impl_type = results["implementation_type"]
        
        if "standard api" in impl_type.lower():
            results["recommendations"].append({
                "title": "API rate limiting headers present",
                "description": "The server provides rate limiting information via standard headers. Consider implementing client-side handling of these headers to avoid hitting limits.",
                "priority": "Medium"
            })
        elif "captcha" in impl_type.lower():
            results["recommendations"].append({
                "title": "CAPTCHA-based rate limiting",
                "description": "The server uses CAPTCHAs to control excessive requests. Ensure your application can handle these challenges or implement proper request pacing.",
                "priority": "Medium"
            })
        elif "ip-based" in impl_type.lower():
            results["recommendations"].append({
                "title": "IP-based rate limiting",
                "description": "The server blocks excessive requests based on IP address. Consider implementing IP rotation or proxy usage for high-volume access.",
                "priority": "Medium"
            })
        
        # Response time degradation recommendations
        if results["response_time_degradation"] and results["response_time_degradation"]["degradation_factor"] > 2:
            results["recommendations"].append({
                "title": "Significant response time degradation under load",
                "description": f"Response times increased by {results['response_time_degradation']['degradation_percent']:.1f}% under load. Consider implementing client-side throttling to maintain performance.",
                "priority": "High"
            })
            
        # Threshold recommendations
        if results["rate_limit_threshold"]:
            results["recommendations"].append({
                "title": "Work within rate limit thresholds",
                "description": f"Design your application to work within the identified rate limit of approximately {results['rate_limit_threshold']} requests per window.",
                "priority": "High"
            })
            
            if results["rate_limit_window"]:
                results["recommendations"].append({
                    "title": "Implement backoff strategy",
                    "description": f"Implement an exponential backoff strategy with a minimum wait time of {results['rate_limit_window']} seconds when limits are hit.",
                    "priority": "Medium"
                })
    else:
        results["recommendations"].append({
            "title": "No rate limiting detected",
            "description": "The server does not appear to implement rate limiting. Consider implementing server-side rate limiting to protect against abuse.",
            "priority": "High"
        })
        
        results["recommendations"].append({
            "title": "Monitor for abuse",
            "description": "Without rate limiting, the server may be vulnerable to DoS attacks or resource exhaustion. Implement monitoring for unusual request patterns.",
            "priority": "High"
        })

if __name__ == "__main__":
    # Example usage
    results = analyze_rate_limits("https://example.com", test_intensity='low')
    print(json.dumps(results, indent=2))