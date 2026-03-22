import requests
import json
import urllib3
import os
import logging
from dotenv import load_dotenv
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

# ====== GLOBAL SETTINGS ======
ssl_verify_env = os.getenv('SSL_VERIFY', 'True')
if ssl_verify_env.lower() == 'false':
    SSL_VERIFY = False
elif ssl_verify_env.lower() == 'true':
    SSL_VERIFY = True
else:
    # Assume it's a path to a CA bundle file
    SSL_VERIFY = ssl_verify_env

# FIX #11: Request Timeout Configuration
# Prevent resource exhaustion from hanging connections
REQUEST_TIMEOUT = 30  # seconds
LONG_REQUEST_TIMEOUT = 60  # for deployment operations

# ====== CONFIGURATION ======
def load_fmc_config():
    """Load FMC configuration from environment variables"""
    fmc_list = []
    
    # Define the FMC instances to look for
    fmc_instances = ['BRU', 'FRA', 'DFW', 'JFK']
    
    for instance in fmc_instances:
        name = os.getenv(f'FMC_{instance}_NAME')
        url = os.getenv(f'FMC_{instance}_URL')
        username = os.getenv(f'FMC_{instance}_USERNAME')
        password = os.getenv(f'FMC_{instance}_PASSWORD')
        
        # Only add if all required fields are present
        if all([name, url, username, password]):
            fmc_list.append({
                "name": name,
                "url": url,
                "username": username,
                "password": password
            })
        else:
            logger.info(f"⚠️  Skipping FMC_{instance} - missing configuration in .env file")
    
    return fmc_list

def validate_uuid(uuid_string):
    """
    Validate that a string is a valid UUID format.
    This prevents injection attacks through ID parameters.
    Returns True if valid UUID, False otherwise.
    """
    import re
    if not uuid_string:
        return False
    # UUID format: 8-4-4-4-12 hex digits
    uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
    return bool(uuid_pattern.match(str(uuid_string)))

# Load domain UUID from environment
DOMAIN_UUID = os.getenv("DOMAIN_UUID", "e276abec-e0f2-11e3-8169-6d9ed49b625f")


# ====== CORE FUNCTIONS ======
def check_user_permissions(fmc_url, token):
    """Check user permissions and accessible domains"""
    headers = {"X-auth-access-token": token}
    
    logger.info(f"🔍 Checking user permissions for {fmc_url}...")
    
    # Check user info with different endpoints
    user_endpoints = [
        f"{fmc_url}/api/fmc_platform/v1/info/userinfo",
        f"{fmc_url}/api/fmc_platform/v1/auth/userinfo"
    ]
    
    for endpoint in user_endpoints:
        try:
            r = requests.get(endpoint, headers=headers, verify=SSL_VERIFY, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200:
                user_info = r.json()
                logger.info(f"🔍 User info: {user_info.get('userName', 'Unknown')}")
                logger.info(f"🔍 User roles: {[role.get('name') for role in user_info.get('roles', [])]}")
                break
            else:
                logger.info(f"⚠️  Could not get user info from {endpoint}: {r.status_code}")
        except Exception as e:
            logger.info(f"⚠️  Error getting user info from {endpoint}: {e}")
    
    # Check accessible domains
    logger.info(f"🏢 Checking accessible domains...")
    domain_url = f"{fmc_url}/api/fmc_platform/v1/info/domain"
    try:
        r = requests.get(domain_url, headers=headers, verify=SSL_VERIFY, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            domains = r.json()
            logger.info(f"🔍 Accessible domains:")
            for domain in domains.get('items', []):
                logger.info(f"   - {domain.get('name')} (UUID: {domain.get('uuid')})")
                if domain.get('uuid') == DOMAIN_UUID:
                    logger.info(f"     ✅ Using this domain")
        else:
            logger.info(f"⚠️  Could not get domain info: {r.status_code}")
    except Exception as e:
        logger.info(f"⚠️  Error getting domain info: {e}")
    
    # Test basic object read permissions
    test_endpoints = [
        f"{fmc_url}/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/fqdns?limit=1",
        f"{fmc_url}/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/networkgroups?limit=1"
    ]
    
    for endpoint in test_endpoints:
        try:
            r = requests.get(endpoint, headers=headers, verify=SSL_VERIFY, timeout=REQUEST_TIMEOUT)
            obj_type = "FQDNs" if "fqdns" in endpoint else "Network Groups"
            if r.status_code == 200:
                logger.info(f"✅ Can read {obj_type}")
            else:
                logger.info(f"❌ Cannot read {obj_type}: {r.status_code}")
        except Exception as e:
            logger.info(f"⚠️  Error testing {obj_type}: {e}")


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception_type((requests.exceptions.ConnectionError, requests.exceptions.Timeout)),
    reraise=True
)
def fmc_auth(fmc_url, username, password):
    url = f"{fmc_url}/api/fmc_platform/v1/auth/generatetoken"
    try:
        r = requests.post(url, auth=(username, password), verify=SSL_VERIFY, timeout=30)
        if r.status_code == 204:
            token = r.headers.get("X-auth-access-token")
            refresh_token = r.headers.get("X-auth-refresh-token")
            domain_uuid = r.headers.get("DOMAIN_UUID")
            logger.info(f"✅ Authentication successful for {fmc_url}")
            logger.info(f"🔍 Domain UUID from auth: {domain_uuid}")
            return token
        else:
            logger.info(f"❌ Auth failed for {fmc_url}: {r.status_code} {r.text}")
            return None
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        logger.warning(f"⚠️  Connection/timeout error with {fmc_url}, will retry: {e}")
        raise  # Re-raise for tenacity to handle retry
    except Exception as e:
        logger.info(f"❌ Connection error with {fmc_url}: {e}")
        return None


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception_type((requests.exceptions.ConnectionError, requests.exceptions.Timeout)),
    reraise=True
)
def create_fqdn(fmc_url, token, fqdn_name, fqdn_value, description=None):
    """Create FQDN object and return structured response"""
    url = f"{fmc_url}/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/fqdns"
    headers = {"Content-Type": "application/json", "X-auth-access-token": token}
    payload = {
        "name": fqdn_name,
        "type": "FQDN",
        "value": fqdn_value,
        "dnsResolution": "IPV4_AND_IPV6",
        "overridable": False
    }

    # Add description if provided
    if description:
        payload["description"] = description

    logger.info(f"📤 Creating FQDN '{fqdn_name}' on {fmc_url}...")
    try:
        logger.info(f"   Payload: {payload}")
        r = requests.post(url, headers=headers, json=payload, verify=SSL_VERIFY, timeout=30)
        logger.info(f"📥 Response status: {r.status_code}")
        
        if r.status_code == 201:
            response_data = r.json()
            fqdn_id = response_data.get("id")
            logger.info(f"✅ Object '{fqdn_name}' created successfully on {fmc_url}")
            return {
                "success": True,
                "data": {"id": fqdn_id},
                "message": f"FQDN '{fqdn_name}' created successfully",
                "response": response_data
            }
        elif r.status_code == 422:
            logger.warning(f"⚠️  Object '{fqdn_name}' already exists on {fmc_url}, fetching ID...")
            # Try to get the existing object ID
            try:
                existing = requests.get(url, headers=headers, verify=SSL_VERIFY, timeout=REQUEST_TIMEOUT)
                if existing.status_code == 200:
                    for obj in existing.json().get("items", []):
                        if obj["name"] == fqdn_name:
                            return {
                                "success": True,
                                "data": {"id": obj["id"]},
                                "message": f"FQDN '{fqdn_name}' already exists",
                                "existing": True
                            }
            except Exception as e:
                logger.error(f"Error fetching existing FQDN: {e}")
            
            return {
                "success": False,
                "message": f"FQDN '{fqdn_name}' already exists but could not retrieve ID",
                "error": "Conflict - object exists"
            }
        else:
            error_msg = f"Failed to create FQDN: HTTP {r.status_code}"
            logger.error(f"❌ Response status: {r.status_code}")
            logger.error(f"❌ Response headers: {dict(r.headers)}")
            logger.error(f"❌ Response body: {r.text}")
            try:
                error_detail = r.json()
                logger.error(f"❌ Parsed error detail: {error_detail}")
                if 'error' in error_detail:
                    messages = error_detail['error'].get('messages', [])
                    if messages and len(messages) > 0:
                        error_msg += f" - {messages[0].get('description', 'Unknown error')}"
            except:
                error_msg += f" - {r.text}"
            
            logger.error(f"❌ {error_msg}")
            return {
                "success": False,
                "message": error_msg,
                "error": f"HTTP {r.status_code}",
                "response_text": r.text
            }
    except Exception as e:
        error_msg = f"Exception creating FQDN: {str(e)}"
        logger.error(f"❌ {error_msg}")
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception_type((requests.exceptions.ConnectionError, requests.exceptions.Timeout)),
    reraise=True
)
def create_host(fmc_url, token, host_name, ip_address, description=None):
    """Create Host object and return structured response"""
    url = f"{fmc_url}/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/hosts"
    headers = {"Content-Type": "application/json", "X-auth-access-token": token}
    payload = {
        "name": host_name,
        "type": "Host",
        "value": ip_address,
        "overridable": False
    }

    # Add description if provided
    if description:
        payload["description"] = description

    # Try to create the Host directly (don't check if exists first to avoid token expiration)
    logger.info(f"📤 Creating Host '{host_name}' with IP '{ip_address}' on {fmc_url}...")
    try:
        logger.info(f"   Payload: {payload}")
        r = requests.post(url, headers=headers, json=payload, verify=SSL_VERIFY, timeout=30)
        logger.info(f"📥 Response status: {r.status_code}")
        
        if r.status_code == 201:
            response_data = r.json()
            host_id = response_data.get("id")
            logger.info(f"✅ Host '{host_name}' created successfully on {fmc_url}")
            return {
                "success": True,
                "data": {"id": host_id},
                "message": f"Host '{host_name}' created successfully",
                "response": response_data
            }
        elif r.status_code == 409:
            logger.warning(f"⚠️  Host '{host_name}' already exists on {fmc_url}, fetching ID...")
            # Try to get the existing object ID
            try:
                existing = requests.get(url, headers=headers, verify=SSL_VERIFY, timeout=REQUEST_TIMEOUT)
                if existing.status_code == 200:
                    for obj in existing.json().get("items", []):
                        if obj["name"] == host_name:
                            return {
                                "success": True,
                                "data": {"id": obj["id"]},
                                "message": f"Host '{host_name}' already exists",
                                "existing": True
                            }
            except Exception as e:
                logger.error(f"Error fetching existing Host: {e}")
            
            return {
                "success": False,
                "message": f"Host '{host_name}' already exists but could not retrieve ID",
                "error": "Conflict - object exists"
            }
        else:
            error_msg = f"Failed to create Host: HTTP {r.status_code}"
            logger.error(f"❌ Response status: {r.status_code}")
            logger.error(f"❌ Response headers: {dict(r.headers)}")
            logger.error(f"❌ Response body: {r.text}")
            try:
                error_detail = r.json()
                logger.error(f"❌ Parsed error detail: {error_detail}")
                if 'error' in error_detail:
                    messages = error_detail['error'].get('messages', [])
                    if messages and len(messages) > 0:
                        error_msg += f" - {messages[0].get('description', 'Unknown error')}"
            except:
                error_msg += f" - {r.text}"
            
            logger.error(f"❌ {error_msg}")
            return {
                "success": False,
                "message": error_msg,
                "error": f"HTTP {r.status_code}",
                "response_text": r.text
            }
    except Exception as e:
        error_msg = f"Exception creating Host: {str(e)}"
        logger.error(f"❌ {error_msg}")
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception_type((requests.exceptions.ConnectionError, requests.exceptions.Timeout)),
    reraise=True
)
def create_network(fmc_url, token, network_name, network_value, description=None):
    """Create Network object with CIDR notation and return structured response"""
    import ipaddress

    # Store original value for logging
    original_value = network_value

    # Normalize the network address - FMC requires the actual network address, not a host address
    # For example: 10.10.10.1/24 should be normalized to 10.10.10.0/24
    try:
        network_obj = ipaddress.IPv4Network(network_value, strict=False)
        normalized_value = str(network_obj)  # This will give us the proper network address

        if normalized_value != original_value:
            logger.info(f"📋 Network value normalized: '{original_value}' -> '{normalized_value}'")
        else:
            logger.info(f"📋 Network value is already normalized: '{network_value}'")

        network_value = normalized_value
    except Exception as e:
        logger.warning(f"⚠️  Could not normalize network value '{network_value}': {e}")
        # Continue with the original value if normalization fails

    url = f"{fmc_url}/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/networks"
    headers = {"Content-Type": "application/json", "X-auth-access-token": token}
    payload = {
        "name": network_name,
        "type": "Network",
        "value": network_value,
        "overridable": False
    }

    # Add description if provided
    if description:
        payload["description"] = description

    logger.info(f"📤 Creating Network '{network_name}' with value '{network_value}' on {fmc_url}...")
    if original_value != network_value:
        logger.info(f"   Original input: '{original_value}' | Sending: '{network_value}'")
    try:
        logger.info(f"   Payload: {payload}")
        r = requests.post(url, headers=headers, json=payload, verify=SSL_VERIFY, timeout=30)
        logger.info(f"📥 Response status: {r.status_code}")

        if r.status_code == 201:
            response_data = r.json()
            network_id = response_data.get("id")
            logger.info(f"✅ Network '{network_name}' created successfully on {fmc_url}")
            if original_value != network_value:
                logger.info(f"   User entered: '{original_value}' | Network created with: '{network_value}'")
            return {
                "success": True,
                "data": {"id": network_id},
                "message": f"Network '{network_name}' created successfully",
                "response": response_data
            }
        elif r.status_code == 409 or r.status_code == 422:
            logger.warning(f"⚠️  Network '{network_name}' already exists on {fmc_url}, fetching ID...")
            # Try to get the existing object ID
            try:
                existing = requests.get(url, headers=headers, verify=SSL_VERIFY, timeout=REQUEST_TIMEOUT)
                if existing.status_code == 200:
                    for obj in existing.json().get("items", []):
                        if obj["name"] == network_name:
                            return {
                                "success": True,
                                "data": {"id": obj["id"]},
                                "message": f"Network '{network_name}' already exists",
                                "existing": True
                            }
            except Exception as e:
                logger.error(f"Error fetching existing Network: {e}")
            
            return {
                "success": False,
                "message": f"Network '{network_name}' already exists but could not retrieve ID",
                "error": "Conflict - object exists"
            }
        else:
            error_msg = f"Failed to create Network: HTTP {r.status_code}"
            logger.error(f"❌ Response status: {r.status_code}")
            logger.error(f"❌ Network name: '{network_name}'")
            logger.error(f"❌ User entered IP: '{original_value}' | Sent to FMC: '{network_value}'")
            logger.error(f"❌ Response headers: {dict(r.headers)}")
            logger.error(f"❌ Response body: {r.text}")
            try:
                error_detail = r.json()
                logger.error(f"❌ Parsed error detail: {error_detail}")
                if 'error' in error_detail:
                    messages = error_detail['error'].get('messages', [])
                    if messages and len(messages) > 0:
                        error_msg += f" - {messages[0].get('description', 'Unknown error')}"
            except:
                error_msg += f" - {r.text}"
            
            logger.error(f"❌ {error_msg}")
            return {
                "success": False,
                "message": error_msg,
                "error": f"HTTP {r.status_code}",
                "response_text": r.text
            }
    except Exception as e:
        error_msg = f"Exception creating Network: {str(e)}"
        logger.error(f"❌ {error_msg}")
        logger.error(f"❌ Network name: '{network_name}'")
        logger.error(f"❌ User entered IP: '{original_value}' | Attempted to send: '{network_value}'")
        logger.error(f"❌ FMC URL: {fmc_url}")
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


def get_network_group_id(fmc_url, token, group_name):
    """Search for a network group by name with pagination support"""
    offset = 0
    limit = 100
    
    logger.info(f"🔍 Searching for network group '{group_name}' on {fmc_url}...")
    
    try:
        while True:
            url = f"{fmc_url}/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/networkgroups"
            headers = {"X-auth-access-token": token}
            params = {
                "offset": offset,
                "limit": limit
            }
            
            r = requests.get(url, headers=headers, params=params, verify=SSL_VERIFY, timeout=REQUEST_TIMEOUT)
            
            if r.status_code == 200:
                response_data = r.json()
                groups = response_data.get("items", [])
                
                # Search for the group in this page
                for obj in groups:
                    if obj["name"] == group_name:
                        logger.info(f"✅ Found group '{group_name}' with ID {obj['id']} on {fmc_url}")
                        return obj["id"]
                
                # Check if we need to fetch more pages
                paging = response_data.get("paging", {})
                total_count = paging.get("count", len(groups))
                current_count = offset + len(groups)
                
                logger.info(f"📋 Searched {current_count} of {total_count} network groups (page offset {offset})")
                
                # If we got fewer items than the limit, or we have checked all items, we're done
                if len(groups) < limit or current_count >= total_count:
                    break
                
                offset += limit
            else:
                logger.info(f"❌ Failed to get network groups from {fmc_url}: {r.status_code} {r.text}")
                return None
        
        # Group not found after checking all pages
        logger.info(f"❌ Group '{group_name}' not found on {fmc_url} (searched {current_count} groups)")
        return None
        
    except Exception as e:
        logger.info(f"❌ Exception getting network group ID from {fmc_url}: {e}")
        return None


def get_network_group_details(fmc_url, token, group_id):
    """Get detailed information about a network group including existing objects"""
    url = f"{fmc_url}/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/networkgroups/{group_id}"
    headers = {"X-auth-access-token": token}
    
    try:
        r = requests.get(url, headers=headers, verify=SSL_VERIFY, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            return {"success": True, "data": r.json()}
        else:
            return {"success": False, "error": f"Failed to get group details: {r.status_code}"}
    except Exception as e:
        return {"success": False, "error": f"Error getting group details: {str(e)}"}


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception_type((requests.exceptions.ConnectionError, requests.exceptions.Timeout)),
    reraise=True
)
def update_network_group(fmc_url, token, group_id, fqdn_id, group_name=None):
    """Update network group while preserving existing objects"""
    logger.info(f"🔄 Starting network group update - Group ID: {group_id}, FQDN ID: {fqdn_id}")

    # First, get the current group details to preserve existing objects
    group_details = get_network_group_details(fmc_url, token, group_id)
    
    if not group_details["success"]:
        logger.info(f"❌ Failed to get group details: {group_details.get('error', 'Unknown error')}")
        return group_details
    
    current_group = group_details["data"]
    existing_objects = current_group.get("objects", [])
    existing_literals = current_group.get("literals", [])
    display_name = group_name or current_group.get("name", "Unknown Group")
    
    logger.info(f"📋 Current group '{display_name}' has {len(existing_objects)} existing objects")
    
    # Debug: Show current objects in group
    if existing_objects:
        logger.info(f"📋 Current objects in group:")
        for i, obj in enumerate(existing_objects):
            logger.info(f"   {i+1}. Type: {obj.get('type')}, ID: {obj.get('id')}, Name: {obj.get('name', 'N/A')}")
    else:
        logger.info(f"📋 Group is currently empty")
    
    # Check if FQDN already exists in the group
    fqdn_exists = any(obj.get("id") == fqdn_id for obj in existing_objects if obj.get("type") == "FQDN")
    
    if fqdn_exists:
        logger.info(f"ℹ️  FQDN already exists in '{display_name}' on {fmc_url}")
        return {"success": True, "message": "FQDN already exists in group"}
    
    # Add the new FQDN to existing objects (will be used in fallback method)
    new_fqdn_object = {"type": "FQDN", "id": fqdn_id}
    updated_objects = existing_objects + [new_fqdn_object]
    logger.info(f"📝 Will update group with {len(updated_objects)} total objects (added 1 FQDN)")
    
    url = f"{fmc_url}/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/networkgroups/{group_id}"
    headers = {"Content-Type": "application/json", "X-auth-access-token": token}
    payload = {
        "id": group_id,
        "name": current_group.get("name"),
        "type": "NetworkGroup",
        "objects": updated_objects,
        "literals": existing_literals
    }
    
    # Try using FMC API action=add first (more efficient)
    logger.info(f"📤 Trying action=add method to update network group on {fmc_url}...")
    logger.info(f"📤 Adding FQDN ID: {fqdn_id} to group ID: {group_id}")
    
    # First, get the FQDN object details to get its name (required for proper API calls)
    fqdn_url = f"{fmc_url}/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/fqdns/{fqdn_id}"
    fqdn_name = None
    fqdn_value = None
    
    try:
        logger.info(f"📋 Fetching FQDN details from: {fqdn_url}")
        fqdn_response = requests.get(fqdn_url, headers={"X-auth-access-token": token}, verify=SSL_VERIFY, timeout=30)
        logger.info(f"📋 FQDN fetch response: {fqdn_response.status_code}")
        
        if fqdn_response.status_code == 200:
            fqdn_data = fqdn_response.json()
            fqdn_name = fqdn_data.get("name")
            fqdn_value = fqdn_data.get("value")
            logger.info(f"📋 Retrieved FQDN - Name: {fqdn_name}, Value: {fqdn_value}")
        else:
            logger.info(f"⚠️  Could not retrieve FQDN details: {fqdn_response.status_code}")
            try:
                error_data = fqdn_response.json()
                logger.info(f"📋 FQDN fetch error: {error_data}")
            except:
                logger.info(f"📋 FQDN fetch error text: {fqdn_response.text}")
    except Exception as e:
        logger.info(f"⚠️  Exception retrieving FQDN details: {e}")
    
    if not fqdn_name:
        logger.info(f"❌ Could not retrieve FQDN name for ID {fqdn_id}. This may cause issues.")
    
    add_url = f"{fmc_url}/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/networkgroups/{group_id}?action=add"
    
    # Build object entry with name if available (as per FMC API documentation)
    fqdn_object = {"type": "FQDN", "id": fqdn_id}
    if fqdn_name:
        fqdn_object["name"] = fqdn_name
    
    # Build the payload for action=add (include the new objects to add)
    add_payload = {
        "type": "NetworkGroup",
        "objects": [fqdn_object] if fqdn_object else [],  # Only the FQDN to add
        "literals": []  # No literals to add
    }
    
    logger.info(f"📤 action=add payload: {add_payload}")
    
    try:
        r = requests.put(add_url, headers=headers, json=add_payload, verify=SSL_VERIFY, timeout=30)
        logger.info(f"📤 action=add response status: {r.status_code}")
        
        if r.status_code == 200:
            logger.info(f"✅ FQDN added to '{display_name}' on {fmc_url} using action=add method")
            # Verify the object was actually added by checking the group again
            verify_result = get_network_group_details(fmc_url, token, group_id)
            if verify_result["success"]:
                updated_group = verify_result["data"]
                updated_objects = updated_group.get("objects", [])
                fqdn_in_group = any(obj.get("id") == fqdn_id for obj in updated_objects if obj.get("type") == "FQDN")
                if fqdn_in_group:
                    logger.info(f"✅ Verified: FQDN {fqdn_id} is now in group '{display_name}'")
                    return {"success": True, "message": "FQDN added to network group successfully"}
                else:
                    logger.info(f"❌ Verification failed: FQDN {fqdn_id} not found in group after action=add")
                    logger.info(f"📋 Group now has {len(updated_objects)} objects")
            return {"success": True, "message": "FQDN added to network group successfully"}
        else:
            logger.info(f"⚠️  action=add failed ({r.status_code})")
            try:
                error_response = r.json()
                logger.info(f"📤 action=add error response: {error_response}")
            except:
                logger.info(f"📤 action=add error text: {r.text}")
            print("⚠️  Falling back to traditional method...")
    except Exception as e:
        logger.info(f"⚠️  action=add exception ({str(e)}), falling back to traditional method...")
    
    # Fallback to traditional method if action=add fails
    logger.info(f"📤 Using traditional PUT method to update network group on {fmc_url}...")
    logger.info(f"📤 Payload summary: {len(updated_objects)} objects, {len(existing_literals)} literals")
    
    try:
        r = requests.put(url, headers=headers, json=payload, verify=SSL_VERIFY, timeout=REQUEST_TIMEOUT)
        logger.info(f"📤 Traditional PUT response status: {r.status_code}")
        
        if r.status_code == 200:
            logger.info(f"✅ FQDN added to '{display_name}' on {fmc_url} (preserving {len(existing_objects)} existing objects)")
            # Verify the object was actually added
            verify_result = get_network_group_details(fmc_url, token, group_id)
            if verify_result["success"]:
                updated_group = verify_result["data"]
                updated_objects_verify = updated_group.get("objects", [])
                fqdn_in_group = any(obj.get("id") == fqdn_id for obj in updated_objects_verify if obj.get("type") == "FQDN")
                if fqdn_in_group:
                    logger.info(f"✅ Verified: FQDN {fqdn_id} is now in group '{display_name}'")
                else:
                    logger.info(f"❌ Verification failed: FQDN {fqdn_id} not found in group after traditional PUT")
                    logger.info(f"📋 Group now has {len(updated_objects_verify)} objects")
            return {"success": True, "message": "FQDN added to network group successfully"}
        else:
            error_msg = f"HTTP {r.status_code}"
            try:
                error_data = r.json()
                if "error" in error_data and "messages" in error_data["error"]:
                    error_msg += f": {error_data['error']['messages'][0].get('description', 'Unknown error')}"
                else:
                    error_msg += f": {r.text}"
            except:
                error_msg += f": {r.text}"
            logger.info(f"❌ Failed to update network group on {fmc_url}: {error_msg}")
            return {"success": False, "message": error_msg}
    except Exception as e:
        error_msg = f"Exception updating network group: {str(e)}"
        logger.info(f"❌ {error_msg}")
        return {"success": False, "message": error_msg}


def create_fqdn_alternative(fmc_url, token, fqdn_name, fqdn_value, description=None):
    """Try alternative methods to create FQDN and return structured response"""
    headers = {"Content-Type": "application/json", "X-auth-access-token": token}
    url = f"{fmc_url}/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/fqdns"
    
    # Method 1: Try with minimal payload
    minimal_payload = {
        "name": fqdn_name,
        "value": fqdn_value,
        "type": "FQDN"
    }
    
    # Add description if provided
    if description:
        minimal_payload["description"] = description
    
    logger.info(f"🔄 Trying alternative method 1 (minimal payload)...")
    try:
        r = requests.post(url, headers=headers, json=minimal_payload, verify=SSL_VERIFY, timeout=REQUEST_TIMEOUT)
        logger.info(f"   Method 1 response: {r.status_code}")
        if r.status_code == 201:
            response_data = r.json()
            logger.info(f"✅ Method 1 successful!")
            return {
                "success": True,
                "data": {"id": response_data.get("id")},
                "message": f"FQDN '{fqdn_name}' created successfully (method 1)",
                "response": response_data
            }
        else:
            logger.info(f"❌ Method 1 failed: {r.status_code} - {r.text}")
    except Exception as e:
        logger.info(f"❌ Method 1 exception: {e}")
    
    # Method 2: Try with expanded payload
    expanded_payload = {
        "name": fqdn_name,
        "value": fqdn_value,
        "type": "FQDN",
        "description": description or f"Auto-created FQDN for {fqdn_value}",
        "overridable": False,
        "dnsResolution": "IPV4_AND_IPV6"
    }
    
    logger.info(f"🔄 Trying alternative method 2 (expanded payload)...")
    try:
        r = requests.post(url, headers=headers, json=expanded_payload, verify=SSL_VERIFY, timeout=REQUEST_TIMEOUT)
        logger.info(f"   Method 2 response: {r.status_code}")
        if r.status_code == 201:
            response_data = r.json()
            logger.info(f"✅ Method 2 successful!")
            return {
                "success": True,
                "data": {"id": response_data.get("id")},
                "message": f"FQDN '{fqdn_name}' created successfully (method 2)",
                "response": response_data
            }
        else:
            logger.info(f"❌ Method 2 failed: {r.status_code} - {r.text}")
    except Exception as e:
        logger.info(f"❌ Method 2 exception: {e}")
    
    # Method 3: Try without dnsResolution
    basic_payload = {
        "name": fqdn_name,
        "value": fqdn_value,
        "type": "FQDN",
        "overridable": False
    }
    
    logger.info(f"🔄 Trying alternative method 3 (basic payload)...")
    try:
        r = requests.post(url, headers=headers, json=basic_payload, verify=SSL_VERIFY, timeout=REQUEST_TIMEOUT)
        logger.info(f"   Method 3 response: {r.status_code}")
        if r.status_code == 201:
            response_data = r.json()
            logger.info(f"✅ Method 3 successful!")
            return {
                "success": True,
                "data": {"id": response_data.get("id")},
                "message": f"FQDN '{fqdn_name}' created successfully (method 3)",
                "response": response_data
            }
        else:
            logger.info(f"❌ Method 3 failed: {r.status_code} - {r.text}")
    except Exception as e:
        logger.info(f"❌ Method 3 exception: {e}")
    
    return {
        "success": False,
        "message": f"All alternative methods failed to create FQDN '{fqdn_name}'",
        "error": "All methods failed"
    }


def check_pending_deployments(fmc_url, token):
    """Check for pending deployments on FMC devices
    
    Note: The /deployment/deployabledevices endpoint only returns devices
    that HAVE pending deployments. If a device appears in this list,
    it means there are pending changes that can be deployed.
    """
    url = f"{fmc_url}/api/fmc_config/v1/domain/{DOMAIN_UUID}/deployment/deployabledevices"
    headers = {"X-auth-access-token": token}
    
    try:
        r = requests.get(f"{url}?expanded=true", headers=headers, verify=SSL_VERIFY, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            deployable_devices = r.json()
            pending_devices = []
            
            # Any device in this list has pending deployments
            for item in deployable_devices.get("items", []):
                device_name = item.get("name", "Unknown Device")
                device_version = item.get("version", "Unknown")
                device_type = item.get("type", "DeployableDevice")
                device_info = item.get("device", {})
                device_id = device_info.get("id", "")
                
                pending_info = {
                    "name": device_name,
                    "version": device_version,
                    "device_id": device_id,
                    "pending": True,
                    "details": {
                        "type": device_type,
                        "version": device_version
                    }
                }
                
                pending_devices.append(pending_info)
            
            logger.info(f"Found {len(pending_devices)} device(s) with pending deployments on {fmc_url}")
            
            return {
                "success": True,
                "pending_devices": pending_devices,
                "total_devices": len(pending_devices),
                "pending_count": len(pending_devices)
            }
        else:
            logger.warning(f"Failed to get deployment status from {fmc_url}: {r.status_code}")
            return {
                "success": False,
                "error": f"Failed to get deployment status: {r.status_code}",
                "pending_devices": [],
                "total_devices": 0,
                "pending_count": 0
            }
    except Exception as e:
        logger.error(f"Error checking deployments on {fmc_url}: {str(e)}")
        return {
            "success": False,
            "error": f"Error checking deployments: {str(e)}",
            "pending_devices": [],
            "total_devices": 0,
            "pending_count": 0
        }


def get_config_changes(fmc_url, token, limit=15):
    """Get recent configuration changes that are pending deployment"""
    try:
        url = f"{fmc_url}/api/fmc_platform/v1/domain/{DOMAIN_UUID}/audit/configchanges"
        headers = {"X-auth-access-token": token}
        
        response = requests.get(
            f"{url}?limit={limit}&expanded=true",
            headers=headers,
            verify=SSL_VERIFY,
            timeout=30
        )

        if response.status_code == 200:
            data = response.json()
            changes = []
            
            for item in data.get("items", []):
                # Parse the change data
                change_info = {
                    "time": item.get("time"),
                    "user": item.get("user", {}).get("name", "System"),
                    "action": item.get("action", "Unknown"),
                    "object_name": item.get("objectName", "N/A"),
                    "object_type": item.get("objectType", "N/A"),
                    "change_type": item.get("changeType", "Modified"),
                    "description": item.get("description", "")
                }
                changes.append(change_info)
            
            logger.info(f"Retrieved {len(changes)} config changes from {fmc_url}")
            return changes
        else:
            logger.warning(f"Failed to get config changes from {fmc_url}: {response.status_code}")
            return []
    except Exception as e:
        logger.error(f"Error getting config changes from {fmc_url}: {str(e)}")
        return []


def get_pending_changes(fmc_url, token, device_id):
    """Get pending changes for a specific device"""
    url = f"{fmc_url}/api/fmc_config/v1/domain/{DOMAIN_UUID}/deployment/deployabledevices/{device_id}/pendingchanges"
    headers = {"X-auth-access-token": token}
    
    try:
        r = requests.get(f"{url}?offset=0&limit=25", headers=headers, verify=SSL_VERIFY, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            pending_changes = []
            
            for item in data.get("items", []):
                change = {
                    "entityType": item.get("entityType", "Unknown"),
                    "entityName": item.get("entityName", "N/A"),
                    "entityUUID": item.get("entityUUID", ""),
                    "action": item.get("action", "UPDATE"),
                    "message": item.get("message", ""),
                    "lastUpdatedByUsers": item.get("lastUpdatedByUsers", []),
                    "parentUUID": item.get("parentUUID", "")
                }
                pending_changes.append(change)
            
            logger.info(f"Retrieved {len(pending_changes)} pending changes for device {device_id}")
            return {
                "success": True,
                "changes": pending_changes
            }
        else:
            logger.warning(f"Failed to get pending changes from {fmc_url}: {r.status_code}")
            return {
                "success": False,
                "error": f"Failed to get pending changes: {r.status_code}",
                "changes": []
            }
    except Exception as e:
        logger.error(f"Error getting pending changes from {fmc_url}: {str(e)}")
        return {
            "success": False,
            "error": f"Error getting pending changes: {str(e)}",
            "changes": []
        }


def get_deployment_history(fmc_url, token, limit=10):
    """Get recent deployment history"""
    url = f"{fmc_url}/api/fmc_config/v1/domain/{DOMAIN_UUID}/deployment/deploymentrequests"
    headers = {"X-auth-access-token": token}
    
    try:
        r = requests.get(f"{url}?limit={limit}", headers=headers, verify=SSL_VERIFY, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            deployments = r.json()
            return {
                "success": True,
                "deployments": deployments.get("items", [])
            }
        else:
            return {
                "success": False,
                "error": f"Failed to get deployment history: {r.status_code}",
                "deployments": []
            }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error getting deployment history: {str(e)}",
            "deployments": []
        }


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception_type((requests.exceptions.ConnectionError, requests.exceptions.Timeout)),
    reraise=True
)
def deploy_changes(fmc_url, token):
    """Deploy pending changes to devices

    Gets list of deployable devices with expanded info to get device IDs directly.
    """
    # Get deployable devices with expanded=true to get device.id field
    deployable_url = f"{fmc_url}/api/fmc_config/v1/domain/{DOMAIN_UUID}/deployment/deployabledevices?expanded=true"
    headers = {"X-auth-access-token": token}

    try:
        r = requests.get(deployable_url, headers=headers, verify=SSL_VERIFY, timeout=30)
        if r.status_code != 200:
            logger.error(f"❌ Failed to get deployable devices from {fmc_url}: {r.status_code}")
            return False
        
        deployable_devices = r.json()
        deployable_items = deployable_devices.get("items", [])
        
        if not deployable_items:
            logger.info(f"ℹ️  No deployable devices found on {fmc_url}")
            return False
        
        logger.info(f"📋 Found {len(deployable_items)} deployable device(s)")
        
        # Extract device UUIDs and version from deployabledevices response
        # The device.id field contains the UUID we need for deployment
        device_uuids = []
        version = None
        
        for item in deployable_items:
            device_name = item.get("name")
            device_info = item.get("device", {})
            device_id = device_info.get("id")
            
            if not version:
                version = item.get("version")
            
            if device_id:
                device_uuids.append(device_id)
                logger.info(f"  ✅ Found device '{device_name}' with UUID: {device_id}")
            else:
                logger.warning(f"  ⚠️  No device ID found for '{device_name}'")
        
        if not device_uuids:
            logger.error(f"❌ No device UUIDs found for deployment")
            return False
        
        if not version:
            logger.warning(f"⚠️  No version found, using empty version")
            version = ""
        
        logger.info(f"📤 Deploying to {len(device_uuids)} device(s) with version {version}")
        
        # Initiate deployment
        deploy_url = f"{fmc_url}/api/fmc_config/v1/domain/{DOMAIN_UUID}/deployment/deploymentrequests"
        deploy_headers = {"Content-Type": "application/json", "X-auth-access-token": token}
        
        payload = {
            "type": "DeploymentRequest",
            "version": version,
            "forceDeploy": True,
            "ignoreWarning": True,
            "deviceList": device_uuids
        }
        
        logger.info(f"📦 Deployment payload: {payload}")
        
        deploy_r = requests.post(deploy_url, headers=deploy_headers, json=payload, verify=SSL_VERIFY, timeout=LONG_REQUEST_TIMEOUT)
        
        if deploy_r.status_code in [200, 202]:
            logger.info(f"🚀 Deployment started successfully on {fmc_url}")
            return True
        else:
            logger.error(f"❌ Deployment failed on {fmc_url}: {deploy_r.status_code} {deploy_r.text}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Error deploying to {fmc_url}: {str(e)}")
        return False


def get_all_network_groups(fmc_url, token):
    """Get all network groups from FMC with pagination support"""
    all_groups = []
    offset = 0
    limit = 100  # FMC default limit is usually 25, increase to 100
    
    logger.info(f"🔍 Fetching network groups from {fmc_url}...")
    
    try:
        while True:
            url = f"{fmc_url}/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/networkgroups"
            headers = {"X-auth-access-token": token}
            params = {
                "offset": offset,
                "limit": limit,
                "expanded": "true"  # Get full object details
            }
            
            r = requests.get(url, headers=headers, params=params, verify=SSL_VERIFY, timeout=REQUEST_TIMEOUT)
            
            if r.status_code == 200:
                response_data = r.json()
                groups = response_data.get("items", [])
                all_groups.extend(groups)
                
                # Check if we have more pages
                paging = response_data.get("paging", {})
                total_count = paging.get("count", len(groups))
                current_count = len(all_groups)
                
                logger.info(f"📄 Retrieved {len(groups)} groups (page offset {offset}), total so far: {current_count}")
                
                # If we got fewer items than the limit, or we have all items, we're done
                if len(groups) < limit or current_count >= total_count:
                    break
                
                offset += limit
                
            else:
                error_msg = f"HTTP {r.status_code}"
                try:
                    error_data = r.json()
                    if "error" in error_data and "messages" in error_data["error"]:
                        error_msg += f": {error_data['error']['messages'][0].get('description', 'Unknown error')}"
                    else:
                        error_msg += f": {r.text}"
                except:
                    error_msg += f": {r.text}"
                logger.info(f"❌ Failed to get network groups from {fmc_url}: {error_msg}")
                return {"success": False, "message": error_msg}
        
        logger.info(f"✅ Successfully retrieved {len(all_groups)} total network groups from {fmc_url}")
        return {"success": True, "data": all_groups}
        
    except Exception as e:
        error_msg = f"Exception: {str(e)}"
        logger.info(f"❌ Error getting network groups from {fmc_url}: {error_msg}")
        return {"success": False, "message": error_msg}


def get_all_fqdns(fmc_url, token):
    """Get all FQDN objects from FMC"""
    url = f"{fmc_url}/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/fqdns"
    headers = {"X-auth-access-token": token}
    
    try:
        r = requests.get(url, headers=headers, verify=SSL_VERIFY, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            fqdns = r.json().get("items", [])
            return {"success": True, "data": fqdns}
        else:
            return {"success": False, "message": f"HTTP {r.status_code}: {r.text}"}
    except Exception as e:
        return {"success": False, "message": str(e)}


def remove_object_from_group(fmc_url, token, group_id, object_id, object_type="FQDN"):
    """Remove a specific object from a network group while preserving others"""
    # Validate UUIDs to prevent injection attacks
    if not validate_uuid(group_id):
        logger.error(f"Invalid group_id format: {group_id}")
        return {"success": False, "message": "Invalid group ID format"}
    if not validate_uuid(object_id):
        logger.error(f"Invalid object_id format: {object_id}")
        return {"success": False, "message": "Invalid object ID format"}
    
    # Get current group details
    group_details = get_network_group_details(fmc_url, token, group_id)
    
    if not group_details["success"]:
        return group_details
    
    current_group = group_details["data"]
    existing_objects = current_group.get("objects", [])
    existing_literals = current_group.get("literals", [])
    
    # Filter out the object to remove
    updated_objects = [
        obj for obj in existing_objects 
        if not (obj.get("id") == object_id and obj.get("type") == object_type)
    ]
    
    # Check if object was actually in the group
    removed_count = len(existing_objects) - len(updated_objects)
    if removed_count == 0:
        return {"success": True, "message": "Object was not in the group"}
    
    url = f"{fmc_url}/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/networkgroups/{group_id}"
    headers = {"Content-Type": "application/json", "X-auth-access-token": token}
    payload = {
        "id": group_id,
        "name": current_group.get("name"),
        "type": "NetworkGroup",
        "objects": updated_objects,
        "literals": existing_literals
    }
    
    try:
        r = requests.put(url, headers=headers, json=payload, verify=SSL_VERIFY, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            logger.info(f"✅ Object removed from '{current_group.get('name')}' on {fmc_url}")
            return {"success": True, "message": f"Object removed successfully. {len(updated_objects)} objects remain."}
        else:
            return {"success": False, "message": f"HTTP {r.status_code}: {r.text}"}
    except Exception as e:
        return {"success": False, "message": str(e)}


def delete_fqdn_object(fmc_url, token, fqdn_id):
    """Delete an FQDN object completely from FMC"""
    # Validate UUID to prevent injection attacks
    if not validate_uuid(fqdn_id):
        logger.error(f"Invalid fqdn_id format: {fqdn_id}")
        return {"success": False, "message": "Invalid FQDN ID format"}
    
    url = f"{fmc_url}/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/fqdns/{fqdn_id}"
    headers = {"X-auth-access-token": token}
    
    try:
        r = requests.delete(url, headers=headers, verify=SSL_VERIFY, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            logger.info(f"✅ FQDN object deleted from {fmc_url}")
            return {"success": True, "message": "FQDN object deleted successfully"}
        else:
            return {"success": False, "message": f"HTTP {r.status_code}: {r.text}"}
    except Exception as e:
        return {"success": False, "message": str(e)}


def add_object_to_group(fmc_url, token, group_id, object_id, object_type="FQDN"):
    """Add any type of object to a network group while preserving existing objects"""
    # Validate UUIDs to prevent injection attacks
    if not validate_uuid(group_id):
        logger.error(f"Invalid group_id format: {group_id}")
        return {"success": False, "message": "Invalid group ID format"}
    if not validate_uuid(object_id):
        logger.error(f"Invalid object_id format: {object_id}")
        return {"success": False, "message": "Invalid object ID format"}
    
    return update_network_group(fmc_url, token, group_id, object_id)


def search_objects(fmc_url, token, search_term, object_types=None, limit=100):
    """
    Search for objects in FMC using the search/object API endpoint
    
    Args:
        fmc_url: FMC base URL
        token: Authentication token
        search_term: Text to search for
        object_types: List of object types to filter by (e.g., ['Networks', 'FQDN', 'Ports'])
        limit: Maximum number of results to return
    
    Returns:
        dict: Search results with success status and items
    """
    try:
        # Construct the filter parameter
        if object_types:
            # Format: "text:searchText;types:Networks,FQDN,Ports;isAcpGlobalSearch:true;"
            types_str = ",".join(object_types)
            filter_param = f"text:{search_term};types:{types_str};isAcpGlobalSearch:true;"
        else:
            # Simple text search
            filter_param = search_term
        
        url = f"{fmc_url}/api/fmc_config/v1/domain/{DOMAIN_UUID}/search/object"
        headers = {"X-auth-access-token": token}
        params = {
            "filter": filter_param,
            "limit": limit,
            "expanded": "true"
        }
        
        logger.info(f"🔍 Searching for objects matching '{search_term}' on {fmc_url}...")
        r = requests.get(url, headers=headers, params=params, verify=SSL_VERIFY)
        
        if r.status_code == 200:
            data = r.json()
            items = data.get("items", [])
            logger.info(f"✅ Found {len(items)} objects matching '{search_term}'")
            
            return {
                "success": True,
                "items": items,
                "total": len(items),
                "search_term": search_term
            }
        else:
            error_msg = f"Failed to search objects: HTTP {r.status_code}"
            if r.content:
                try:
                    error_data = r.json()
                    error_msg += f" - {error_data.get('error', {}).get('messages', [{}])[0].get('description', 'Unknown error')}"
                except:
                    pass
            logger.info(f"❌ {error_msg}")
            return {
                "success": False,
                "message": error_msg,
                "items": [],
                "total": 0
            }
            
    except Exception as e:
        error_msg = f"Error searching objects: {str(e)}"
        logger.info(f"❌ {error_msg}")
        return {
            "success": False,
            "message": error_msg,
            "items": [],
            "total": 0
        }


def search_global(fmc_url, token, search_term, limit=100):
    """
    Search for objects and policies globally in FMC using the search/global API endpoint
    
    Args:
        fmc_url: FMC base URL
        token: Authentication token
        search_term: Text to search for
        limit: Maximum number of results to return
    
    Returns:
        dict: Search results with success status and items
    """
    try:
        url = f"{fmc_url}/api/fmc_config/v1/domain/{DOMAIN_UUID}/search/global"
        headers = {"X-auth-access-token": token}
        params = {
            "filter": search_term,
            "limit": limit,
            "expanded": "true"
        }
        
        logger.info(f"🔍 Performing global search for '{search_term}' on {fmc_url}...")
        r = requests.get(url, headers=headers, params=params, verify=SSL_VERIFY)
        
        if r.status_code == 200:
            data = r.json()
            items = data.get("items", [])
            logger.info(f"✅ Found {len(items)} items matching '{search_term}' globally")
            
            return {
                "success": True,
                "items": items,
                "total": len(items),
                "search_term": search_term
            }
        else:
            error_msg = f"Failed to perform global search: HTTP {r.status_code}"
            if r.content:
                try:
                    error_data = r.json()
                    error_msg += f" - {error_data.get('error', {}).get('messages', [{}])[0].get('description', 'Unknown error')}"
                except:
                    pass
            logger.info(f"❌ {error_msg}")
            return {
                "success": False,
                "message": error_msg,
                "items": [],
                "total": 0
            }
            
    except Exception as e:
        error_msg = f"Error performing global search: {str(e)}"
        logger.info(f"❌ {error_msg}")
        return {
            "success": False,
            "message": error_msg,
            "items": [],
            "total": 0
        }


# ====== MAIN FLOW ======
if __name__ == "__main__":
    print("=== Cisco FMC FQDN Push Utility ===")
    fqdn_value = input("Enter FQDN to add: ").strip()
    fqdn_name = fqdn_value.replace(".", "_")

    # Load FMC list for CLI execution
    fmc_list = load_fmc_config()
    
    for fmc in fmc_list:
        logger.info(f"\n--- Processing {fmc['name']} ({fmc['url']}) ---")
        token = fmc_auth(fmc["url"], fmc["username"], fmc["password"])
        if not token:
            continue

        # Check user permissions and domain access
        check_user_permissions(fmc["url"], token)

        fqdn_id = create_fqdn(fmc["url"], token, fqdn_name, fqdn_value)
        if not fqdn_id:
            logger.info(f"🔄 Trying alternative methods for {fmc['name']}...")
            fqdn_id = create_fqdn_alternative(fmc["url"], token, fqdn_name, fqdn_value)
            if not fqdn_id:
                continue

        # Note: Main flow now handled by web interface
        # CLI functionality moved to web-based object management
        logger.info(f"⚠️  CLI functionality deprecated. Use web interface for object management.")
    print("\n✅ All FMCs processed.")