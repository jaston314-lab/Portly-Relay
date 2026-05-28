import requests
import subprocess
import time
import traceback
import os


def load_local_env_file(base_dir: str):
    env_path = os.path.join(base_dir, ".env")
    if not os.path.exists(env_path):
        return

    try:
        with open(env_path, "r", encoding="utf-8") as env_file:
            for raw_line in env_file:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue

                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")

                if key and key not in os.environ:
                    os.environ[key] = value
    except Exception as e:
        print(f"WARNING: Could not load local env file {env_path}: {e}")

# --- CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_local_env_file(BASE_DIR)

BRAIN_URL = os.getenv("BRAIN_URL", "https://api.portly.uk")
RELAY_HOSTNAME = "portly-relay-01"
RELAY_SERVICE_KEY = os.getenv("RELAY_SERVICE_KEY")
RELAY_PRIVATE_KEY_PATH = os.path.join(BASE_DIR, "relay_privatekey")
WG_INTERFACE = "wg0"
SUDO_PREFIX = "" if hasattr(os, "geteuid") and os.geteuid() == 0 else "sudo "
SYNC_INTERVAL_SECONDS = int(os.getenv("RELAY_SYNC_INTERVAL_SECONDS", "10"))
REQUEST_TIMEOUT_SECONDS = int(os.getenv("RELAY_REQUEST_TIMEOUT_SECONDS", "10"))

def run_command(command):
    try:
        subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        if "-C" not in command: # Don't log "Check" commands
            print(f"Error running: {command} -> {e.stderr}")
        return False

def derive_public_key_from_private_key():
    try:
        with open(RELAY_PRIVATE_KEY_PATH, "r", encoding="utf-8") as private_key_file:
            private_key = private_key_file.read().strip()

        if not private_key:
            return None

        result = subprocess.run(
            ["wg", "pubkey"],
            input=private_key,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip() or None
    except Exception as e:
        print(f"CRITICAL: Could not derive WireGuard Public Key from {RELAY_PRIVATE_KEY_PATH}. Error: {e}")
        return None

def get_my_wireguard_key():
    """Reads the REAL public key from the interface to identify myself."""
    try:
        command = ["wg", "show", WG_INTERFACE, "public-key"]
        if SUDO_PREFIX:
            command.insert(0, "sudo")

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except Exception as e:
        print(f"WARNING: Could not read WireGuard Public Key from wg0. Falling back to {RELAY_PRIVATE_KEY_PATH}. Error: {e}")
        return derive_public_key_from_private_key()

def wireguard_interface_exists():
    try:
        command = ["ip", "link", "show", WG_INTERFACE]
        if SUDO_PREFIX:
            command.insert(0, "sudo")

        subprocess.run(command, capture_output=True, text=True, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def get_current_peers():
    """Returns a set of all Public Keys currently active on the wg0 interface."""
    try:
        # 'wg show wg0 peers' returns a list of public keys, one per line
        output = subprocess.check_output(f"{SUDO_PREFIX}wg show {WG_INTERFACE} peers", shell=True).decode('utf-8').strip()
        if not output:
            return set()
        return set(output.splitlines())
    except Exception:
        return set()

def sync_relay():
    if not RELAY_SERVICE_KEY:
        print("CRITICAL: RELAY_SERVICE_KEY is not set. Skipping relay sync.")
        return

    MY_PUBLIC_KEY = get_my_wireguard_key()
    if not MY_PUBLIC_KEY:
        return

    print(f"Syncing Relay {RELAY_HOSTNAME} (Key: {MY_PUBLIC_KEY[:10]}...)...")
    
    try:
        # 1. Get Inventory (Target State)
        headers = {"x-relay-key": RELAY_SERVICE_KEY}
        r = requests.get(f"{BRAIN_URL}/infra/sync", headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)
        
        if r.status_code != 200:
            print(f"Failed to fetch inventory: {r.status_code} {r.text}")
            return
        
        inventory = r.json()

        if not wireguard_interface_exists():
            print(f"Brain reachable, but {WG_INTERFACE} is not up. Run 'sudo wg-quick up {WG_INTERFACE}' or use the updated Start All task.")
            return
        
        # 2. Flush & Masquerade (Standard Plumbing)
        run_command(f"{SUDO_PREFIX}iptables -t nat -F PREROUTING")
        run_command(f"{SUDO_PREFIX}iptables -t nat -C POSTROUTING -o {WG_INTERFACE} -j MASQUERADE 2>/dev/null || {SUDO_PREFIX}iptables -t nat -A POSTROUTING -o {WG_INTERFACE} -j MASQUERADE")

        # 3. Build "Target" List (Who SHOULD be here)
        valid_peer_keys = set()
        
        for d in inventory:
            mac = d['mac_address']
            
            # Filter: Is it for me? Is it active? Does it have a key?
            if d.get('relay_public_key') != MY_PUBLIC_KEY: continue
            if not d.get('is_active'): continue
            if not d.get('device_public_key'): continue
            
            # Add to valid list
            valid_peer_keys.add(d['device_public_key'])

            # --- CONFIGURE PEER (Add/Update) ---
            print(f"   + Configuring: {mac}")
            
            # WireGuard Peer
            allowed_ips = f"{d['vpn_ip']}/32"
            if d['local_subnet']:
                allowed_ips += f",{d['local_subnet']}"
            
            run_command(f"{SUDO_PREFIX}wg set {WG_INTERFACE} peer {d['device_public_key']} allowed-ips {allowed_ips}")

            try:
                r_det = requests.get(f"{BRAIN_URL}/admin/device/{d['id']}", timeout=REQUEST_TIMEOUT_SECONDS)
                if r_det.status_code == 200:
                    mappings = r_det.json().get("ports", [])
                    for m in mappings:
                        target = m['internal_ip']
                        pub_p = m['public_port']
                        int_p = m['internal_port']
                        allowed = m.get('allowed_ips')

                        run_command(f"{SUDO_PREFIX}ip route replace {target} dev {WG_INTERFACE}")
                        
                        if not allowed or allowed == "null":
                            run_command(f"{SUDO_PREFIX}iptables -t nat -A PREROUTING -p tcp --dport {pub_p} -j DNAT --to-destination {target}:{int_p}")
                        else:
                            for ip in allowed.split(','):
                                if ip.strip():
                                    run_command(f"{SUDO_PREFIX}iptables -t nat -A PREROUTING -s {ip.strip()} -p tcp --dport {pub_p} -j DNAT --to-destination {target}:{int_p}")
            except Exception:
                pass # Fail silently on port mappings if auth is tricky, keep tunnel up.

        # 4. PRUNING PHASE (Remove who SHOULDN'T be here)
        current_peers = get_current_peers()
        zombies = current_peers - valid_peer_keys
        
        if zombies:
            print(f"   x Pruning {len(zombies)} zombie peers...")
            for zombie_key in zombies:
                print(f"     - Removing Peer: {zombie_key[:15]}...")
                run_command(f"{SUDO_PREFIX}wg set {WG_INTERFACE} peer {zombie_key} remove")
        else:
            print("   (No zombies found)")

    except Exception as e:
        print(f"Sync failed: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    while True:
        sync_relay()
        time.sleep(SYNC_INTERVAL_SECONDS)