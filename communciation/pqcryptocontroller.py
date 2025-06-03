import traci
import os
import hashlib
import math
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from kyber_py.kyber import Kyber512  # Changed import
from dilithium import Dilithium2     # Changed import
import base64

# Start SUMO GUI
sumoCmd = ["sumo-gui", "-c", "simple.sumocfg"]
traci.start(sumoCmd)

COMM_COLOR = (0, 255, 0, 255)    # Green for communication
DEFAULT_COLOR = (255, 0, 0, 255)  # Red for default
BROADCAST_RADIUS = 50  # meters

# ------------------------
# Helper Functions (unchanged)
# ------------------------
def calculate_distance(veh1_id, veh2_id):
    pos1 = traci.vehicle.getPosition(veh1_id)
    pos2 = traci.vehicle.getPosition(veh2_id)
    return math.sqrt((pos1[0] - pos2[0])**2 + (pos1[1] - pos2[1])**2)

def get_vehicles_in_radius(sender_id, radius):
    nearby_vehicles = []
    for veh_id in traci.vehicle.getIDList():
        if veh_id != sender_id:
            distance = calculate_distance(sender_id, veh_id)
            if distance <= radius:
                nearby_vehicles.append(veh_id)
    return nearby_vehicles

def get_stopped_vehicles_near_tls(tls_id):
    lane_ids = traci.trafficlight.getControlledLanes(tls_id)
    stopped_vehicles = []
    for lane in lane_ids:
        veh_ids = traci.lane.getLastStepVehicleIDs(lane)
        for vid in veh_ids:
            speed = traci.vehicle.getSpeed(vid)
            if speed < 0.1:
                stopped_vehicles.append(vid)
    return stopped_vehicles

# ------------------------
# Updated Post-Quantum Crypto Implementation
# ------------------------
vehicle_keys = {}

def initialize_vehicle_keys(vehicle_id):
    if vehicle_id not in vehicle_keys:
        # Generate Kyber key pair using kyber-py
        kyber_pk, kyber_sk = Kyber512.keygen()
        
        # Generate Dilithium key pair using dilithium
        dilithium_pk, dilithium_sk = Dilithium2.keygen()
        
        vehicle_keys[vehicle_id] = {
            'kyber_pk': kyber_pk,
            'kyber_sk': kyber_sk,
            'dilithium_pk': dilithium_pk,
            'dilithium_sk': dilithium_sk
        }

def pq_key_exchange(sender_id, receiver_id):
    """Perform Kyber key exchange using kyber-py"""
    receiver_pk = vehicle_keys[receiver_id]['kyber_pk']
    shared_secret, ciphertext = Kyber512.encaps(receiver_pk)  # Changed order
    return ciphertext, shared_secret

def pq_decrypt_shared_secret(receiver_id, ciphertext):
    """Decrypt shared secret using Kyber"""
    receiver_sk = vehicle_keys[receiver_id]['kyber_sk']
    return Kyber512.decaps(receiver_sk, ciphertext)

def pq_sign_message(sender_id, message):
    """Sign message with Dilithium"""
    sender_sk = vehicle_keys[sender_id]['dilithium_sk']
    return Dilithium2.sign(sender_sk, message.encode())  # Changed signature

def pq_verify_signature(receiver_id, message, signature, sender_id):
    """Verify signature with Dilithium"""
    sender_pk = vehicle_keys[sender_id]['dilithium_pk']
    try:
        return Dilithium2.verify(sender_pk, message.encode(), signature)  # Changed order
    except:
        return False

# ------------------------
# Updated Secure Message Functions
# ------------------------
def send_secure_message(sender, receiver, message):
    """Send message using post-quantum crypto"""
    initialize_vehicle_keys(sender)
    initialize_vehicle_keys(receiver)
    
    # 1. Perform Kyber key exchange
    ciphertext, shared_secret = pq_key_exchange(sender, receiver)
    
    # 2. Sign message with Dilithium
    signature = pq_sign_message(sender, message)
    
    # 3. Encrypt with AES (using Kyber-derived key)
    key = hashlib.sha256(shared_secret).digest()[:32]  # AES-256 key
    cipher = AES.new(key, AES.MODE_GCM)
    aes_ct, tag = cipher.encrypt_and_digest(pad(message.encode(), AES.block_size))
    
    return {
        'kyber_ct': base64.b64encode(ciphertext).decode(),
        'aes_nonce': base64.b64encode(cipher.nonce).decode(),
        'aes_tag': base64.b64encode(tag).decode(),
        'signature': base64.b64encode(signature).decode()
    }

def receive_secure_message(receiver, sender, encrypted_data):
    """Receive and verify message"""
    try:
        initialize_vehicle_keys(receiver)
        initialize_vehicle_keys(sender)
        
        # 1. Decrypt shared secret
        ciphertext = base64.b64decode(encrypted_data['kyber_ct'])
        shared_secret = pq_decrypt_shared_secret(receiver, ciphertext)
        
        # 2. Decrypt message
        key = hashlib.sha256(shared_secret).digest()[:32]
        cipher = AES.new(
            key, 
            AES.MODE_GCM,
            nonce=base64.b64decode(encrypted_data['aes_nonce'])
        )
        plaintext = unpad(
            cipher.decrypt_and_verify(
                base64.b64decode(encrypted_data['aes_ct']),
                base64.b64decode(encrypted_data['aes_tag'])
            ),
            AES.block_size
        ).decode()
        
        # 3. Verify signature
        signature = base64.b64decode(encrypted_data['signature'])
        if not pq_verify_signature(receiver, plaintext, signature, sender):
            print(f"⚠️ Signature verification failed for message from {sender}")
            return None
        
        return plaintext
    except Exception as e:
        print(f"❌ Error processing message: {e}")
        return None

# ------------------------
# Main Simulation Loop (unchanged)
# ------------------------
step = 0
already_communicated = set()

while traci.simulation.getMinExpectedNumber() > 0:
    traci.simulationStep()
    
    # Reset all vehicle colors
    for veh_id in traci.vehicle.getIDList():
        traci.vehicle.setColor(veh_id, DEFAULT_COLOR)

    tls_state = traci.trafficlight.getRedYellowGreenState("n1")

    if 'r' in tls_state:  # If red light present
        stopped_vehicles = get_stopped_vehicles_near_tls("n1")
        if len(stopped_vehicles) >= 2:
            v1, v2 = stopped_vehicles[:2]
            pair = tuple(sorted((v1, v2)))
            if pair not in already_communicated:
                plain_message = "RED LIGHT ALERT"
                encrypted_data = send_secure_message(v2, v1, plain_message)
                decrypted_msg = receive_secure_message(v1, v2, encrypted_data)
                
                if decrypted_msg:
                    print(f"\n[Step {step}] 🛡️ Post-Quantum Secure Communication:")
                    print(f"  📤 Sender: {v2}")
                    print(f"  📥 Receiver: {v1}")
                    print(f"  🔐 Kyber: Key exchange completed")
                    print(f"  🔏 Dilithium: Signature verified")
                    print(f"  📖 Decrypted: '{decrypted_msg}'")
                    
                    # Broadcast to nearby vehicles
                    nearby_vehicles = get_vehicles_in_radius(v2, BROADCAST_RADIUS)
                    if nearby_vehicles:
                        print(f"\n  📢 Broadcasting to {len(nearby_vehicles)} nearby vehicles:")
                        for nearby_veh in nearby_vehicles:
                            distance = calculate_distance(v2, nearby_veh)
                            print(f"    - Vehicle {nearby_veh} (distance: {distance:.2f}m)")
                            broadcast_data = send_secure_message(v2, nearby_veh, plain_message)
                            decrypted_broadcast = receive_secure_message(nearby_veh, v2, broadcast_data)
                            if decrypted_broadcast:
                                print(f"      ✓ Message received and verified by {nearby_veh}")
                                traci.vehicle.setColor(nearby_veh, COMM_COLOR)
                    
                    already_communicated.add(pair)

                traci.vehicle.setColor(v1, COMM_COLOR)
                traci.vehicle.setColor(v2, COMM_COLOR)

    step += 1

traci.close()
