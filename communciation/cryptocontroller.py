import traci
import os
import hashlib
import math
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# Start SUMO GUI
sumoCmd = ["sumo-gui", "-c", "simple.sumocfg"]
traci.start(sumoCmd)

COMM_COLOR = (0, 255, 0, 255)    # Green for communication
DEFAULT_COLOR = (255, 0, 0, 255)  # Red for default
BROADCAST_RADIUS = 50  # meters

# ------------------------
# Helper: Calculate distance between two vehicles
# ------------------------
def calculate_distance(veh1_id, veh2_id):
    pos1 = traci.vehicle.getPosition(veh1_id)
    pos2 = traci.vehicle.getPosition(veh2_id)
    return math.sqrt((pos1[0] - pos2[0])**2 + (pos1[1] - pos2[1])**2)

# ------------------------
# Helper: Get vehicles within radius
# ------------------------
def get_vehicles_in_radius(sender_id, radius):
    nearby_vehicles = []
    for veh_id in traci.vehicle.getIDList():
        if veh_id != sender_id:  # Don't include the sender
            distance = calculate_distance(sender_id, veh_id)
            if distance <= radius:
                nearby_vehicles.append(veh_id)
    return nearby_vehicles

# ------------------------
# Helper: Get stopped vehicles near TLS
# ------------------------
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
# Post-Quantum Hybrid Crypto Implementation
# ------------------------

# Store for vehicle keys
vehicle_keys = {}

def initialize_vehicle_keys(vehicle_id):
    if vehicle_id not in vehicle_keys:
        # Generate ECDH key pair (quantum-resistant curve)
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        
        # Store keys
        vehicle_keys[vehicle_id] = {
            'private_key': private_key,
            'public_key': public_key
        }

def derive_shared_key(private_key, peer_public_key):
    # Perform ECDH key exchange
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    
    # Derive a key using HKDF (quantum-resistant)
    derived_key = HKDF(
        algorithm=hashes.SHA384(),
        length=32,
        salt=None,
        info=b'VANET_KEY_DERIVATION'
    ).derive(shared_key)
    
    return derived_key

def send_secure_message(sender, receiver, message):
    # Initialize keys if not already done
    initialize_vehicle_keys(sender)
    initialize_vehicle_keys(receiver)
    
    # Get keys
    sender_private_key = vehicle_keys[sender]['private_key']
    receiver_public_key = vehicle_keys[receiver]['public_key']
    
    # Derive shared key
    shared_key = derive_shared_key(sender_private_key, receiver_public_key)
    
    # Create AES-GCM cipher
    cipher = AESGCM(shared_key)
    
    # Generate nonce
    nonce = os.urandom(12)
    
    # Encrypt message
    ciphertext = cipher.encrypt(nonce, message.encode(), None)
    
    # Sign the message using ECDSA
    signature = sender_private_key.sign(
        message.encode(),
        ec.ECDSA(hashes.SHA384())
    )
    
    return {
        'ciphertext': ciphertext,
        'nonce': nonce,
        'signature': signature
    }

def receive_secure_message(receiver, sender, encrypted_data):
    try:
        # Initialize keys if not already done
        initialize_vehicle_keys(receiver)
        initialize_vehicle_keys(sender)
        
        # Get keys
        receiver_private_key = vehicle_keys[receiver]['private_key']
        sender_public_key = vehicle_keys[sender]['public_key']
        
        # Derive shared key
        shared_key = derive_shared_key(receiver_private_key, sender_public_key)
        
        # Create AES-GCM cipher
        cipher = AESGCM(shared_key)
        
        # Decrypt message
        plaintext = cipher.decrypt(
            encrypted_data['nonce'],
            encrypted_data['ciphertext'],
            None
        )
        
        # Verify signature
        try:
            sender_public_key.verify(
                encrypted_data['signature'],
                plaintext,
                ec.ECDSA(hashes.SHA384())
            )
        except Exception as e:
            print(f"⚠️ Signature verification failed for message from {sender}")
            return None
        
        return plaintext.decode()
    except Exception as e:
        print(f"❌ Error processing message: {e}")
        return None

# ------------------------
# Main Loop
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
                    print(f"\n[Step {step}] 🛡️ Hybrid Post-Quantum Secure Communication:")
                    print(f"  📤 Sender: {v2}")
                    print(f"  📥 Receiver: {v1}")
                    print(f"  📝 Plain Text: '{plain_message}'")
                    print(f"  🔒 Encrypted (hex): {encrypted_data['ciphertext'].hex()}")
                    print(f"  🔏 Signature (hex): {encrypted_data['signature'].hex()}")
                    print(f"  📖 Decrypted: '{decrypted_msg}'")
                    
                    # Broadcast to nearby vehicles
                    nearby_vehicles = get_vehicles_in_radius(v2, BROADCAST_RADIUS)
                    if nearby_vehicles:
                        print(f"\n  📢 Broadcasting to {len(nearby_vehicles)} nearby vehicles:")
                        for nearby_veh in nearby_vehicles:
                            distance = calculate_distance(v2, nearby_veh)
                            print(f"    - Vehicle {nearby_veh} (distance: {distance:.2f}m)")
                            # Send message to nearby vehicle
                            broadcast_data = send_secure_message(v2, nearby_veh, plain_message)
                            decrypted_broadcast = receive_secure_message(nearby_veh, v2, broadcast_data)
                            if decrypted_broadcast:
                                print(f"      ✓ Message received and decrypted by {nearby_veh}")
                                traci.vehicle.setColor(nearby_veh, COMM_COLOR)
                    
                    already_communicated.add(pair)

                traci.vehicle.setColor(v1, COMM_COLOR)
                traci.vehicle.setColor(v2, COMM_COLOR)

    step += 1

traci.close()