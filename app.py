# main_app.py

import httpx
import time
import re
import json
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask import Flask, request, jsonify
from datetime import datetime
import jwt as pyjwt

# --- Protobuf Imports (নিশ্চিত করুন এই ফাইলগুলো আপনার প্রোজেক্টে আছে) ---
# এই ফাইলগুলো আপনার কাছে না থাকলে কোডটি কাজ করবে না।
try:
    import data_pb2
    import encode_id_clan_pb2
    import reqClan_pb2
except ImportError:
    print("Error: Protobuf files (data_pb2.py, etc.) not found. Please generate them first.")
    exit(1)

# --- Configuration (কনফিগারেশন) ---
# এই মানগুলো সহজেই পরিবর্তন করা যাবে
FREEFIRE_VERSION = "OB53"
JWT_REGEX = re.compile(r'(eyJ[A-Za-z0-9_\-\.=]+)')

# --- Security: Load secrets from environment variables (নিরাপত্তা: এনভায়রনমেন্ট ভ্যারিয়েবল থেকে গোপন তথ্য লোড করুন) ---
# সরাসরি কোডে key/iv না লিখে এনভায়রনমেন্ট ভ্যারিয়েবল ব্যবহার করা নিরাপদ
# উদাহরণ: export AES_KEY="89,103,38,..."
try:
    AES_KEY_STR = os.environ.get("AES_KEY", "89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56")
    AES_IV_STR = os.environ.get("AES_IV", "54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37")
    
    AES_KEY = bytes([int(k) for k in AES_KEY_STR.split(',')])
    AES_IV = bytes([int(i) for i in AES_IV_STR.split(',')])
except (ValueError, TypeError) as e:
    print(f"Error: Invalid format for AES_KEY or AES_IV in environment variables. Error: {e}")
    exit(1)


app = Flask(__name__)

# --- Helper Functions (সহায়ক ফাংশন) ---

def get_jwt_token_from_api(uid, password):
    data_param = f"{uid}:{password}"
    url = f"https://api.freefireservice.dnc.su/oauth/account:login?data={data_param}"
    try:
        with httpx.Client(timeout=15.0) as client:
            response = client.get(url)
            response.raise_for_status() # HTTP 4xx/5xx এররের জন্য exception তুলবে

        # JWT খোঁজার জন্য একাধিক পদ্ধতি
        try:
            data = response.json()
            for key in ("token", "jwt", "access_token", "data", "auth"):
                token = data.get(key)
                if isinstance(token, str) and token.startswith("ey"):
                    return token
        except json.JSONDecodeError:
            pass # যদি রেসপন্স JSON না হয়, তাহলে টেক্সট থেকে খোঁজা হবে

        match = JWT_REGEX.search(response.text)
        if match:
            return match.group(1)

        for header_value in response.headers.values():
            match = JWT_REGEX.search(header_value)
            if match:
                return match.group(1)
        
        return None
    except httpx.RequestError as e:
        print(f"JWT Token API request error: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred while getting JWT token: {e}")
        return None

def get_region_from_jwt(jwt_token):
    try:
        decoded = pyjwt.decode(jwt_token, options={"verify_signature": False})
        return decoded.get('lock_region', 'BD').upper()
    except pyjwt.PyJWTError as e:
        print(f"JWT decode error: {e}")
        return 'BD' # ডিফল্ট একটি মান দেওয়া হলো

def get_region_url(region):
    region_map = {
        "BD": "https://clientbp.ggwhitehawk.com",
        "BR": "https://client.us.freefiremobile.com/",
        "US": "https://client.us.freefiremobile.com/",
        "SAC": "https://client.us.freefiremobile.com/",
        "NA": "https://client.us.freefiremobile.com/",
    }
    return region_map.get(region.upper(), "https://clientbp.ggblueshark.com/")

def create_encrypted_payload(data_to_serialize):
    serialized_data = data_to_serialize.SerializeToString()
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    encrypted_data = cipher.encrypt(pad(serialized_data, AES.block_size))
    return encrypted_data

def get_clan_info(base_url, jwt_token, clan_id):
    try:
        clan_info_req = encode_id_clan_pb2.MyData()
        clan_info_req.field1 = clan_id
        clan_info_req.field2 = 1 # ডিফল্ট মান
        
        encrypted_info_data = create_encrypted_payload(clan_info_req)

        info_url = f"{base_url}/GetClanInfoByClanID"
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "ReleaseVersion": FREEFIRE_VERSION,
            "Content-Type": "application/octet-stream",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
        }

        with httpx.Client(timeout=15.0) as client:
            info_response = client.post(info_url, headers=headers, content=encrypted_info_data)
            info_response.raise_for_status()
        
        resp_info = data_pb2.response()
        resp_info.ParseFromString(info_response.content)
        
        return {
            "clan_name": getattr(resp_info, "special_code", "Unknown"),
            "clan_level": getattr(resp_info, "level", "Unknown")
        }
    except Exception as e:
        print(f"Clan info retrieval error: {e}")
        return {"clan_name": "Unknown", "clan_level": "Unknown"}

# --- API Endpoint ---
@app.route('/join', methods=['POST'])
def join_clan():
    # POST রিকোয়েস্টের বডি থেকে JSON ডেটা গ্রহণ করা হচ্ছে
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON in request body"}), 400

    clan_id_str = data.get('clan_id')
    jwt_token = data.get('jwt')
    uid = data.get('uid')
    password = data.get('password')

    if not clan_id_str:
        return jsonify({"error": "clan_id is required"}), 400
    
    try:
        clan_id = int(clan_id_str)
    except (ValueError, TypeError):
        return jsonify({"error": "clan_id must be a valid integer"}), 400

    if not jwt_token and not (uid and password):
        return jsonify({"error": "Either 'jwt' or both 'uid' and 'password' are required"}), 400

    final_token = jwt_token
    if not final_token:
        print(f"Attempting to get JWT for UID: {uid}")
        final_token = get_jwt_token_from_api(uid, password)
        if not final_token:
            return jsonify({"error": "Failed to get JWT token from uid/password. Check credentials or external API status."}), 401

    final_region = get_region_from_jwt(final_token)
    base_url = get_region_url(final_region)
    url = f"{base_url}/RequestJoinClan"
    
    try:
        # Join request payload তৈরি
        join_req_message = reqClan_pb2.MyMessage()
        join_req_message.field_1 = clan_id
        encrypted_data = create_encrypted_payload(join_req_message)

        headers = {
            "Authorization": f"Bearer {final_token}",
            "ReleaseVersion": FREEFIRE_VERSION,
            "Content-Type": "application/octet-stream",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
        }

        with httpx.Client(timeout=30.0) as client:
            response = client.post(url, headers=headers, content=encrypted_data)
            response.raise_for_status() # ব্যর্থ হলে (4xx/5xx) এরর দেবে

        clan_info = get_clan_info(base_url, final_token, clan_id)

        result = {
            "success": True,
            "message": "Request sent successfully",
            "status_code": response.status_code,
            "clan_id": clan_id,
            "region": final_region,
            "clan_name": clan_info.get("clan_name"),
            "clan_level": clan_info.get("clan_level"),
            "timestamp": datetime.utcnow().isoformat()
        }
        return jsonify(result), 200

    except httpx.HTTPStatusError as e:
        return jsonify({
            "success": False,
            "error": "Request to game server failed",
            "details": f"Status code: {e.response.status_code}. Response: {e.response.text}",
            "clan_id": clan_id
        }), e.response.status_code
    except Exception as e:
        print(f"Server error during clan join request: {e}")
        return jsonify({"error": "An internal server error occurred", "details": str(e)}), 500

if __name__ == '__main__':
    # সার্ভার পোর্ট নির্ধারণ
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting Clan Join API on port {port}...")
    # debug=False প্রোডাকশনের জন্য ভালো
    app.run(host='0.0.0.0', port=port, debug=False)