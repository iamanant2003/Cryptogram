import os
import hashlib
from flask import Flask, render_template, request, send_file, jsonify, make_response
from cryptography.fernet import Fernet
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import time
from threading import Thread
import dropbox
from dropbox.exceptions import AuthError, ApiError
import zipfile
import io
from datetime import datetime

app = Flask(__name__)


ENCRYPTED_DIR = "encrypted_files"
DECRYPTED_DIR = "decrypted_files"
HASH_DIR = "hashes"
TEMP_DIR = "temp_files"
DROPBOX_ACCESS_TOKEN = 'sl.u.AF_HvHDXsF-CsB9qTvshGj2guI120mrrWnqdBqcBKdfK9s-EuKDKHuRu9sUGRTgLg2e0AYN7v8M7dclXGNs5dub-fEUp_kJ8H7W49ZrV6WpLbydRvLFqagh_OTJ2lUZYkBJl6JX8J4Kwgw8hJk66U9EjhbqHywpPsDB1nKWazaPVghRYQCFrUhYSrfvQ0rTL-PvJrTOgpSgeeHuPzQVcT8hxHLi9dXWTPnhllTQhY5KaOOZwlUh0BmgK29M5XTNk4KFz3fiLfqqAwGI2u4KGiC3Xhwn8qPcfFVBp1HF7hQ3MvXRNzd9djnfABqr8p652SQ6K0GIEIqsGlcJGkpkfNWTjV4O-hf0_pwkVEzEFF2js6snNT9dtPJfqkCc9U7wfL7G6xYIpM5Krzu4J9eLZxYB771cmXNBlZA8WXdKUovJGqQrq4tN8gPeM7ms99-kDiMyPW9jljrLlyzzd2nKvez1My6vo42BpExawd4fkrOl3UogX-GmaRyg32enl1LTwHETsNIQqiuLWHyNopJrf9fEfsbWF2ls1V_MhX4tu9a1PUqcBfb3Mtmto7q84-LYq9OHgmAVqL8pVvEC-ppSOBvd4hbiIBnfuTnd7elGlqR5g44o9xi6U8uZwPWm_lpkLc8CeF_a4_qsp6Q1GSIgJn2XhU1zM3BSu54e784vTtjEuc1lj5dW0GWqkg7CeiDpGG4AONOYCXCP0nvRYZJzrDfbokL_WFgor9wvuTLHKoSnGviKj3FFfaNQ17ZWi5q7s0R3xKD9ptafnXr31YHm73WVYUqtScpowDFwYU2GJjY5sj_WQxVdlm8B_ttMzW6tUV04QECJioYh9E3roRUSKuZwx1bKJEI8ZvapDxignpQHwyNZyhyTuzQGVqxcE2THUwhFOv4tozMEI6v5xV-NtQBPGkkAnsEGgi-CyeoO-CmqjA9fdYDGKdsQox295sIGrGp4qOxpwR79M0lJnr6j8MUs-b3uH_LhFut1X2Hto9_35O0CjSW8LNliDlEWeF6e0EkC3fDzATnzK3_pnVDrJ-p5YxCEA2m_AYWTCJE8Crud77OnaZICLp6CPRwIIP7Me_KMLPTyorIzCehfv4CCQIVA6Ndh2KpcXDWwp-ji-KHzp3JyTH0QsiAFxFbLOIU_W-aoKtLKacWrwdbZ2sFKF8zx7rclb-HOIix6cq3JipsntNExhBq_L4iRZe-3MKcDdFD1lQyDgV6uF9rpn2UCmunxn7QOdfQpvGZGgYVk64gThUfG9jsRza3jMNOBeqUS-wP7JngJbLNB9V_kjSTb9UsbD'
DROPBOX_KEY_FOLDER = '/cryptogram_keys'
DROPBOX_STORAGE_FOLDER = '/cryptogram_storage'
FILE_EXPIRATION_MINUTES = 5

os.makedirs(ENCRYPTED_DIR, exist_ok=True)
os.makedirs(DECRYPTED_DIR, exist_ok=True)
os.makedirs(HASH_DIR, exist_ok=True)
os.makedirs(TEMP_DIR, exist_ok=True)

def generate_salt():
    return os.urandom(16)

def derive_key(password: str, salt: bytes, key_length: int = 32):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def hash_data(data, algorithm):
    if algorithm == "SHA-256":
        return hashlib.sha256(data).hexdigest()
    elif algorithm == "SHA-512":
        return hashlib.sha512(data).hexdigest()
    return None

def encrypt_data(data, password: str, algorithm):
    salt = generate_salt()
    
    if algorithm == "AES":
        key = derive_key(password, salt, 16)
        cipher = AES.new(key, AES.MODE_CBC)
        encrypted = cipher.iv + cipher.encrypt(pad(data, AES.block_size))
    elif algorithm == "DES":
        key = derive_key(password, salt, 8)
        cipher = DES.new(key, DES.MODE_CBC)
        encrypted = cipher.iv + cipher.encrypt(pad(data, DES.block_size))
    else:
        key = derive_key(password, salt, 16)
        cipher = AES.new(key, AES.MODE_CBC)
        encrypted = cipher.iv + cipher.encrypt(pad(data, AES.block_size))
    
    timestamp = int(time.time())
    encrypted_with_timestamp = salt + timestamp.to_bytes(8, 'big') + encrypted
    
    return encrypted_with_timestamp

def decrypt_data(data, password: str, algorithm):
    salt = data[:16]
    timestamp_bytes = data[16:24]
    encrypted_data = data[24:]
    
    try:
        timestamp = int.from_bytes(timestamp_bytes, 'big')
        current_time = int(time.time())
        if current_time - timestamp > FILE_EXPIRATION_MINUTES * 60:
            raise ValueError("File has expired and can no longer be decrypted")
        
        if algorithm == "AES":
            key = derive_key(password, salt, 16)
            iv = encrypted_data[:AES.block_size]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
        elif algorithm == "DES":
            key = derive_key(password, salt, 8)
            iv = encrypted_data[:DES.block_size]
            cipher = DES.new(key, DES.MODE_CBC, iv)
            return unpad(cipher.decrypt(encrypted_data[DES.block_size:]), DES.block_size)
        else:
            key = derive_key(password, salt, 16)
            iv = encrypted_data[:AES.block_size]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
    except Exception as e:
        raise ValueError("Invalid password, corrupted data, or file has expired") from e

def upload_to_dropbox(file_path, dropbox_path):
    """Upload a file to Dropbox"""
    try:
        dbx = dropbox.Dropbox(DROPBOX_ACCESS_TOKEN)
        with open(file_path, 'rb') as f:
            dbx.files_upload(f.read(), dropbox_path, mode=dropbox.files.WriteMode.overwrite)
        return True
    except Exception as e:
        print(f"Error uploading to Dropbox: {e}")
        return False


def ensure_dropbox_folders():
    try:
        dbx = dropbox.Dropbox(DROPBOX_ACCESS_TOKEN)
        try:
            dbx.files_get_metadata(DROPBOX_KEY_FOLDER)
        except ApiError:
            dbx.files_create_folder(DROPBOX_KEY_FOLDER)
        
        try:
            dbx.files_get_metadata(f"{DROPBOX_KEY_FOLDER}/hashes")
        except ApiError:
            dbx.files_create_folder(f"{DROPBOX_KEY_FOLDER}/hashes")
        
        try:
            dbx.files_get_metadata(DROPBOX_STORAGE_FOLDER)
        except ApiError:
            dbx.files_create_folder(DROPBOX_STORAGE_FOLDER)
    except Exception as e:
        print(f"Error ensuring Dropbox folders: {e}")

def cleanup_expired_files():
    """Background task to clean up expired files"""
    while True:
        try:
            now = time.time()
            for filename in os.listdir(ENCRYPTED_DIR):
                if filename.endswith(".enc"):
                    filepath = os.path.join(ENCRYPTED_DIR, filename)
                    try:
                        with open(filepath, 'rb') as f:
                            data = f.read()
                            if len(data) >= 24:
                                timestamp = int.from_bytes(data[16:24], 'big')
                                if now - timestamp > FILE_EXPIRATION_MINUTES * 60:
                                    f.close()
                                    try:
                                        os.remove(filepath)
                                        print(f"Removed expired file: {filename}")
                                    except PermissionError:
                                        print(f"Could not remove {filename} - file in use, will retry later")
                    except IOError as e:
                        print(f"Could not access {filename}: {e}, will retry later")
                        continue
        except Exception as e:
            print(f"Error in cleanup task: {e}")
        time.sleep(60)

ensure_dropbox_folders()

cleanup_thread = Thread(target=cleanup_expired_files, daemon=True)
cleanup_thread.start()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypted_files_count')
def encrypted_files_count():
    try:
        count = len([name for name in os.listdir(ENCRYPTED_DIR) if name.endswith('.enc')])
        return jsonify({'status': 'success', 'count': count})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/stored_files_count')
def stored_files_count():
    try:
        dbx = dropbox.Dropbox(DROPBOX_ACCESS_TOKEN)
        res = dbx.files_list_folder(DROPBOX_STORAGE_FOLDER)
        count = len([entry for entry in res.entries if isinstance(entry, dropbox.files.FileMetadata)])
        return jsonify({'status': 'success', 'count': count})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/verified_files_count')
def verified_files_count():
    try:
        dbx = dropbox.Dropbox(DROPBOX_ACCESS_TOKEN)
        res = dbx.files_list_folder(f"{DROPBOX_KEY_FOLDER}/hashes")
        count = len([entry for entry in res.entries if isinstance(entry, dropbox.files.FileMetadata)])
        return jsonify({'status': 'success', 'count': count})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

def upload_file_to_dropbox(file_data, dropbox_path):
    """Upload file data directly to Dropbox"""
    try:
        dbx = dropbox.Dropbox(DROPBOX_ACCESS_TOKEN)
        
        dbx.files_upload(file_data, dropbox_path, mode=dropbox.files.WriteMode.overwrite)
        return True
    except Exception as e:
        print(f"Error uploading to Dropbox: {e}")
        return False

@app.route('/process_file', methods=['POST'])
def process_file():
    try:
        action = request.form.get('action')
        algorithm = request.form.get('algorithm')
        password = request.form.get('password', '')
        file = request.files.get('file')
        store_in_dropbox = request.form.get('store_in_dropbox', 'false') == 'true'
        file_type = request.form.get('file_type', '')

        if not action:
            return jsonify({"status": "error", "message": "Action not selected"}), 400
        if not algorithm:
            return jsonify({"status": "error", "message": "Algorithm not selected"}), 400
        if not file:
            return jsonify({"status": "error", "message": "No file uploaded"}), 400

        filename = secure_filename(file.filename)
        file_data = file.read()

        if action == 'hash' and algorithm in ["SHA-256", "SHA-512"]:
            hash_value = hash_data(file_data, algorithm)
    
            hash_file_path = os.path.join(HASH_DIR, f"{filename}.hash.txt")
            with open(hash_file_path, "w") as hash_file:
                hash_file.write(hash_value)
    
            if store_in_dropbox:
                dropbox_path = f"{DROPBOX_KEY_FOLDER}/hashes/{filename}.hash.txt"
                if not upload_file_to_dropbox(hash_value.encode(), dropbox_path):
                    return jsonify({"status": "error", "message": "Failed to store hash in Dropbox"}), 500
    
            return jsonify({
                "status": "success", 
                "hash": hash_value, 
                "filename": f"{filename}.hash.txt"
            })

        if action in ['encrypt', 'decrypt'] and not file_type:
            return jsonify({"status": "error", "message": "File type is required for encryption/decryption"}), 400

        if action == 'encrypt':
            if not password:
                return jsonify({"status": "error", "message": "Password is required for encryption"}), 400
            
            key_id = hashlib.sha256(f"{filename}{time.time()}".encode()).hexdigest()[:16]
            encrypted_data = encrypt_data(file_data, password, algorithm)
            
            temp_file_path = os.path.join(TEMP_DIR, f"{filename}.enc")
            with open(temp_file_path, "wb") as temp_file:
                temp_file.write(encrypted_data)
            
            if store_in_dropbox:
                encrypted_file_path = os.path.join(ENCRYPTED_DIR, f"{filename}.enc")
                with open(encrypted_file_path, "wb") as enc_file:
                    enc_file.write(encrypted_data)

            key_info = {
                'filename': filename,
                'algorithm': algorithm,
                'key_id': key_id,
                'timestamp': int(time.time())
            }

            key_file_path = os.path.join(TEMP_DIR, f"{key_id}.key")
            with open(key_file_path, 'w') as key_file:
                key_file.write(str(key_info))

            if store_in_dropbox:
                dropbox_path = f"{DROPBOX_KEY_FOLDER}/{key_id}.key"
                if not upload_to_dropbox(key_file_path, dropbox_path):
                    return jsonify({"status": "error", "message": "Failed to store encryption key in Dropbox"}), 500

            os.remove(key_file_path)
            
            return send_file(
                temp_file_path,
                as_attachment=True,
                download_name=f"{filename}.enc",
                mimetype='application/octet-stream'
            )

        elif action == 'decrypt':
            if not filename.endswith(".enc"):
                return jsonify({"status": "error", "message": "File must have .enc extension for decryption"}), 400
            if not password:
                return jsonify({"status": "error", "message": "Password is required for decryption"}), 400

            decrypted_data = decrypt_data(file_data, password, algorithm)
            decrypted_file_path = os.path.join(DECRYPTED_DIR, filename.replace(".enc", ""))
            with open(decrypted_file_path, "wb") as dec_file:
                dec_file.write(decrypted_data)
                
            if store_in_dropbox:
                dropbox_path = f"{DROPBOX_STORAGE_FOLDER}/{filename.replace('.enc', '')}"
                if not upload_file_to_dropbox(decrypted_data, dropbox_path):
                    return jsonify({"status": "error", "message": "Failed to store decrypted file in Dropbox"}), 500
                    
            return send_file(decrypted_file_path, as_attachment=True)

        else:
            return jsonify({"status": "error", "message": f"Invalid action selected: {action}"}), 400

    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"An error occurred: {str(e)}"}), 500
    try:
        action = request.form.get('action')
        algorithm = request.form.get('algorithm')
        password = request.form.get('password', '')
        file = request.files.get('file')
        store_in_dropbox = request.form.get('store_in_dropbox', 'false') == 'true'

        if not action:
            return jsonify({"status": "error", "message": "Action not selected"}), 400
        if not algorithm:
            return jsonify({"status": "error", "message": "Algorithm not selected"}), 400
        if not file:
            return jsonify({"status": "error", "message": "No file uploaded"}), 400

        filename = secure_filename(file.filename)
        file_data = file.read()

        if action == 'hash' and algorithm in ["SHA-256", "SHA-512"]:
            hash_value = hash_data(file_data, algorithm)
    
            hash_file_path = os.path.join(HASH_DIR, f"{filename}.hash.txt")
            with open(hash_file_path, "w") as hash_file:
                hash_file.write(hash_value)
    
            if store_in_dropbox:
                dropbox_path = f"{DROPBOX_KEY_FOLDER}/hashes/{filename}.hash.txt"
                if not upload_file_to_dropbox(hash_value.encode(), dropbox_path):
                    return jsonify({"status": "error", "message": "Failed to store hash in Dropbox"}), 500
    
            return jsonify({
                "status": "success", 
                "hash": hash_value, 
                "filename": f"{filename}.hash.txt"
            })

        file_type = request.form.get('file_type')
        if action in ['encrypt', 'decrypt'] and not file_type:
            return jsonify({"status": "error", "message": "File type is required for encryption/decryption"}), 400

        if action == 'encrypt':
            if not password:
                return jsonify({"status": "error", "message": "Password is required for encryption"}), 400
            
            key_id = hashlib.sha256(f"{filename}{time.time()}".encode()).hexdigest()[:16]
            encrypted_data = encrypt_data(file_data, password, algorithm)
            
            temp_file_path = os.path.join(TEMP_DIR, f"{filename}.enc")
            with open(temp_file_path, "wb") as temp_file:
                temp_file.write(encrypted_data)
            
            if store_in_dropbox:
                encrypted_file_path = os.path.join(ENCRYPTED_DIR, f"{filename}.enc")
                with open(encrypted_file_path, "wb") as enc_file:
                    enc_file.write(encrypted_data)

            key_info = {
                'filename': filename,
                'algorithm': algorithm,
                'key_id': key_id,
                'timestamp': int(time.time())
            }

            key_file_path = os.path.join(TEMP_DIR, f"{key_id}.key")
            with open(key_file_path, 'w') as key_file:
                key_file.write(str(key_info))

            if store_in_dropbox:
                dropbox_path = f"{DROPBOX_KEY_FOLDER}/{key_id}.key"
                if not upload_to_dropbox(key_file_path, dropbox_path):
                    return jsonify({"status": "error", "message": "Failed to store encryption key in Dropbox"}), 500

            os.remove(key_file_path)
            
            return send_file(
                temp_file_path,
                as_attachment=True,
                download_name=f"{filename}.enc",
                mimetype='application/octet-stream'
            )

        elif action == 'decrypt':
            if not filename.endswith(".enc"):
                return jsonify({"status": "error", "message": "File must have .enc extension for decryption"}), 400
            if not password:
                return jsonify({"status": "error", "message": "Password is required for decryption"}), 400

            decrypted_data = decrypt_data(file_data, password, algorithm)
            decrypted_file_path = os.path.join(DECRYPTED_DIR, filename.replace(".enc", ""))
            with open(decrypted_file_path, "wb") as dec_file:
                dec_file.write(decrypted_data)
                
            if store_in_dropbox:
                dropbox_path = f"{DROPBOX_STORAGE_FOLDER}/{filename.replace('.enc', '')}"
                if not upload_file_to_dropbox(decrypted_data, dropbox_path):
                    return jsonify({"status": "error", "message": "Failed to store decrypted file in Dropbox"}), 500
                    
            return send_file(decrypted_file_path, as_attachment=True)

        else:
            return jsonify({"status": "error", "message": f"Invalid action selected: {action}"}), 400

    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"An error occurred: {str(e)}"}), 500
    try:
        action = request.form.get('action')
        algorithm = request.form.get('algorithm')
        password = request.form.get('password', '')
        file = request.files.get('file')

        if not action:
            return jsonify({"status": "error", "message": "Action not selected"}), 400
        if not algorithm:
            return jsonify({"status": "error", "message": "Algorithm not selected"}), 400
        if not file:
            return jsonify({"status": "error", "message": "No file uploaded"}), 400

        filename = secure_filename(file.filename)
        file_data = file.read()

        if action == 'hash' and algorithm in ["SHA-256", "SHA-512"]:
            hash_value = hash_data(file_data, algorithm)
    
            hash_file_path = os.path.join(HASH_DIR, f"{filename}.hash.txt")
            with open(hash_file_path, "w") as hash_file:
                hash_file.write(hash_value)
    
            dropbox_path = f"{DROPBOX_KEY_FOLDER}/hashes/{filename}.hash.txt"
            if not upload_to_dropbox(hash_file_path, dropbox_path):
                return jsonify({"status": "error", "message": "Failed to store hash in Dropbox"}), 500
    
            return jsonify({
                "status": "success", 
                "hash": hash_value, 
                "filename": f"{filename}.hash.txt"
            })

        file_type = request.form.get('file_type')
        if action in ['encrypt', 'decrypt'] and not file_type:
            return jsonify({"status": "error", "message": "File type is required for encryption/decryption"}), 400

        if action == 'encrypt':
            if not password:
                return jsonify({"status": "error", "message": "Password is required for encryption"}), 400
            
            key_id = hashlib.sha256(f"{filename}{time.time()}".encode()).hexdigest()[:16]
            encrypted_data = encrypt_data(file_data, password, algorithm)
            
            temp_file_path = os.path.join(TEMP_DIR, f"{filename}.enc")
            with open(temp_file_path, "wb") as temp_file:
                temp_file.write(encrypted_data)
            
            encrypted_file_path = os.path.join(ENCRYPTED_DIR, f"{filename}.enc")
            with open(encrypted_file_path, "wb") as enc_file:
                enc_file.write(encrypted_data)

            key_info = {
                'filename': filename,
                'algorithm': algorithm,
                'key_id': key_id,
                'timestamp': int(time.time())
            }

            key_file_path = os.path.join(TEMP_DIR, f"{key_id}.key")
            with open(key_file_path, 'w') as key_file:
                key_file.write(str(key_info))

            dropbox_path = f"{DROPBOX_KEY_FOLDER}/{key_id}.key"
            if not upload_to_dropbox(key_file_path, dropbox_path):
                return jsonify({"status": "error", "message": "Failed to store encryption key in Dropbox"}), 500

            os.remove(key_file_path)
            
            return send_file(
                temp_file_path,
                as_attachment=True,
                download_name=f"{filename}.enc",
                mimetype='application/octet-stream'
            )

        elif action == 'decrypt':
            if not filename.endswith(".enc"):
                return jsonify({"status": "error", "message": "File must have .enc extension for decryption"}), 400
            if not password:
                return jsonify({"status": "error", "message": "Password is required for decryption"}), 400

            decrypted_data = decrypt_data(file_data, password, algorithm)
            decrypted_file_path = os.path.join(DECRYPTED_DIR, filename.replace(".enc", ""))
            with open(decrypted_file_path, "wb") as dec_file:
                dec_file.write(decrypted_data)
            return send_file(decrypted_file_path, as_attachment=True)

        else:
            return jsonify({"status": "error", "message": f"Invalid action selected: {action}"}), 400

    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"An error occurred: {str(e)}"}), 500

@app.route('/verify_hash', methods=['POST'])
def verify_hash():
    try:
        filename = request.form.get('filename')
        uploaded_hash = request.form.get('hash', '').strip()
        
        if not filename or not uploaded_hash:
            return jsonify({"status": "error", "message": "Missing filename or hash"}), 400
        
        try:
            dbx = dropbox.Dropbox(DROPBOX_ACCESS_TOKEN)
            dropbox_path = f"{DROPBOX_KEY_FOLDER}/hashes/{filename}.hash.txt"
            
            try:
                _, res = dbx.files_download(dropbox_path)
                stored_hash = res.content.decode('utf-8').strip()
                
                return jsonify({
                    "status": "success",
                    "match": stored_hash == uploaded_hash,
                    "message": "File is authentic!" if stored_hash == uploaded_hash else "File is NOT authentic!"
                })
            except ApiError as e:
                if e.error.is_path() and e.error.get_path().is_not_found():
                    local_path = os.path.join(HASH_DIR, f"{filename}.hash.txt")
                    if os.path.exists(local_path):
                        with open(local_path, 'r') as f:
                            stored_hash = f.read().strip()
                        return jsonify({
                            "status": "success",
                            "match": stored_hash == uploaded_hash,
                            "message": "File is authentic!" if stored_hash == uploaded_hash else "File is NOT authentic!"
                        })
                    return jsonify({
                        "status": "error",
                        "message": "No hash found for this file"
                    }), 404
                raise
        except Exception as e:
            print(f"Error accessing Dropbox: {e}")
            local_path = os.path.join(HASH_DIR, f"{filename}.hash.txt")
            if os.path.exists(local_path):
                with open(local_path, 'r') as f:
                    stored_hash = f.read().strip()
                return jsonify({
                    "status": "success",
                    "match": stored_hash == uploaded_hash,
                    "message": "File is authentic!" if stored_hash == uploaded_hash else "File is NOT authentic!"
                })
            return jsonify({
                "status": "error",
                "message": "Failed to verify hash"
            }), 500
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "An unexpected error occurred"
        }), 500

@app.route('/store_file', methods=['POST'])
def store_file():
    try:
        if 'file' not in request.files:
            return jsonify({"status": "error", "message": "No file part"}), 400
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({"status": "error", "message": "No selected file"}), 400

        filename = secure_filename(file.filename)
        if not filename:
            return jsonify({"status": "error", "message": "Invalid filename"}), 400

        os.makedirs(TEMP_DIR, exist_ok=True)

        temp_path = os.path.join(TEMP_DIR, filename)
        file.save(temp_path)

        zip_filename = f"{filename}.zip"
        zip_path = os.path.join(TEMP_DIR, zip_filename)
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(temp_path, arcname=filename)

        dbx = dropbox.Dropbox(DROPBOX_ACCESS_TOKEN)
        dropbox_path = f"{DROPBOX_STORAGE_FOLDER}/{zip_filename}"
        
        with open(zip_path, 'rb') as f:
            dbx.files_upload(f.read(), dropbox_path, mode=dropbox.files.WriteMode.overwrite)

        os.remove(temp_path)
        os.remove(zip_path)

        return jsonify({
            "status": "success", 
            "message": "File stored successfully!",
            "filename": filename
        })

    except Exception as e:
        print(f"Error in store_file: {str(e)}")
        return jsonify({
            "status": "error", 
            "message": f"Failed to store file: {str(e)}"
        }), 500

@app.route('/list_stored_files')
def list_stored_files():
    try:
        dbx = dropbox.Dropbox(DROPBOX_ACCESS_TOKEN)
        files = []
        
        try:
            res = dbx.files_list_folder(DROPBOX_STORAGE_FOLDER)
            for entry in res.entries:
                if isinstance(entry, dropbox.files.FileMetadata):
                    files.append({
                        'name': entry.name.replace('.zip', ''),
                        'size': entry.size,
                        'modified': entry.client_modified.strftime('%Y-%m-%d %H:%M:%S')
                    })
        except ApiError as e:
            if e.error.is_path() and e.error.get_path().is_not_found():
                return jsonify({"status": "error", "message": "Storage folder not found"}), 404
            raise
        
        return jsonify({"status": "success", "files": files})
    except Exception as e:
        print(f"Error in list_stored_files: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/retrieve_file', methods=['POST'])
def retrieve_file():
    try:
        filename = request.form.get('filename')
        if not filename:
            return jsonify({"status": "error", "message": "Filename required"}), 400

        dbx = dropbox.Dropbox(DROPBOX_ACCESS_TOKEN)
        dropbox_path = f"{DROPBOX_STORAGE_FOLDER}/{filename}.zip"

        try:
            _, res = dbx.files_download(dropbox_path)
            zip_data = res.content

            with zipfile.ZipFile(io.BytesIO(zip_data)) as zipf:
                file_list = zipf.namelist()
                if not file_list:
                    return jsonify({"status": "error", "message": "No files in zip archive"}), 400
                
                extracted_data = zipf.read(file_list[0])
                original_filename = file_list[0]

            temp_file_path = os.path.join(TEMP_DIR, original_filename)
            with open(temp_file_path, 'wb') as temp_file:
                temp_file.write(extracted_data)

            return send_file(
                temp_file_path,
                as_attachment=True,
                download_name=original_filename,
                mimetype='application/octet-stream'
            )

        except ApiError as e:
            if e.error.is_path() and e.error.get_path().is_not_found():
                return jsonify({"status": "error", "message": f"File '{filename}' not found in storage"}), 404
            raise
    except Exception as e:
        print(f"Error in retrieve_file: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)