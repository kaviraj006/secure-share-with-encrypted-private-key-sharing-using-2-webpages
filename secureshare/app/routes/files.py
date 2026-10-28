from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from app.extensions import db
from app.models import EncryptedFile
from app.services.storage import CiphertextStorageService, StorageError
from app.services.security import verify_csrf_token

files_bp = Blueprint("files", __name__, url_prefix="/api/files")

@files_bp.route("/upload", methods=["POST"])
@login_required
def upload_file():
    verify_csrf_token()
    
    if "file" not in request.files:
        return jsonify({"error": "No file stream provided in upload request.", "code": "MISSING_FILE"}), 400
        
    uploaded_file = request.files["file"]
    if not uploaded_file.filename:
        return jsonify({"error": "Empty filename submitted.", "code": "EMPTY_FILENAME"}), 400
        
    nonce = (request.form.get("nonce") or "").strip()
    algorithm = (request.form.get("algorithm") or "AES-256-GCM").strip()
    protocol_version = int(request.form.get("protocol_version") or 1)
    
    if not nonce:
        return jsonify({"error": "Cryptographic nonce is required.", "code": "MISSING_NONCE"}), 400
        
    storage_svc = CiphertextStorageService()
    max_size = current_app.config["MAX_CONTENT_LENGTH"]
    
    try:
        storage_id, total_bytes = storage_svc.save_ciphertext(uploaded_file.stream, max_size=max_size)
    except StorageError as e:
        return jsonify({"error": str(e), "code": "STORAGE_ERROR"}), 400
    except Exception:
        return jsonify({"error": "Internal error storing encrypted ciphertext.", "code": "UPLOAD_FAILED"}), 500
        
    enc_file = EncryptedFile(
        owner_id=current_user.id,
        storage_id=storage_id,
        encrypted_size=total_bytes,
        nonce=nonce,
        algorithm=algorithm,
        protocol_version=protocol_version,
        status="active"
    )
    db.session.add(enc_file)
    db.session.commit()
    
    return jsonify({
        "message": "Ciphertext uploaded successfully.",
        "file": enc_file.to_dict()
    }), 201

@files_bp.route("/<file_id>", methods=["GET"])
@login_required
def get_file_metadata(file_id: str):
    file_record = EncryptedFile.query.filter_by(id=file_id).first_or_404(description="File not found.")
    if file_record.owner_id != current_user.id:
        return jsonify({"error": "Unauthorized.", "code": "FORBIDDEN"}), 403
    return jsonify({"file": file_record.to_dict()})

@files_bp.route("/<file_id>", methods=["DELETE"])
@login_required
def delete_file(file_id: str):
    verify_csrf_token()
    file_record = EncryptedFile.query.filter_by(id=file_id).first_or_404(description="File not found.")
    if file_record.owner_id != current_user.id:
        return jsonify({"error": "Unauthorized.", "code": "FORBIDDEN"}), 403
        
    storage_svc = CiphertextStorageService()
    storage_svc.delete_ciphertext(file_record.storage_id)
    
    file_record.status = "deleted"
    db.session.delete(file_record)
    db.session.commit()
    
    return jsonify({"message": "File and ciphertext permanently deleted."})
