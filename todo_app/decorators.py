from functools import wraps
from flask_jwt_extended import get_jwt_identity,get_jwt
from flask import jsonify
from .models import User


def required_auth(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
          try:
            jwt_data = get_jwt()
            role = jwt_data.get('role')

            if role in roles:
                return fn(*args, **kwargs)

            identity = get_jwt_identity()
            if not identity:
                return jsonify({"message": "Invalid token"}), 401

            user = User.query.get(identity)
            if not user:
                return jsonify({"message": "User not found"}), 404

            if user.role not in roles:
                return jsonify({
                    "message": f"Access denied. Required roles: {', '.join(roles)}"
                }), 403
            return fn(*args, **kwargs)
          except Exception as e:
            return jsonify({"message": str(e)}), 500
        return wrapper
    return decorator
