from warnings import catch_warnings
import random
from flask import Blueprint,request,jsonify
from flask_limiter import Limiter
from sqlalchemy import except_
from sqlalchemy.sql.functions import user
from . import limiter
from .models import *
from . import db
from werkzeug.security import generate_password_hash,check_password_hash
from .services import *
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required,get_jwt_identity
from .decorators import *

main = Blueprint("main",__name__)

@main.route("/register",methods  = ["POST"])
@limiter.limit("5 per minute")  # prevent abuse of registration
def register_user():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message':"no json data found"}),400
        if not is_field_present(data):
            return jsonify({'message':"key field missing"}),400
        if not is_valid_email(data['email']):
            return jsonify({'message':"invalid email"}),400
        if User.query.filter_by(email=data['email'].lower()).first():
            return jsonify({'message':"user with email already exists"}),409
        pass_hash = generate_password_hash(data['password'], method='pbkdf2:sha256',salt_length=16)
        db_user = User(username=data['username'],email=data['email'],password=pass_hash)
        db.session.add(db_user)
        db.session.commit()
        return jsonify({'message':f"User with name {data["username"]} created"}),201

    except Exception as e:
        db.session.rollback()
        return jsonify({'message':str(e)}),500

@main.route("/login",methods = ["POST"])
@limiter.limit("5 per minute")  # allow multiple but protect brute force
def login_user():
   try:
    data = request.get_json()
    if not data:
        return jsonify({'message':"no json data found"}),400
    if not is_login_field_present(data):
        return jsonify({'message':"key field(s) missing"}),409
    if not is_valid_email(data['email']):
        return jsonify({'message':"invalid email"}),400
    get_user = User.query.filter_by(email=data['email'].lower()).first()
    if get_user:
        if check_password_hash(get_user.password,data['password']):
            access_token=create_access_token(identity=str(get_user.id),additional_claims={"role":get_user.role})
            refresh_token=create_refresh_token(identity=str(get_user.id),additional_claims={"role":get_user.role})

            return jsonify({'message':"login successful",
                            'token':access_token,
                            'refresh_token':refresh_token}),200
        else:
            return jsonify({'message':"invalid password"}),401
    else:
        return jsonify({'message':"login failed"}),401
   except Exception as e:
       return jsonify({'message':str(e)}),500

@main.route("/Todos",methods = ["POST"])
@jwt_required(refresh=True)
@limiter.limit("20 per minute")
@required_auth('admin','user')
def add_todos():
    try:
        data=request.get_json()
        get_current_user = get_jwt_identity()
        if not data or "description" not in data or 'title'not in data:
            return jsonify({'message':"no json data found"}),404
        db_todo = Todos(title=data["title"],description=data["description"],user_id=get_current_user,is_completed=False)
        db.session.add(db_todo)
        db.session.commit()
        return jsonify({'message':"Todos added successfully"}),201
    except Exception as e:
        db.commit.rollback()
        return jsonify({'message':str(e)}),500

@main.route("/get_todos",methods = ["GET"])
@jwt_required(refresh=True)
@limiter.limit("30 per minute")
@required_auth('admin','user')
def get_todo():
 try:
    current_user_id = get_jwt_identity()
    get_user= User.query.get(current_user_id)
    if get_user.role == "admin":
        db_todo = Todos.query.all()
    else:
        db_todo = Todos.query.filter_by(user_id=current_user_id).all()
    if not db_todo :
        return jsonify({'message':"Todos not found"}),404
    return jsonify([todo.to_dict() for todo in db_todo])

 except Exception as error:
     return jsonify({'message':str(error)}),500

@main.route("/delete_todo/<int:id>",methods = ["DELETE"])
@jwt_required(refresh=True)
@limiter.limit("15 per minute")
@required_auth('admin','user')
def delete_todo(id):
    try:
        current_user_id = get_jwt_identity()
        get_role = User.query.get(current_user_id)
        if get_role.role == "admin":
            db_todo = Todos.query.filter_by(id=id)
        else:
           db_todo = Todos.query.filter_by(user_id=current_user_id,id=id).first()
        if not db_todo :
          return jsonify({'message':"Todo not found"}),401
        db.session.delete(db_todo)
        db.session.commit()
        return jsonify({"message":"success"})
    except Exception as error:
        db.session.rollback()
        return jsonify({"message":str(error)}),500

@main.route("/update_todo/<int:id>",methods = ["PATCH"])
@jwt_required(refresh=True)
@limiter.limit("15 per minute")
@required_auth('admin','user')
def update_todo(id):
   try:
    data = request.get_json()
    current_user_id=get_jwt_identity()
    get_role = User.query.get(current_user_id)
    if not data:
        return jsonify({'message':"no json data found"}),401
    if not required_field_present(data):
        return jsonify({'message':"key field(s) missing"}),409
    if get_role.role == "admin":
        db_todo = Todos.query.filter_by(id=id).first()
    else:
        db_todo = Todos.query.filter_by(user_id=current_user_id,id= id).first()
    if not db_todo:
        return jsonify({'message':"Todo not found"}),401
    if 'title' in data:
        db_todo.title = data["title"]
    if 'description' in data:
        db_todo.description = data["description"]
    db.session.commit()
    return jsonify({"message":"success"})
   except Exception as error:
       db.session.rollback()
       return jsonify({"message":str(error)}),500


@main.route("/todo/complete/<int:id>",methods = ['PATCH'])
@jwt_required(refresh=True)
@limiter.limit("15 per minute")  # avoid mass-completing todos quickly
@required_auth('admin','user')
def mark_todo(id):
    get_current_user = get_jwt_identity()
    db_todo = Todos.query.filter_by(user_id=get_current_user,id=id).first()
    if not db_todo:
        return jsonify({'message':"Todo not found"}),404
    db_todo.is_completed = True
    completed_todo=CompletedTodos(id=db_todo.id,title=db_todo.title,description=db_todo.description,user_id=db_todo.user_id,is_completed=db_todo.is_completed)
    db.session.add(completed_todo)
    db.session.delete(db_todo)
    db.session.commit()
    return jsonify({'message':"todo with id marked as completed"}),201


@main.route("/completed-todos", methods=["GET"])
@jwt_required(refresh=True)
@limiter.limit("30 per minute")  # limit repeated completed fetches
@required_auth('admin','user')
def get_completed_todos():
 try:
    get_current_user = get_jwt_identity()
    get_user = User.query.get(get_current_user)
    if get_user.role == "admin":
        db_todo = CompletedTodos.query.all()
    else:
        db_todo = Todos.query.get.all()
    if not db_todo :
        return jsonify({'message':"Todo not found"}),404
    return jsonify([todo.to_dict() for todo in db_todo])

 except Exception as error:
     return jsonify({'message':str(error)}),500


@main.route("/password-reset-request",methods=['POST'])
@limiter.limit('3 per hour')
def reset_password():
    try:
        data = request.get_json()
        if not data or "email" not in data:
            return jsonify({'message':"key field missing"}),400
        if not is_valid_email(data["email"]):
            return jsonify({'message':"invalid email"}),400
        get_user = User.query.filter_by(email=data["email"]).first()
        if not get_user:
            return jsonify({'message':"user not found"}),404
        otp = random.randint(100000,999999)
        if send_otp_email(get_user.email,otp):
            hashed_password = generate_password_hash(str(otp), method='pbkdf2:sha256')
            add_otp = PasswordReset(user_id=get_user.id, otp_hash=hashed_password)
            db.session.add(add_otp)
            db.session.commit()
            return jsonify({'message':'OTP is sent if the user exists'}),201
        else:
            return jsonify({'message':'failed'})
    except Exception as error:
        db.session.rollback()
        return jsonify({'message':str(error)}),500

@main.route("/password-reset",methods=['POST','PATCH'])

def reset_password():
    try:
        data = request.get_json()
        if not data or "password" not in data or "otp" not in data or 'email' not in data:
            return jsonify({'message':"key field missing"}),400
        if not is_valid_email(data["email"]):
            return jsonify({'message':"invalid email"}),400
        fetch_user = User.query.filter_by(email=data["email"]).first()
        if not fetch_user:
            return jsonify({'message':"user not found"}),404
        fetch_otp = PasswordReset.query.filter_by(user_id=fetch_user.id).first()
        if not fetch_otp:
                    return jsonify({'message':"otp not found"}),404
        if not check_password_hash(fetch_otp.otp, data["otp"]):
            return jsonify({'message':"invlaid otp"}),404
        if datetime.utcnow() > fetch_otp.expires_at:
            return jsonify({'message':"otp expired"}),401
        updated_password = generate_password_hash(data["password"], method='pbkdf2:sha256')
        fetch_user.password = updated_password
        db.session.delete(fetch_otp)
        db.session.commit()
    except Exception as error:
        return jsonify({'message':str(error)}),500












