import hashlib

from flask import request
from flask_restx import Resource, Namespace

from auth import auth_required, admin_required
from models import User, UserSchema
from setup_db import db


def get_hash(password):
    return hashlib.md5(password.encode('utf-8')).hexdigest()

user_ns = Namespace('users')

@user_ns.route('/')
class UsersView(Resource):
    def get(self):

        all_users = db.session.query(User).all()
        res = UserSchema(many=True).dump(all_users)
        return res, 200

    def post(self):
        req_json = request.json
        # res = User(**req_json)
        print(type(req_json))
        req_json['password'] = get_hash(req_json['password'])
        db.session.add(User(**req_json))
        db.session.commit()
        return "", 201, {"location": f"/users/{req_json['id']}"}



@user_ns.route('/<int:uid>')
class UserView(Resource):
    @admin_required
    def delete(self, uid):

        user = User.query.get(uid)
        db.session.delete(user)
        db.session.commit()
        return "", 204

    @admin_required
    def put(self, uid):
        user = db.session.query(User).get(uid)
        req_json = request.json
        user.username = req_json.get("username")
        user.password = req_json.get("password")
        user.role = req_json.get("role")
        db.session.add(user)
        db.session.commit()
        return "", 204