
import flask_restful
import json
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_jwt_extended import jwt_required, create_refresh_token, get_jwt, create_access_token, get_jwt_identity, \
    unset_jwt_cookies
from operator import attrgetter

app = Flask(__name__)
app.url_map.strict_slashes = False
app.config['CORS_HEADERS'] = 'Content-Type'
CORS(app, resources={r"/*": {"origins": "*"}})

app.config["JWT_SECRET_KEY"] = "!@#$%^&*()"  # Change this!
jwt = JWTManager(app)


@app.route('/')
def hello_world():
    return 'Server is running'


app.config['CORS_HEADERS'] = 'Content-Type'
CORS(app, resources={r"/*": {"origins": "*"}})


@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    myResult = ["admin", "admin", 1]

    if username is None or password is None:
        flask_restful. abort(400)
    elif username != "admin" and password != "admin":
        flask_restful.abort(401)
    else:

        additional_claims = {
            "username": "admin", "name": "admin"}
        access_token = create_access_token(
            username, additional_claims=additional_claims)
        refresh_token = create_refresh_token(
            username, additional_claims=additional_claims)
        return jsonify(access_token=access_token, refresh_token=refresh_token)


@app.route("/logout", methods=["POST"])
def logout():
    response = jsonify({"msg": "logout successful"})
    unset_jwt_cookies(response)
    return response


@app.route("/refresh", methods=["GET"])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify(access_token=access_token)


@app.route('/user', methods=['GET'])
@jwt_required()
def user():
    claims = get_jwt()
    return jsonify({"name": "smok"})


@app.route('/users', methods=['GET'])
@jwt_required()
def strategy():
    f = open('users.json')
    data = json.load(f)
    f.close()

    q = '' if request.args.get('name') is None else request.args.get('name')
    tmp2 = [x for x in data if q in str(x['name'])]

    return jsonify(tmp2)


@app.route('/users/<id>', methods=['GET'])
@jwt_required()
def param(id):

    f = open('users.json')
    data = json.load(f)
    f.close()

    tmp2 = [x for x in data if x['id'] == int(id)]

    if len(tmp2) > 0:
        return jsonify(tmp2[0])
    else:
        return flask_restful.abort(404)


@app.route("/users", methods=["POST"])
@jwt_required()
def create_user():
    f = open('users.json')
    data = json.load(f)
    f.close()

    new_user = {
        "id": len(data)+1,
        "name": request.json.get('name'),
        "last_name": request.json.get('last_name')
    }

    f = open('users.json', 'w')
    data.append(new_user)
    json.dump(data, f)
    f.close()
    return jsonify(new_user)

@app.route("/users/:id", methods=["PUT"])
@jwt_required()
def update_user():
    f = open('users.json')
    data = json.load(f)
    f.close()

    tmp2 = [x for x in data if x['id'] == int(id)]

    if len(tmp2) > 0:
        for u in tmp2:
            if u["id"] == int(id):
                u["name"]= request.json.get('name')
                u["last_name"]=    request.json.get('last_name')
    
    else:
        return flask_restful.abort(404)
    

    f = open('users.json', 'w')
    json.dump(data, f)
    f.close()
    return "Success"

if __name__ == '__main__':
    try:
        app.run(debug=True, port=4000, host='0.0.0.0')
    except Exception as e:
        print(e)
