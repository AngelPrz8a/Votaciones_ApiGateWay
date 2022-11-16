from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json
from waitress import serve
import datetime
import requests
import re

from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app = Flask(__name__)
cors = CORS(app)
jwt = JWTManager(app)

app.config["JWT_SECRET_KEY"] = "juan-angel-perez-ochoa"  # Cambiar por el que se convierte


@app.route("/", methods=['GET'])
def test():
    json = {}
    json["message"] = "Server running ..."
    return jsonify(json)


@app.route("/login", methods=["POST"])
def createToken():
    data = request.get_json()
    configData = loadFileConfig()
    url = configData["url-backend-security"] + "/user/validation"
    headers = {"Content-Type": "application/json; charset=utf-8"}  # no ingresar ñ, úóéíá
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(seconds=60 * 60 * 24)
        accesToken = create_access_token(identity=user, expires_delta=expires)
        return jsonify({"token": accesToken, "userId": user["_id"]})
    else:
        return jsonify({"msg": "Usuario o contraseña incorrectos"}), 401


@app.before_request
def beforeRequestCallback():
    endPoint = limpiarUrl(request.path)
    #endPoint = request.path
    excludeRoutes = ["/login"]
    if excludeRoutes.__contains__(request.path):
        print("ruta excluida", request.path)
        pass
    else:
        if verify_jwt_in_request():
            usuario = get_jwt_identity()
            if usuario["role"] is not None:
                if not validarPermiso(endPoint, request.method.upper(), usuario["role"]):
                    return jsonify({"msg": "El permiso no lo puede ejecutar"}), 401
            else:
                return jsonify({"msg": "El usuario no tiene rol"}), 401
        else:
            return jsonify({"msg": "El usuario no tiene rol"}), 401


def validarPermiso(endPoint, metodo, idRol):
    tienePermiso = False
    dataConfig = loadFileConfig()
    url = dataConfig["url-backend-security"] + "/permissionrole/validate-permission/" + str(idRol)
    headers = {"Content-Type": "application/json;charset=utf-8"}
    body = {
        "url": endPoint,
        "method": metodo
    }
    #print("url=",endPoint,str(idRol),"body=",body)
    # print("url",url,"rol = 636d72f9b93192603786a5ca =",idRol)#http://127.0.0.1:8082/permisorol/validar-permisos/636d72f9b93192603786a5ca
    response = requests.post(url, json=body, headers=headers)
    #print("response=",response.json())
    try:
        data = response.json()
        if ("_id" in data):
            tienePermiso = True
    except:
        pass
    return tienePermiso


def limpiarUrl(url):
    partes = url.split("/")
    for parte in partes:
        if re.search("\\d", parte):
            #url = url.replace(parte, "?")
            url = url.replace(parte, "<string:id>")
    return url


############################################################################
############################################################################
# RUTAS



#RESULTADO
@app.route("/result", methods=["GET"])
def getAllResult():
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/result"
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/result/<string:id>", methods=["GET"])
def showResult(id):
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/result/" + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/result", methods=["POST"])
def createResult():
    data = request.get_json()
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/result"
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/result/<string:id>", methods=["PUT"])
def updateResult(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/result/" + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/result/<string:id>", methods=["DELETE"])
def deleteResult(id):
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/result/" + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)
# END RESULTADO



# CIUDADANO
@app.route("/citizen", methods=["GET"])
def getAllCitizen():
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/citizen"
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/citizen/<string:id>", methods=["GET"])
def showCitizen(id):
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/citizen/" + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/citizen", methods=["POST"])
def createCitizen():
    data = request.get_json()
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/citizen"
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/citizen/<string:id>", methods=["PUT"])
def updateCitizen(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/citizen/" + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/citizen/<string:id>", methods=["DELETE"])
def deleteCitizen(id):
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/citizen/" + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)
# END CIUDADANO



# CANDIDATO
@app.route("/candidate", methods=["GET"])
def getAllCandidate():
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/candidate"
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/candidate/<string:id>", methods=["GET"])
def showCandidate(id):
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/candidate/" + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/candidate", methods=["POST"])
def createCandidate():
    data = request.get_json()
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/candidate"
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/candidate/<string:id>", methods=["PUT"])
def updateCandidate(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/candidate/" + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/candidate/<string:id>", methods=["DELETE"])
def deleteCandidate(id):
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/candidate/" + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)
# END CANDIDATO



# PARTIDO
@app.route("/match", methods=["GET"])
def getAllMatch():
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/match"
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/match/<string:id>", methods=["GET"])
def showMatch(id):
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/match/" + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/match", methods=["POST"])
def createMatch():
    data = request.get_json()
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/match"
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/match/<string:id>", methods=["PUT"])
def updateMatch(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/match/" + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/match/<string:id>", methods=["DELETE"])
def deleteMatch(id):
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/match/" + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)
# END PARTIDO



# MESAS
@app.route("/table", methods=["GET"])
def getAllTable():
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/table"
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/table/<string:id>", methods=["GET"])
def showTable(id):
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/table/" + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/table", methods=["POST"])
def createTable():
    data = request.get_json()
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/table"
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/table/<string:id>", methods=["PUT"])
def updateTable(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/table/" + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/table/<string:id>", methods=["DELETE"])
def deleteTable(id):
    headers = {"Content-Type": "application/json;charset=utf-8"}
    url = dataConfig["url-backend-academic"] + "/table/" + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)
# END MESA


############################################################################
############################################################################

def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data


if __name__ == '__main__':
    dataConfig = loadFileConfig()
    print("Server running : " + "http://" + dataConfig["url-backend"] + ":" +
          str(dataConfig["port"]))
    serve(app, host=dataConfig["url-backend"], port=dataConfig["port"])
