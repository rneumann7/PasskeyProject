from flask import Blueprint, request, Response
from webauthn.helpers.structs import RegistrationCredential, AuthenticationCredential
from webauthn import options_to_json

from Models.assertion_options_request import AssertionOptionsRequest
from Models.attestation_options_request import AttestationOptionsRequest
import rp_registration as reg
import rp_authentication as auth
import json
from helper import generate_guid

main = Blueprint('main', __name__)


# This is the route for the registration options
@main.route('/attestation/options', methods=['POST'])    
def startRegister():
    try:
        options_request = AttestationOptionsRequest.model_validate(request.get_json())
        if options_request.username == "":
            raise Exception("Username cannot be empty")
        if options_request.user_id is None:
            options_request.user_id = generate_guid()
        options = options_to_json(reg.create_options(options_request))
        dict_options = json.loads(options)
        # Add these fields to the response for FIDO conformance test tool
        dict_options["status"] = "ok"
        dict_options["errorMessage"] = ""
        return Response(json.dumps(dict_options), mimetype='application/json')
    except Exception as e:
        return Response(json.dumps({"status": "failed", "errorMessage": str(e)}), mimetype='application/json', status=400)

    
# This is the route for the registration response
@main.route('/attestation/result', methods=['POST'])
def finishRegister():
    try:
        attestation_response = RegistrationCredential.model_validate(request.get_json())
        reg.verify_response(attestation_response)
        response = {"status": "ok", "errorMessage": ""}
        return Response(json.dumps(response), mimetype='application/json')
    except Exception as e:
        return Response(json.dumps({"status": "failed", "errorMessage": str(e)}), mimetype='application/json', status=400)
    
# This is the route for the authentication options
@main.route('/assertion/options', methods=['POST'])
def startLogin():
    try:
        options_request = AssertionOptionsRequest.model_validate(request.get_json())
        if options_request.username == "":
            raise Exception("Username cannot be empty")
        options = options_to_json(auth.create_options(options_request))
        dict_options = json.loads(options)
        # Add these fields to the response for FIDO conoformance test tool
        dict_options["status"] = "ok"
        dict_options["errorMessage"] = ""
        return Response(json.dumps(dict_options), mimetype='application/json')
    except Exception as e:
        return Response(json.dumps({"status": "failed", "errorMessage": str(e)}), mimetype='application/json', status=400)
    
# This is the route for the authentication response
@main.route('/assertion/result', methods=['POST'])
def finishLogin():
    try:
        assertion_response = AuthenticationCredential.model_validate(request.get_json())
        auth.verify_response(assertion_response)
        response = {"status": "ok", "errorMessage": ""}
        return Response(json.dumps(response), mimetype='application/json')
    except Exception as e:
        return Response(json.dumps({"status": "failed", "errorMessage": str(e)}), mimetype='application/json', status=400)