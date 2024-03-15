from webauthn import generate_authentication_options,verify_authentication_response
from rp_config import RP_ID, RP_ORIGIN
from storage import temp_storage
from webauthn.helpers.structs import PublicKeyCredentialDescriptor

def create_options (options_request):
    allow_cred = None
    cred_id = temp_storage['credential_id'] 
    pkcd = PublicKeyCredentialDescriptor(id=cred_id, type='public-key')
    allow_cred = [pkcd]
    generated_options = generate_authentication_options(
        rp_id = RP_ID, 
        user_verification=options_request.user_verification,
        allow_credentials=allow_cred)
    temp_storage['authentication_options'] = generated_options
    return generated_options

def verify_response (response):
    auth_options = temp_storage['authentication_options']
    sign_count = temp_storage['sign_count']
    cred_pk = temp_storage['credential_public_key']
    verified = verify_authentication_response(
        credential = response,
        expected_challenge = auth_options.challenge,
        expected_origin = RP_ORIGIN,
        expected_rp_id = RP_ID,
        credential_public_key=cred_pk,
        credential_current_sign_count=sign_count,
        require_user_verification=auth_options.user_verification
    )
    temp_storage['sign_count'] = verified.new_sign_count
