from webauthn import generate_registration_options,verify_registration_response
from rp_config import RP_ID, RP_NAME, RP_ORIGIN
from storage import temp_storage, trusted_cert

def create_options (options_request):
    generated_options = generate_registration_options(
        rp_id = RP_ID, 
        rp_name = RP_NAME,
        user_id = options_request.user_id,
        user_name = options_request.username,
        authenticator_selection=options_request.authenticatorSelection)
    temp_storage['registration_options'] = generated_options
    return generated_options

def verify_response (response):
    reg_options = temp_storage['registration_options']
    if reg_options.authenticator_selection.user_verification == 'required':
        require_uv = True
    else:
        require_uv = False
    verified = verify_registration_response(
        credential = response,
        expected_challenge = reg_options.challenge,
        expected_origin = RP_ORIGIN,
        expected_rp_id = RP_ID,
        require_user_verification=require_uv,
        pem_root_certs_bytes_by_fmt={'packed': [trusted_cert]}
    )
    temp_storage['credential_public_key'] = verified.credential_public_key
    temp_storage['sign_count'] = verified.sign_count
    temp_storage['credential_id'] = verified.credential_id
