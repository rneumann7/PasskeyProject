from helper import read_pem_file
# Create a dictionary to store the options
temp_storage = {
    'registration_options': None,
    'authentication_options': None,
    'credential_public_key': None,
    'sign_count': 0,
    'credential_id': None
}

# trusted certificate
trusted_cert = read_pem_file('trusted_cert.pem')