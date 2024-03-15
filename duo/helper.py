
import uuid

def generate_guid():
    return str(uuid.uuid4())

def read_pem_file(filename):
    with open(filename, 'rb') as file:
        return file.read()