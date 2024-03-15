from typing import Optional
from pydantic import BaseModel, Field
from webauthn.helpers.structs import AuthenticatorSelectionCriteria

# temporary model to map this to AuthenticatorSelectionCriteria
class AuthCriteria (BaseModel):
    resident_key: Optional[str] = Field(None, alias='residentKey')
    user_verification: Optional[str] = Field(None, alias='userVerification')

class AttestationOptionsRequest (BaseModel):

    username: str
    user_id: Optional[str] = Field(None, alias='userId')
    authenticator_selection: Optional[AuthCriteria] =  Field(None, alias='authenticatorSelection')
    attestation: Optional[str] = Field(None, alias='attestation')

    @property
    def authenticatorSelection(self):
        if self.authenticator_selection:
            return AuthenticatorSelectionCriteria.model_validate(self.authenticator_selection.model_dump())
        return None