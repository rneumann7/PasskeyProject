from typing import Optional
from pydantic import BaseModel, Field

class AssertionOptionsRequest (BaseModel):
    username: str
    user_verification: Optional[str] = Field(None, alias='userVerification')
