"""
Identity Federation Module for Boundary Daemon

Provides external identity integration while maintaining ceremony requirements:
- OIDC token validation for SSO integration
- LDAP group mapping for enterprise directories
- PAM integration for system authentication

IMPORTANT: External identity is ADVISORY only. Ceremonies are still
required for all sensitive operations regardless of identity source.
"""

from .oidc_validator import (
    OIDCValidator,
    OIDCConfig,
    OIDCToken,
    TokenValidationResult,
    OIDCProvider,
)

from .ldap_mapper import (
    LDAPMapper,
    LDAPConfig,
    LDAPGroup,
    GroupMapping,
    CapabilitySet,
)

from .pam_integration import (
    PAMAuthenticator,
    PAMConfig,
    PAMResult,
    PAMSession,
)

from .identity_manager import (
    IdentityManager,
    IdentitySource,
    FederatedIdentity,
    IdentityConfig,
)

__all__ = [
    # OIDC
    'OIDCValidator',
    'OIDCConfig',
    'OIDCToken',
    'TokenValidationResult',
    'OIDCProvider',

    # LDAP
    'LDAPMapper',
    'LDAPConfig',
    'LDAPGroup',
    'GroupMapping',
    'CapabilitySet',

    # PAM
    'PAMAuthenticator',
    'PAMConfig',
    'PAMResult',
    'PAMSession',

    # Manager
    'IdentityManager',
    'IdentitySource',
    'FederatedIdentity',
    'IdentityConfig',
]
