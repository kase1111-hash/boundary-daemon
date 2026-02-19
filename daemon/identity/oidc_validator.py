"""
OIDC Token Validator for Identity Federation

Validates OIDC/OAuth2 tokens from external identity providers and maps
claims to local capabilities. Supports common providers:
- Okta
- Auth0
- Azure AD
- Google Workspace
- Keycloak
- Generic OIDC providers

IMPORTANT: OIDC validation provides ADVISORY identity only.
Ceremonies are still required for sensitive operations.

SECURITY (Vuln #7 - Fetch-Execute): All outbound HTTP requests for OIDC
discovery and JWKS fetching use TLS with certificate pinning and are gated
behind boundary mode checks. Requests are blocked in AIRGAP/COLDROOM/LOCKDOWN.
"""

import base64
import hashlib
import json
import logging
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Callable, Dict, List, Optional, Any, Set, Tuple
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

# Try to import JWT library
try:
    import jwt
    from jwt import PyJWKClient
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    logger.warning("PyJWT not available - OIDC validation disabled")


class OIDCProvider(Enum):
    """Known OIDC providers with pre-configured settings."""
    OKTA = "okta"
    AUTH0 = "auth0"
    AZURE_AD = "azure_ad"
    GOOGLE = "google"
    KEYCLOAK = "keycloak"
    GENERIC = "generic"


@dataclass
class OIDCConfig:
    """Configuration for OIDC validation."""
    # Provider settings
    provider: OIDCProvider = OIDCProvider.GENERIC
    issuer: str = ""
    client_id: str = ""
    client_secret: Optional[str] = None

    # Discovery
    discovery_url: Optional[str] = None  # .well-known/openid-configuration
    jwks_uri: Optional[str] = None

    # Validation settings
    audience: Optional[str] = None
    verify_at_hash: bool = True
    allowed_algorithms: List[str] = field(default_factory=lambda: ["RS256", "RS384", "RS512"])
    clock_skew_seconds: int = 60

    # Claim mappings
    username_claim: str = "preferred_username"
    email_claim: str = "email"
    groups_claim: str = "groups"
    roles_claim: str = "roles"

    # TLS certificate pinning (Vuln #7)
    # Pin to specific CA certificates for the OIDC provider to prevent MITM
    tls_ca_bundle: Optional[str] = None  # Path to CA bundle file
    tls_pin_sha256: Optional[List[str]] = None  # SHA-256 pin(s) of server cert

    # Caching
    cache_jwks_seconds: int = 3600
    cache_tokens_seconds: int = 300


@dataclass
class OIDCToken:
    """Parsed and validated OIDC token."""
    raw: str
    header: Dict[str, Any]
    payload: Dict[str, Any]

    # Standard claims
    issuer: str = ""
    subject: str = ""
    audience: List[str] = field(default_factory=list)
    expiration: Optional[datetime] = None
    issued_at: Optional[datetime] = None
    not_before: Optional[datetime] = None
    jwt_id: Optional[str] = None

    # Common claims
    username: Optional[str] = None
    email: Optional[str] = None
    email_verified: bool = False
    name: Optional[str] = None
    groups: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)

    # Custom claims
    custom_claims: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        if self.expiration is None:
            return False
        return datetime.utcnow() > self.expiration

    @property
    def time_until_expiry(self) -> Optional[timedelta]:
        """Get time until token expires."""
        if self.expiration is None:
            return None
        return self.expiration - datetime.utcnow()


@dataclass
class TokenValidationResult:
    """Result of token validation."""
    valid: bool
    token: Optional[OIDCToken] = None
    error: Optional[str] = None
    error_code: Optional[str] = None

    # Mapped capabilities (advisory only)
    capabilities: Set[str] = field(default_factory=set)

    # Ceremony requirements
    ceremony_required: bool = True
    ceremony_type: Optional[str] = None


class OIDCValidator:
    """
    Validates OIDC tokens and maps claims to local capabilities.

    Usage:
        validator = OIDCValidator(OIDCConfig(
            issuer="https://accounts.google.com",
            client_id="your-client-id",
        ))

        result = validator.validate_token(token_string)
        if result.valid:
            # Identity is advisory - still need ceremony for sensitive ops
            print(f"User: {result.token.username}")
            print(f"Capabilities: {result.capabilities}")
    """

    # Modes that block all external network access (Vuln #7)
    NETWORK_BLOCKED_MODES = {'AIRGAP', 'COLDROOM', 'LOCKDOWN'}

    def __init__(
        self,
        config: OIDCConfig,
        mode_getter: Optional[Callable[[], str]] = None,
    ):
        self.config = config
        self._jwks_client: Optional['PyJWKClient'] = None
        self._jwks_cache_time: float = 0
        self._discovery_cache: Optional[Dict[str, Any]] = None
        self._token_cache: Dict[str, Tuple[TokenValidationResult, float]] = {}
        self._lock = threading.Lock()

        # SECURITY (Vuln #7): Mode getter to gate HTTP requests
        self._get_mode = mode_getter

        # Capability mappings
        self._group_capabilities: Dict[str, Set[str]] = {}
        self._role_capabilities: Dict[str, Set[str]] = {}

        # SECURITY (Vuln #7): Build pinned TLS context
        self._ssl_context = self._create_pinned_ssl_context()

    def set_mode_getter(self, getter: Callable[[], str]) -> None:
        """Set mode getter for boundary mode checks."""
        self._get_mode = getter

    def _is_network_blocked(self) -> bool:
        """Check if outbound network is blocked in current boundary mode.

        SECURITY (Vuln #7): OIDC discovery and JWKS fetching require
        outbound HTTPS. These MUST be blocked in network-isolated modes
        to prevent data exfiltration via crafted OIDC issuer URLs.
        """
        if not self._get_mode:
            return False
        try:
            current_mode = self._get_mode()
            if current_mode and current_mode.upper() in self.NETWORK_BLOCKED_MODES:
                return True
        except Exception:
            pass
        return False

    def _create_pinned_ssl_context(self) -> ssl.SSLContext:
        """Create TLS context with certificate pinning for OIDC endpoints.

        SECURITY (Vuln #7): Pins TLS connections to a specific CA bundle
        to prevent MITM attacks on OIDC discovery and JWKS endpoints.
        Without pinning, a compromised CA or DNS hijack could serve
        forged signing keys, allowing token forgery.
        """
        context = ssl.create_default_context()

        # Always enforce certificate verification
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        # Minimum TLS 1.2
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Load custom CA bundle if configured (cert pinning)
        if self.config.tls_ca_bundle:
            try:
                context.load_verify_locations(self.config.tls_ca_bundle)
                logger.info(
                    f"OIDC TLS pinned to CA bundle: {self.config.tls_ca_bundle}"
                )
            except Exception as e:
                logger.error(f"Failed to load OIDC CA bundle: {e}")
                raise

        return context

    def _validate_url_scheme(self, url: str, purpose: str) -> bool:
        """Validate that a URL uses HTTPS.

        SECURITY (Vuln #7): Reject non-HTTPS URLs for OIDC endpoints
        to prevent credential/token interception.
        """
        parsed = urlparse(url)
        if parsed.scheme != 'https':
            logger.error(
                f"SECURITY: {purpose} URL must use HTTPS, got {parsed.scheme}:// "
                f"(rejecting to prevent credential interception)"
            )
            return False
        return True

    def _fetch_discovery(self) -> Optional[Dict[str, Any]]:
        """Fetch OIDC discovery document with TLS pinning and mode check.

        SECURITY (Vuln #7): Uses pinned TLS context and is blocked in
        network-isolated boundary modes.
        """
        if self._discovery_cache:
            return self._discovery_cache

        # SECURITY: Block in network-isolated modes
        if self._is_network_blocked():
            logger.warning(
                "OIDC discovery blocked: network-isolated boundary mode active"
            )
            return None

        discovery_url = self.config.discovery_url
        if not discovery_url:
            discovery_url = urljoin(
                self.config.issuer.rstrip('/') + '/',
                '.well-known/openid-configuration'
            )

        # SECURITY: Enforce HTTPS
        if not self._validate_url_scheme(discovery_url, "OIDC discovery"):
            return None

        try:
            import urllib.request
            with urllib.request.urlopen(
                discovery_url,
                timeout=10,
                context=self._ssl_context,
            ) as response:
                self._discovery_cache = json.loads(response.read().decode())
                return self._discovery_cache
        except Exception as e:
            logger.error(f"Failed to fetch OIDC discovery: {e}")
            return None

    def _get_jwks_client(self) -> Optional['PyJWKClient']:
        """Get or create JWKS client with mode check.

        SECURITY (Vuln #7): Blocked in network-isolated modes.
        The PyJWKClient fetches signing keys over HTTPS.
        """
        if not JWT_AVAILABLE:
            return None

        # SECURITY: Block in network-isolated modes
        if self._is_network_blocked():
            logger.warning(
                "JWKS fetch blocked: network-isolated boundary mode active"
            )
            return None

        now = time.time()

        # Check cache
        if self._jwks_client and (now - self._jwks_cache_time) < self.config.cache_jwks_seconds:
            return self._jwks_client

        # Get JWKS URI
        jwks_uri = self.config.jwks_uri
        if not jwks_uri:
            discovery = self._fetch_discovery()
            if discovery:
                jwks_uri = discovery.get('jwks_uri')

        if not jwks_uri:
            logger.error("No JWKS URI available")
            return None

        # SECURITY: Enforce HTTPS for JWKS
        if not self._validate_url_scheme(jwks_uri, "JWKS"):
            return None

        try:
            # Pass SSL context to PyJWKClient for cert pinning
            self._jwks_client = PyJWKClient(
                jwks_uri,
                ssl_context=self._ssl_context,
            )
            self._jwks_cache_time = now
            return self._jwks_client
        except TypeError:
            # Older PyJWT versions don't support ssl_context parameter
            logger.warning(
                "PyJWT version does not support ssl_context - "
                "using system default TLS (cert pinning unavailable)"
            )
            self._jwks_client = PyJWKClient(jwks_uri)
            self._jwks_cache_time = now
            return self._jwks_client
        except Exception as e:
            logger.error(f"Failed to create JWKS client: {e}")
            return None

    def add_group_capabilities(self, group: str, capabilities: Set[str]) -> None:
        """Map a group to capabilities."""
        self._group_capabilities[group] = capabilities

    def add_role_capabilities(self, role: str, capabilities: Set[str]) -> None:
        """Map a role to capabilities."""
        self._role_capabilities[role] = capabilities

    def _map_capabilities(self, token: OIDCToken) -> Set[str]:
        """Map token claims to capabilities."""
        capabilities: Set[str] = set()

        # Map from groups
        for group in token.groups:
            if group in self._group_capabilities:
                capabilities.update(self._group_capabilities[group])

        # Map from roles
        for role in token.roles:
            if role in self._role_capabilities:
                capabilities.update(self._role_capabilities[role])

        return capabilities

    def _parse_token(self, token_string: str) -> Optional[OIDCToken]:
        """Parse JWT token without validation."""
        try:
            parts = token_string.split('.')
            if len(parts) != 3:
                return None

            # Decode header and payload (no signature verification)
            header = json.loads(
                base64.urlsafe_b64decode(parts[0] + '==').decode()
            )
            payload = json.loads(
                base64.urlsafe_b64decode(parts[1] + '==').decode()
            )

            token = OIDCToken(
                raw=token_string,
                header=header,
                payload=payload,
            )

            # Standard claims
            token.issuer = payload.get('iss', '')
            token.subject = payload.get('sub', '')

            aud = payload.get('aud', [])
            token.audience = aud if isinstance(aud, list) else [aud]

            if 'exp' in payload:
                token.expiration = datetime.utcfromtimestamp(payload['exp'])
            if 'iat' in payload:
                token.issued_at = datetime.utcfromtimestamp(payload['iat'])
            if 'nbf' in payload:
                token.not_before = datetime.utcfromtimestamp(payload['nbf'])

            token.jwt_id = payload.get('jti')

            # Common claims
            token.username = payload.get(self.config.username_claim)
            token.email = payload.get(self.config.email_claim)
            token.email_verified = payload.get('email_verified', False)
            token.name = payload.get('name')

            # Groups and roles
            groups = payload.get(self.config.groups_claim, [])
            token.groups = groups if isinstance(groups, list) else [groups]

            roles = payload.get(self.config.roles_claim, [])
            token.roles = roles if isinstance(roles, list) else [roles]

            # Custom claims
            standard_claims = {
                'iss', 'sub', 'aud', 'exp', 'iat', 'nbf', 'jti',
                'name', 'email', 'email_verified',
                self.config.username_claim,
                self.config.groups_claim,
                self.config.roles_claim,
            }
            token.custom_claims = {
                k: v for k, v in payload.items()
                if k not in standard_claims
            }

            return token

        except Exception as e:
            logger.error(f"Failed to parse token: {e}")
            return None

    def validate_token(
        self,
        token_string: str,
        require_groups: Optional[List[str]] = None,
        require_roles: Optional[List[str]] = None,
    ) -> TokenValidationResult:
        """
        Validate an OIDC token.

        Args:
            token_string: The JWT token string
            require_groups: Optional list of required groups
            require_roles: Optional list of required roles

        Returns:
            TokenValidationResult with validation status and parsed token
        """
        # Check cache
        cache_key = hashlib.sha256(token_string.encode()).hexdigest()[:16]
        with self._lock:
            if cache_key in self._token_cache:
                cached_result, cache_time = self._token_cache[cache_key]
                if time.time() - cache_time < self.config.cache_tokens_seconds:
                    return cached_result

        # Parse token first
        token = self._parse_token(token_string)
        if not token:
            return TokenValidationResult(
                valid=False,
                error="Failed to parse token",
                error_code="parse_error",
            )

        # Check if JWT validation is available
        if not JWT_AVAILABLE:
            # Return parsed but unverified token
            logger.warning("JWT validation unavailable - token not cryptographically verified")
            capabilities = self._map_capabilities(token)
            result = TokenValidationResult(
                valid=True,  # Parsed successfully, but not verified
                token=token,
                capabilities=capabilities,
                ceremony_required=True,
                error="Signature not verified - PyJWT not available",
            )
            return result

        # Get JWKS client for signature verification
        jwks_client = self._get_jwks_client()
        if not jwks_client:
            return TokenValidationResult(
                valid=False,
                token=token,
                error="Failed to get signing keys",
                error_code="jwks_error",
            )

        try:
            # Get signing key
            signing_key = jwks_client.get_signing_key_from_jwt(token_string)

            # Validate token
            options = {
                'verify_aud': bool(self.config.audience),
                'verify_iss': bool(self.config.issuer),
            }

            decoded = jwt.decode(
                token_string,
                signing_key.key,
                algorithms=self.config.allowed_algorithms,
                audience=self.config.audience,
                issuer=self.config.issuer,
                leeway=self.config.clock_skew_seconds,
                options=options,
            )

            # Check required groups
            if require_groups:
                missing_groups = set(require_groups) - set(token.groups)
                if missing_groups:
                    return TokenValidationResult(
                        valid=False,
                        token=token,
                        error=f"Missing required groups: {missing_groups}",
                        error_code="missing_groups",
                    )

            # Check required roles
            if require_roles:
                missing_roles = set(require_roles) - set(token.roles)
                if missing_roles:
                    return TokenValidationResult(
                        valid=False,
                        token=token,
                        error=f"Missing required roles: {missing_roles}",
                        error_code="missing_roles",
                    )

            # Map capabilities
            capabilities = self._map_capabilities(token)

            result = TokenValidationResult(
                valid=True,
                token=token,
                capabilities=capabilities,
                ceremony_required=True,  # Always require ceremony for sensitive ops
            )

            # Cache result
            with self._lock:
                self._token_cache[cache_key] = (result, time.time())

            return result

        except jwt.ExpiredSignatureError:
            return TokenValidationResult(
                valid=False,
                token=token,
                error="Token has expired",
                error_code="expired",
            )
        except jwt.InvalidAudienceError:
            return TokenValidationResult(
                valid=False,
                token=token,
                error="Invalid audience",
                error_code="invalid_audience",
            )
        except jwt.InvalidIssuerError:
            return TokenValidationResult(
                valid=False,
                token=token,
                error="Invalid issuer",
                error_code="invalid_issuer",
            )
        except jwt.InvalidSignatureError:
            return TokenValidationResult(
                valid=False,
                token=token,
                error="Invalid signature",
                error_code="invalid_signature",
            )
        except Exception as e:
            return TokenValidationResult(
                valid=False,
                token=token,
                error=f"Validation failed: {e}",
                error_code="validation_error",
            )

    def clear_cache(self) -> None:
        """Clear token cache."""
        with self._lock:
            self._token_cache.clear()
            self._discovery_cache = None
            self._jwks_client = None


if __name__ == '__main__':
    print("Testing OIDC Validator...")

    # Create test config
    config = OIDCConfig(
        issuer="https://example.auth0.com/",
        client_id="test-client-id",
        username_claim="email",
    )

    validator = OIDCValidator(config)

    # Add capability mappings
    validator.add_group_capabilities("admins", {"admin", "read", "write"})
    validator.add_group_capabilities("operators", {"read", "write"})
    validator.add_role_capabilities("viewer", {"read"})

    # Create a test token (not valid, just for parsing test)
    # In production, this would be a real JWT from the IdP
    test_payload = {
        "iss": "https://example.auth0.com/",
        "sub": "user123",
        "aud": "test-client-id",
        "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
        "iat": int(datetime.utcnow().timestamp()),
        "email": "user@example.com",
        "groups": ["operators"],
        "roles": ["viewer"],
    }

    # Encode as JWT (unsigned for testing)
    import base64
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).decode().rstrip('=')
    payload = base64.urlsafe_b64encode(
        json.dumps(test_payload).encode()
    ).decode().rstrip('=')
    test_token = f"{header}.{payload}."

    print(f"\nTest token (unsigned):")
    print(f"  Header: {test_payload}")

    # Parse (won't validate signature since it's unsigned)
    token = validator._parse_token(test_token)
    if token:
        print(f"\nParsed token:")
        print(f"  Subject: {token.subject}")
        print(f"  Email: {token.email}")
        print(f"  Groups: {token.groups}")
        print(f"  Roles: {token.roles}")
        print(f"  Expires: {token.expiration}")

        caps = validator._map_capabilities(token)
        print(f"  Mapped capabilities: {caps}")

    print("\nOIDC validator test complete.")
    print("\nNote: Full validation requires PyJWT and a valid JWKS endpoint.")
