"""
Identity Manager - Unified Identity Federation

Provides a unified interface for all identity sources:
- OIDC tokens (SSO)
- LDAP groups (enterprise directory)
- PAM (system authentication)

IMPORTANT: All external identity is ADVISORY only. Ceremonies are
still required for all sensitive operations regardless of identity.
"""

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Any, Union

logger = logging.getLogger(__name__)


class IdentitySource(Enum):
    """Source of identity assertion."""
    OIDC = "oidc"
    LDAP = "ldap"
    PAM = "pam"
    LOCAL = "local"
    UNKNOWN = "unknown"


@dataclass
class FederatedIdentity:
    """
    Represents a federated identity from any source.

    IMPORTANT: This identity is ADVISORY. The ceremony_required
    field should ALWAYS be True for sensitive operations.
    """
    # Identity info
    username: str
    source: IdentitySource
    source_id: Optional[str] = None  # Provider-specific ID

    # Verification status
    verified: bool = False
    verified_at: Optional[datetime] = None

    # User attributes
    email: Optional[str] = None
    display_name: Optional[str] = None
    groups: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)

    # Mapped capabilities (ADVISORY only)
    capabilities: Set[str] = field(default_factory=set)

    # Session info
    session_id: Optional[str] = None
    expires_at: Optional[datetime] = None

    # CRITICAL: Ceremony requirements
    ceremony_required: bool = True  # ALWAYS True for sensitive ops
    ceremony_type: Optional[str] = None

    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        """Check if identity assertion has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def has_capability(self, capability: str) -> bool:
        """Check if identity has a capability (advisory only)."""
        return capability in self.capabilities

    def has_any_capability(self, capabilities: Set[str]) -> bool:
        """Check if identity has any of the capabilities."""
        return bool(self.capabilities & capabilities)

    def has_all_capabilities(self, capabilities: Set[str]) -> bool:
        """Check if identity has all capabilities."""
        return capabilities <= self.capabilities


@dataclass
class IdentityConfig:
    """Configuration for identity manager."""
    # Enabled sources
    enable_oidc: bool = True
    enable_ldap: bool = True
    enable_pam: bool = True

    # Source priority (first match wins)
    source_priority: List[IdentitySource] = field(
        default_factory=lambda: [
            IdentitySource.OIDC,
            IdentitySource.LDAP,
            IdentitySource.PAM,
        ]
    )

    # Capability aggregation
    aggregate_capabilities: bool = True  # Combine from all sources

    # Cache settings
    cache_identities_seconds: int = 300

    # Ceremony settings
    sensitive_capabilities: Set[str] = field(
        default_factory=lambda: {
            "admin", "delete", "lockdown", "ceremony_override",
            "key_rotation", "mode_change", "export",
        }
    )


class IdentityManager:
    """
    Unified identity federation manager.

    Aggregates identity information from multiple sources and
    maps to local capabilities. All identity is advisory -
    ceremonies are required for sensitive operations.

    Usage:
        manager = IdentityManager(IdentityConfig())

        # Add identity sources
        manager.set_oidc_validator(oidc_validator)
        manager.set_ldap_mapper(ldap_mapper)
        manager.set_pam_authenticator(pam_auth)

        # Authenticate via any source
        identity = manager.authenticate_oidc(token)
        identity = manager.authenticate_ldap(username)
        identity = manager.authenticate_pam(username, password)

        # Or get from cache
        identity = manager.get_identity(username)
    """

    def __init__(self, config: IdentityConfig):
        self.config = config
        self._lock = threading.Lock()

        # Identity sources
        self._oidc_validator = None
        self._ldap_mapper = None
        self._pam_authenticator = None

        # Identity cache
        self._identity_cache: Dict[str, FederatedIdentity] = {}

        # Capability aggregation
        self._capability_overrides: Dict[str, Set[str]] = {}

    def set_oidc_validator(self, validator) -> None:
        """Set OIDC validator instance."""
        self._oidc_validator = validator

    def set_ldap_mapper(self, mapper) -> None:
        """Set LDAP mapper instance."""
        self._ldap_mapper = mapper

    def set_pam_authenticator(self, authenticator) -> None:
        """Set PAM authenticator instance."""
        self._pam_authenticator = authenticator

    def add_capability_override(
        self,
        username: str,
        capabilities: Set[str],
    ) -> None:
        """Add local capability overrides for a user."""
        self._capability_overrides[username.lower()] = capabilities

    def _determine_ceremony_type(
        self,
        capabilities: Set[str],
    ) -> Optional[str]:
        """Determine required ceremony type based on capabilities."""
        sensitive = self.config.sensitive_capabilities & capabilities

        if not sensitive:
            return None

        # Determine ceremony type by most sensitive capability
        if "admin" in sensitive or "lockdown" in sensitive:
            return "ELEVATED_ACCESS"
        if "delete" in sensitive or "export" in sensitive:
            return "DATA_OPERATION"
        if "mode_change" in sensitive:
            return "MODE_OVERRIDE"
        if "key_rotation" in sensitive:
            return "KEY_CEREMONY"

        return "STANDARD"

    def authenticate_oidc(
        self,
        token: str,
        require_groups: Optional[List[str]] = None,
    ) -> Optional[FederatedIdentity]:
        """
        Authenticate via OIDC token.

        Args:
            token: OIDC/JWT token string
            require_groups: Optional required groups

        Returns:
            FederatedIdentity or None
        """
        if not self.config.enable_oidc or not self._oidc_validator:
            return None

        result = self._oidc_validator.validate_token(
            token,
            require_groups=require_groups,
        )

        if not result.valid or not result.token:
            return None

        identity = FederatedIdentity(
            username=result.token.username or result.token.subject,
            source=IdentitySource.OIDC,
            source_id=result.token.subject,
            verified=True,
            verified_at=datetime.utcnow(),
            email=result.token.email,
            display_name=result.token.name,
            groups=result.token.groups,
            roles=result.token.roles,
            capabilities=result.capabilities,
            expires_at=result.token.expiration,
            ceremony_required=True,  # ALWAYS
            metadata={
                'issuer': result.token.issuer,
                'jwt_id': result.token.jwt_id,
            },
        )

        # Add local overrides
        self._apply_overrides(identity)

        # Determine ceremony type
        identity.ceremony_type = self._determine_ceremony_type(
            identity.capabilities
        )

        # Cache
        self._cache_identity(identity)

        return identity

    def authenticate_ldap(
        self,
        username: str,
        require_groups: Optional[List[str]] = None,
    ) -> Optional[FederatedIdentity]:
        """
        Get identity from LDAP.

        Args:
            username: Username to lookup
            require_groups: Optional required groups

        Returns:
            FederatedIdentity or None
        """
        if not self.config.enable_ldap or not self._ldap_mapper:
            return None

        caps = self._ldap_mapper.get_user_capabilities(username)
        if not caps:
            return None

        # Check required groups
        if require_groups:
            is_member, missing = self._ldap_mapper.validate_user_groups(
                username, require_groups
            )
            if not is_member:
                logger.warning(
                    f"User {username} missing required groups: {missing}"
                )
                return None

        identity = FederatedIdentity(
            username=caps.username,
            source=IdentitySource.LDAP,
            source_id=caps.user_dn,
            verified=True,
            verified_at=datetime.utcnow(),
            email=caps.email,
            groups=caps.groups,
            capabilities=caps.capabilities,
            ceremony_required=True,  # ALWAYS
            metadata={
                'dn': caps.user_dn,
            },
        )

        # Add local overrides
        self._apply_overrides(identity)

        # Determine ceremony type
        identity.ceremony_type = self._determine_ceremony_type(
            identity.capabilities
        )

        # Cache
        self._cache_identity(identity)

        return identity

    def authenticate_pam(
        self,
        username: str,
        password: str,
        require_groups: Optional[List[str]] = None,
    ) -> Optional[FederatedIdentity]:
        """
        Authenticate via PAM.

        Args:
            username: Username
            password: Password
            require_groups: Optional required groups

        Returns:
            FederatedIdentity or None
        """
        if not self.config.enable_pam or not self._pam_authenticator:
            return None

        result = self._pam_authenticator.authenticate(username, password)
        if not result.success:
            return None

        # Check required groups
        if require_groups:
            is_member, missing = self._pam_authenticator.validate_group_membership(
                username, require_groups
            )
            if not is_member:
                logger.warning(
                    f"User {username} missing required groups: {missing}"
                )
                return None

        identity = FederatedIdentity(
            username=result.username,
            source=IdentitySource.PAM,
            source_id=str(result.uid),
            verified=True,
            verified_at=datetime.utcnow(),
            groups=result.groups,
            capabilities=result.capabilities,
            ceremony_required=True,  # ALWAYS
            metadata={
                'uid': result.uid,
                'gid': result.gid,
                'home': result.home_dir,
            },
        )

        # Add local overrides
        self._apply_overrides(identity)

        # Determine ceremony type
        identity.ceremony_type = self._determine_ceremony_type(
            identity.capabilities
        )

        # Cache
        self._cache_identity(identity)

        return identity

    def _apply_overrides(self, identity: FederatedIdentity) -> None:
        """Apply local capability overrides."""
        overrides = self._capability_overrides.get(identity.username.lower())
        if overrides:
            identity.capabilities.update(overrides)

    def _cache_identity(self, identity: FederatedIdentity) -> None:
        """Cache an identity."""
        with self._lock:
            self._identity_cache[identity.username.lower()] = identity

    def get_identity(self, username: str) -> Optional[FederatedIdentity]:
        """Get cached identity for username."""
        with self._lock:
            identity = self._identity_cache.get(username.lower())
            if identity and not identity.is_expired:
                return identity
            return None

    def get_aggregate_identity(
        self,
        username: str,
        oidc_token: Optional[str] = None,
        password: Optional[str] = None,
    ) -> Optional[FederatedIdentity]:
        """
        Get identity aggregated from all available sources.

        If aggregate_capabilities is True, combines capabilities
        from all sources where the user is found.

        Args:
            username: Username
            oidc_token: Optional OIDC token
            password: Optional password for PAM

        Returns:
            Aggregated FederatedIdentity or None
        """
        identities: List[FederatedIdentity] = []

        # Try each source in priority order
        for source in self.config.source_priority:
            identity = None

            if source == IdentitySource.OIDC and oidc_token:
                identity = self.authenticate_oidc(oidc_token)
            elif source == IdentitySource.LDAP:
                identity = self.authenticate_ldap(username)
            elif source == IdentitySource.PAM and password:
                identity = self.authenticate_pam(username, password)

            if identity:
                identities.append(identity)
                if not self.config.aggregate_capabilities:
                    # Return first match
                    return identity

        if not identities:
            return None

        # Aggregate capabilities
        primary = identities[0]

        if len(identities) > 1:
            for other in identities[1:]:
                primary.capabilities.update(other.capabilities)
                primary.groups.extend(
                    g for g in other.groups if g not in primary.groups
                )
                primary.roles.extend(
                    r for r in other.roles if r not in primary.roles
                )

            primary.metadata['aggregated_sources'] = [
                i.source.value for i in identities
            ]

        # Re-determine ceremony type with aggregated caps
        primary.ceremony_type = self._determine_ceremony_type(
            primary.capabilities
        )

        return primary

    def clear_cache(self) -> None:
        """Clear identity cache."""
        with self._lock:
            self._identity_cache.clear()

    def revoke_identity(self, username: str) -> bool:
        """Revoke cached identity for user."""
        with self._lock:
            return self._identity_cache.pop(username.lower(), None) is not None


if __name__ == '__main__':
    print("Testing Identity Manager...")

    config = IdentityConfig(
        enable_oidc=True,
        enable_ldap=True,
        enable_pam=True,
        aggregate_capabilities=True,
    )

    manager = IdentityManager(config)

    # Add local capability override
    manager.add_capability_override("testuser", {"read", "write"})

    # Create a mock identity
    test_identity = FederatedIdentity(
        username="testuser",
        source=IdentitySource.LOCAL,
        verified=True,
        verified_at=datetime.utcnow(),
        groups=["operators"],
        capabilities={"read", "write"},
        ceremony_required=True,
    )

    print(f"\nTest identity:")
    print(f"  Username: {test_identity.username}")
    print(f"  Source: {test_identity.source.value}")
    print(f"  Capabilities: {test_identity.capabilities}")
    print(f"  Ceremony required: {test_identity.ceremony_required}")
    print(f"  Has 'read': {test_identity.has_capability('read')}")
    print(f"  Has 'admin': {test_identity.has_capability('admin')}")

    # Test ceremony type determination
    admin_caps = {"admin", "read", "write"}
    ceremony_type = manager._determine_ceremony_type(admin_caps)
    print(f"\nCeremony for {admin_caps}: {ceremony_type}")

    print("\nIMPORTANT: ceremony_required is ALWAYS True for sensitive operations.")
    print("\nIdentity manager test complete.")
