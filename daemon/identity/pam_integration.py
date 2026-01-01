"""
PAM Integration for Identity Federation

Integrates with Linux PAM (Pluggable Authentication Modules) for:
- System user authentication
- Session management
- Password validation

IMPORTANT: PAM authentication is ADVISORY only. Ceremonies are still
required for all sensitive operations regardless of PAM success.
"""

import ctypes
import ctypes.util
import logging
import os
import pwd
import grp
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum, Enum
from typing import Dict, List, Optional, Set, Any, Tuple, Callable

logger = logging.getLogger(__name__)

# Try to load PAM library
_pam_lib = None
try:
    _lib_path = ctypes.util.find_library('pam')
    if _lib_path:
        _pam_lib = ctypes.CDLL(_lib_path)
        PAM_AVAILABLE = True
    else:
        PAM_AVAILABLE = False
        logger.warning("libpam not found - PAM integration disabled")
except Exception as e:
    PAM_AVAILABLE = False
    logger.warning(f"Failed to load libpam: {e}")


class PAMReturnCode(IntEnum):
    """PAM return codes."""
    SUCCESS = 0
    OPEN_ERR = 1
    SYMBOL_ERR = 2
    SERVICE_ERR = 3
    SYSTEM_ERR = 4
    BUF_ERR = 5
    PERM_DENIED = 6
    AUTH_ERR = 7
    CRED_INSUFFICIENT = 8
    AUTHINFO_UNAVAIL = 9
    USER_UNKNOWN = 10
    MAXTRIES = 11
    NEW_AUTHTOK_REQD = 12
    ACCT_EXPIRED = 13
    SESSION_ERR = 14
    CRED_UNAVAIL = 15
    CRED_EXPIRED = 16
    CRED_ERR = 17
    NO_MODULE_DATA = 18
    CONV_ERR = 19
    AUTHTOK_ERR = 20
    AUTHTOK_RECOVERY_ERR = 21
    AUTHTOK_LOCK_BUSY = 22
    AUTHTOK_DISABLE_AGING = 23
    TRY_AGAIN = 24
    IGNORE = 25
    ABORT = 26
    AUTHTOK_EXPIRED = 27


class PAMMessageStyle(IntEnum):
    """PAM conversation message styles."""
    PROMPT_ECHO_OFF = 1
    PROMPT_ECHO_ON = 2
    ERROR_MSG = 3
    TEXT_INFO = 4


@dataclass
class PAMConfig:
    """Configuration for PAM integration."""
    # Service name (maps to /etc/pam.d/<service>)
    service_name: str = "boundary-daemon"

    # Fallback service if custom service doesn't exist
    fallback_service: str = "login"

    # Group mappings
    admin_groups: List[str] = field(default_factory=lambda: ["wheel", "sudo", "admin"])
    operator_groups: List[str] = field(default_factory=lambda: ["operators", "staff"])

    # Session settings
    establish_session: bool = False  # Whether to call pam_open_session

    # Timeout
    auth_timeout_seconds: int = 30


@dataclass
class PAMResult:
    """Result of PAM authentication."""
    success: bool
    return_code: PAMReturnCode
    username: str
    error_message: Optional[str] = None

    # User info
    uid: Optional[int] = None
    gid: Optional[int] = None
    groups: List[str] = field(default_factory=list)
    home_dir: Optional[str] = None
    shell: Optional[str] = None

    # Mapped capabilities (advisory only)
    capabilities: Set[str] = field(default_factory=set)

    # Ceremony requirements
    ceremony_required: bool = True  # Always True for sensitive ops


@dataclass
class PAMSession:
    """PAM session handle."""
    username: str
    service: str
    handle: Any = None
    opened: bool = False
    opened_at: Optional[datetime] = None


class PAMConversation:
    """PAM conversation handler for password prompts."""

    def __init__(self, password: str):
        self.password = password
        self.messages: List[str] = []

    def __call__(self, num_msg: int, messages, responses, app_data):
        """Handle PAM conversation callback."""
        # This is a simplified implementation
        # Real implementation would handle different message types
        return PAMReturnCode.SUCCESS


class PAMAuthenticator:
    """
    Authenticates users via PAM.

    Usage:
        auth = PAMAuthenticator(PAMConfig(
            service_name="boundary-daemon",
            admin_groups=["wheel", "sudo"],
        ))

        result = auth.authenticate("username", "password")
        if result.success:
            print(f"Authenticated: {result.username}")
            print(f"Groups: {result.groups}")
            print(f"Capabilities: {result.capabilities}")
            # Note: result.ceremony_required is always True
    """

    def __init__(self, config: PAMConfig):
        self.config = config
        self._lock = threading.Lock()
        self._sessions: Dict[str, PAMSession] = {}

        # Capability mappings
        self._group_capabilities: Dict[str, Set[str]] = {}

        # Default mappings from config
        for group in config.admin_groups:
            self._group_capabilities[group] = {"admin", "read", "write", "delete"}
        for group in config.operator_groups:
            self._group_capabilities[group] = {"read", "write"}

    def add_group_capabilities(self, group: str, capabilities: Set[str]) -> None:
        """Map a system group to capabilities."""
        self._group_capabilities[group] = capabilities

    def _get_user_info(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user info from passwd database."""
        try:
            pw = pwd.getpwnam(username)
            groups = []

            # Get primary group
            try:
                primary_group = grp.getgrgid(pw.pw_gid).gr_name
                groups.append(primary_group)
            except KeyError:
                pass

            # Get supplementary groups
            try:
                for group in grp.getgrall():
                    if username in group.gr_mem:
                        if group.gr_name not in groups:
                            groups.append(group.gr_name)
            except Exception:
                pass

            return {
                'username': pw.pw_name,
                'uid': pw.pw_uid,
                'gid': pw.pw_gid,
                'home': pw.pw_dir,
                'shell': pw.pw_shell,
                'gecos': pw.pw_gecos,
                'groups': groups,
            }
        except KeyError:
            return None

    def _map_capabilities(self, groups: List[str]) -> Set[str]:
        """Map groups to capabilities."""
        capabilities: Set[str] = set()
        for group in groups:
            if group in self._group_capabilities:
                capabilities.update(self._group_capabilities[group])
        return capabilities

    def authenticate(
        self,
        username: str,
        password: str,
    ) -> PAMResult:
        """
        Authenticate a user via PAM.

        Args:
            username: Username to authenticate
            password: Password to verify

        Returns:
            PAMResult with authentication status
        """
        if not PAM_AVAILABLE:
            return PAMResult(
                success=False,
                return_code=PAMReturnCode.SERVICE_ERR,
                username=username,
                error_message="PAM not available",
                ceremony_required=True,
            )

        # Get user info first
        user_info = self._get_user_info(username)
        if not user_info:
            return PAMResult(
                success=False,
                return_code=PAMReturnCode.USER_UNKNOWN,
                username=username,
                error_message="User not found",
                ceremony_required=True,
            )

        # Use Python's crypt module for simple auth
        # (Full PAM integration would use libpam directly)
        try:
            import crypt
            import spwd

            # Try to read shadow password
            try:
                sp = spwd.getspnam(username)
                stored_hash = sp.sp_pwdp
            except (KeyError, PermissionError):
                # Can't read shadow, try passwd
                try:
                    pw = pwd.getpwnam(username)
                    stored_hash = pw.pw_passwd
                    if stored_hash == 'x':
                        # Password in shadow file, need root
                        return PAMResult(
                            success=False,
                            return_code=PAMReturnCode.PERM_DENIED,
                            username=username,
                            error_message="Cannot read shadow passwords (need root)",
                            ceremony_required=True,
                        )
                except KeyError:
                    return PAMResult(
                        success=False,
                        return_code=PAMReturnCode.USER_UNKNOWN,
                        username=username,
                        error_message="User not found",
                        ceremony_required=True,
                    )

            # Verify password
            if stored_hash in ('*', '!', '!!', ''):
                return PAMResult(
                    success=False,
                    return_code=PAMReturnCode.AUTH_ERR,
                    username=username,
                    error_message="Account locked or no password",
                    ceremony_required=True,
                )

            computed_hash = crypt.crypt(password, stored_hash)
            if computed_hash != stored_hash:
                return PAMResult(
                    success=False,
                    return_code=PAMReturnCode.AUTH_ERR,
                    username=username,
                    error_message="Invalid password",
                    ceremony_required=True,
                )

            # Authentication successful
            capabilities = self._map_capabilities(user_info['groups'])

            return PAMResult(
                success=True,
                return_code=PAMReturnCode.SUCCESS,
                username=username,
                uid=user_info['uid'],
                gid=user_info['gid'],
                groups=user_info['groups'],
                home_dir=user_info['home'],
                shell=user_info['shell'],
                capabilities=capabilities,
                ceremony_required=True,  # ALWAYS require ceremony
            )

        except ImportError:
            return PAMResult(
                success=False,
                return_code=PAMReturnCode.SERVICE_ERR,
                username=username,
                error_message="crypt/spwd modules not available",
                ceremony_required=True,
            )
        except Exception as e:
            return PAMResult(
                success=False,
                return_code=PAMReturnCode.SYSTEM_ERR,
                username=username,
                error_message=str(e),
                ceremony_required=True,
            )

    def check_user_exists(self, username: str) -> bool:
        """Check if a user exists in the system."""
        return self._get_user_info(username) is not None

    def get_user_groups(self, username: str) -> List[str]:
        """Get groups for a user."""
        info = self._get_user_info(username)
        return info['groups'] if info else []

    def validate_group_membership(
        self,
        username: str,
        required_groups: List[str],
    ) -> Tuple[bool, List[str]]:
        """
        Check if user is member of required groups.

        Args:
            username: Username to check
            required_groups: List of required group names

        Returns:
            (is_member, missing_groups)
        """
        user_groups = set(self.get_user_groups(username))
        required = set(required_groups)
        missing = list(required - user_groups)
        return (len(missing) == 0, missing)


class PAMSessionManager:
    """
    Manages PAM sessions for authenticated users.

    Note: Sessions are informational only and do not
    bypass ceremony requirements for sensitive operations.
    """

    def __init__(self, config: PAMConfig):
        self.config = config
        self._sessions: Dict[str, PAMSession] = {}
        self._lock = threading.Lock()

    def create_session(
        self,
        username: str,
        auth_result: PAMResult,
    ) -> Optional[PAMSession]:
        """
        Create a session for an authenticated user.

        Args:
            username: Username
            auth_result: Successful PAMResult

        Returns:
            PAMSession or None
        """
        if not auth_result.success:
            return None

        session = PAMSession(
            username=username,
            service=self.config.service_name,
            opened=True,
            opened_at=datetime.utcnow(),
        )

        with self._lock:
            self._sessions[username] = session

        logger.info(f"Created session for user: {username}")
        return session

    def get_session(self, username: str) -> Optional[PAMSession]:
        """Get existing session for user."""
        with self._lock:
            return self._sessions.get(username)

    def close_session(self, username: str) -> bool:
        """Close a user's session."""
        with self._lock:
            session = self._sessions.pop(username, None)
            if session:
                session.opened = False
                logger.info(f"Closed session for user: {username}")
                return True
            return False

    def close_all_sessions(self) -> int:
        """Close all sessions."""
        with self._lock:
            count = len(self._sessions)
            self._sessions.clear()
            return count


if __name__ == '__main__':
    print("Testing PAM Integration...")

    config = PAMConfig(
        service_name="boundary-daemon",
        admin_groups=["wheel", "sudo", "admin"],
        operator_groups=["operators", "staff"],
    )

    auth = PAMAuthenticator(config)

    # Test user info lookup
    current_user = os.getenv('USER', 'nobody')
    print(f"\nCurrent user: {current_user}")

    if auth.check_user_exists(current_user):
        groups = auth.get_user_groups(current_user)
        print(f"Groups: {groups}")

        caps = auth._map_capabilities(groups)
        print(f"Mapped capabilities: {caps}")
    else:
        print("User not found in system")

    print("\nNote: Actual password authentication requires appropriate permissions.")
    print("IMPORTANT: ceremony_required is ALWAYS True for sensitive operations.")
    print("\nPAM integration test complete.")
