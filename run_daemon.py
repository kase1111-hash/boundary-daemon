#!/usr/bin/env python3
"""
Boundary Daemon Entry Point

This script serves as the main entry point for both:
- Running as a module: python -m daemon.boundary_daemon
- Running as a standalone executable: boundary-daemon.exe

It handles the import path setup required for PyInstaller builds.
"""

import sys
import os

def setup_path():
    """Setup Python path for standalone execution."""
    # Get the directory where this script is located
    if getattr(sys, 'frozen', False):
        # Running as compiled executable
        base_path = sys._MEIPASS
    else:
        # Running as script
        base_path = os.path.dirname(os.path.abspath(__file__))

    # Add base path to sys.path if not already there
    if base_path not in sys.path:
        sys.path.insert(0, base_path)

    # Also add parent directory for local development
    parent_path = os.path.dirname(base_path)
    if parent_path not in sys.path:
        sys.path.insert(0, parent_path)


def main():
    """Main entry point."""
    setup_path()

    # Now import and run the daemon
    try:
        from daemon.boundary_daemon import BoundaryDaemon, BoundaryMode
    except ImportError as e:
        print(f"Import error: {e}")
        print("Attempting alternative import...")
        try:
            # Try direct import for frozen executable
            import daemon.boundary_daemon as bd
            BoundaryDaemon = bd.BoundaryDaemon
            BoundaryMode = bd.BoundaryMode
        except ImportError as e2:
            print(f"Failed to import daemon: {e2}")
            sys.exit(1)

    import argparse

    parser = argparse.ArgumentParser(description='Boundary Daemon - Trust Boundary Enforcement')
    parser.add_argument('--mode', choices=['open', 'restricted', 'trusted', 'airgap', 'coldroom', 'lockdown'],
                        default='open', help='Initial boundary mode')
    parser.add_argument('--log-dir', default='./logs', help='Directory for log files')
    parser.add_argument('--skip-integrity-check', action='store_true',
                        help='Skip integrity verification (DANGEROUS - dev only)')

    args = parser.parse_args()

    # Parse mode
    mode_map = {
        'open': BoundaryMode.OPEN,
        'restricted': BoundaryMode.RESTRICTED,
        'trusted': BoundaryMode.TRUSTED,
        'airgap': BoundaryMode.AIRGAP,
        'coldroom': BoundaryMode.COLDROOM,
        'lockdown': BoundaryMode.LOCKDOWN,
    }
    initial_mode = mode_map.get(args.mode, BoundaryMode.OPEN)

    # Create and run daemon
    print("=" * 70)
    print("Boundary Daemon - Trust Boundary Enforcement System")
    print("=" * 70)

    try:
        daemon = BoundaryDaemon(
            log_dir=args.log_dir,
            initial_mode=initial_mode,
            skip_integrity_check=args.skip_integrity_check,
        )

        daemon.start()

        # Keep running until interrupted
        import time
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

        daemon.stop()

    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
