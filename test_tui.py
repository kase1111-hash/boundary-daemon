#!/usr/bin/env python3
"""TUI Integration Test Script."""

import sys
import asyncio
import os
import tempfile
import shutil
import logging

# Suppress verbose logging
logging.disable(logging.WARNING)

os.environ['TERM'] = 'xterm-256color'

async def test_tui():
    """Run TUI integration tests."""
    print("=== TUI Integration Test ===\n")

    # Start daemon
    from daemon.boundary_daemon import BoundaryDaemon
    from daemon.policy_engine import BoundaryMode

    log_dir = tempfile.mkdtemp(prefix='tui_test_')

    try:
        daemon = BoundaryDaemon(
            log_dir=log_dir,
            initial_mode=BoundaryMode.OPEN,
            skip_integrity_check=True
        )
        print(f"Daemon started: {daemon.policy_engine.get_current_mode().name}")

        from tui.app import (
            BoundaryDaemonTUI, DashboardScreen, ModeControlScreen,
            EventLogScreen, TripwireScreen, SettingsScreen,
            ModeIndicator, HealthIndicator
        )

        app = BoundaryDaemonTUI(daemon=daemon)

        async with app.run_test() as pilot:
            # Wait for mount
            await asyncio.sleep(0.5)

            print(f"\nInitial screen: {app.screen.__class__.__name__}")
            print(f"Stack depth: {len(app.screen_stack)}")

            # Test 1: Verify we're on dashboard
            print("\n1. Dashboard Test...")
            if not isinstance(app.screen, DashboardScreen):
                await pilot.press('d')
                await asyncio.sleep(0.3)

            if isinstance(app.screen, DashboardScreen):
                print("   [PASS] On DashboardScreen")

                # Query widgets
                try:
                    mi = app.screen.query_one('#mode-indicator', ModeIndicator)
                    print(f"   [PASS] Mode indicator: {mi.mode}")
                except Exception as e:
                    print(f"   [WARN] Mode indicator query: {e}")
            else:
                print(f"   [FAIL] Expected DashboardScreen, got {app.screen.__class__.__name__}")

            # Test 2: Mode Control
            print("\n2. Mode Control Test...")
            await pilot.press('m')
            await asyncio.sleep(0.3)

            if isinstance(app.screen, ModeControlScreen):
                print("   [PASS] On ModeControlScreen")
            else:
                print(f"   [FAIL] Expected ModeControlScreen, got {app.screen.__class__.__name__}")

            # Test 3: Back to Dashboard
            print("\n3. Return to Dashboard Test...")
            await pilot.press('d')
            await asyncio.sleep(0.3)

            if isinstance(app.screen, DashboardScreen):
                print("   [PASS] Returned to DashboardScreen")
            else:
                print(f"   [FAIL] Expected DashboardScreen, got {app.screen.__class__.__name__}")

            # Test 4: Events
            print("\n4. Event Log Test...")
            await pilot.press('e')
            await asyncio.sleep(0.3)

            if isinstance(app.screen, EventLogScreen):
                print("   [PASS] On EventLogScreen")
            else:
                print(f"   [FAIL] Expected EventLogScreen, got {app.screen.__class__.__name__}")

            # Test 5: Tripwires
            print("\n5. Tripwire Test...")
            await pilot.press('t')
            await asyncio.sleep(0.3)

            if isinstance(app.screen, TripwireScreen):
                print("   [PASS] On TripwireScreen")
            else:
                print(f"   [FAIL] Expected TripwireScreen, got {app.screen.__class__.__name__}")

            # Test 6: Settings
            print("\n6. Settings Test...")
            await pilot.press('s')
            await asyncio.sleep(0.3)

            if isinstance(app.screen, SettingsScreen):
                print("   [PASS] On SettingsScreen")
            else:
                print(f"   [FAIL] Expected SettingsScreen, got {app.screen.__class__.__name__}")

            print("\n=== All Tests Complete ===")

    finally:
        shutil.rmtree(log_dir, ignore_errors=True)


if __name__ == "__main__":
    try:
        asyncio.run(test_tui())
    except Exception as e:
        print(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
