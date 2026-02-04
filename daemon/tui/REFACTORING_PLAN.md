# TUI Dashboard Refactoring Plan

**Status:** PLANNED
**Priority:** HIGH
**Reason:** `dashboard.py` is 12,647 lines (548KB) - unmaintainable monolith

## Current Structure (Single File)

```
dashboard.py (12,647 lines)
├── Data Models (lines 86-136)
│   ├── PanelType
│   ├── DashboardEvent
│   ├── DashboardAlert
│   └── SandboxStatus
├── Colors (lines 138-314)
│   └── Colors class
├── Weather Effects (lines 316-1131)
│   ├── WeatherMode
│   └── MatrixRain
├── Backdrop (lines 1132-1357)
│   └── TunnelBackdrop
├── Scene (lines 1358-8371)
│   └── AlleyScene (~7000 lines!)
├── Creatures (lines 8372-8843)
│   ├── LightningBolt
│   ├── AlleyRat
│   └── LurkingShadow
├── Client (lines 8844-9794)
│   └── DashboardClient
└── Dashboard (lines 9795-12647)
    ├── Dashboard class
    └── run_dashboard()
```

## Proposed Module Structure

```
daemon/tui/
├── __init__.py          # Re-export Dashboard, run_dashboard
├── models.py            # Data classes (~60 lines) [CREATED]
├── colors.py            # Color definitions (~200 lines) [CREATED]
├── weather.py           # WeatherMode, MatrixRain (~820 lines)
├── backdrop.py          # TunnelBackdrop (~230 lines)
├── scene.py             # AlleyScene (~7000 lines)
├── creatures.py         # LightningBolt, AlleyRat, LurkingShadow (~470 lines)
├── client.py            # DashboardClient (~950 lines)
├── dashboard.py         # Dashboard class, run_dashboard (~2900 lines)
└── REFACTORING_PLAN.md  # This document
```

## Migration Strategy

### Phase 1: Create New Modules (LOW RISK)
- [x] Create `models.py` with data classes
- [x] Create `colors.py` with color definitions
- [ ] Create `weather.py` with weather effects
- [ ] Create `backdrop.py` with tunnel backdrop
- [ ] Create `creatures.py` with animation creatures
- [ ] Create `client.py` with DashboardClient

### Phase 2: Update Imports (MEDIUM RISK)
- [ ] Update `dashboard.py` to import from new modules
- [ ] Remove duplicate definitions from `dashboard.py`
- [ ] Update `__init__.py` with re-exports
- [ ] Ensure backward compatibility

### Phase 3: Extract Scene (HIGH RISK)
- [ ] Create `scene.py` with AlleyScene
- [ ] This is the largest component (~7000 lines)
- [ ] Requires careful testing of visual output

### Phase 4: Testing & Validation
- [ ] Run existing TUI tests
- [ ] Manual testing of visual output
- [ ] Performance testing (frame rate, memory)
- [ ] Cross-platform testing (Linux, Windows, macOS)

## Benefits After Refactoring

1. **Maintainability:** Each module has single responsibility
2. **Testability:** Smaller units can be tested in isolation
3. **Code Navigation:** Easier to find and understand components
4. **Parallel Development:** Multiple developers can work on different modules
5. **Memory Efficiency:** Only load needed modules

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Import cycles | HIGH | Careful dependency ordering |
| Visual regression | MEDIUM | Screenshot comparison tests |
| Performance regression | MEDIUM | Frame rate benchmarking |
| Windows compatibility | LOW | Existing tests cover this |

## Completed Work

The following modules have been created:

| Module | Contents | Lines | Status |
|--------|----------|-------|--------|
| **models.py** | PanelType, DashboardEvent, DashboardAlert, SandboxStatus | ~60 | Complete |
| **colors.py** | Colors class with all color pair definitions | ~200 | Complete |
| **weather.py** | WeatherMode enum, MatrixRain particle system | ~820 | Complete |
| **backdrop.py** | TunnelBackdrop 3D tunnel effect | ~230 | Complete |
| **creatures.py** | LightningBolt, AlleyRat, LurkingShadow | ~470 | Complete |

**Remaining to extract:**
- **client.py** - DashboardClient (~950 lines)
- **scene.py** - AlleyScene (~7000 lines) - largest component

These modules are ready for integration but dashboard.py has not yet been updated
to use them (to avoid breaking changes during this phase).

## Integration Strategy

When integrating, update dashboard.py imports like this:

```python
# Replace local class definitions with imports
from .models import PanelType, DashboardEvent, DashboardAlert, SandboxStatus
from .colors import Colors
from .weather import WeatherMode, MatrixRain
from .backdrop import TunnelBackdrop
from .creatures import LightningBolt, AlleyRat, LurkingShadow
```

## Next Steps

1. Extract DashboardClient to client.py
2. Extract AlleyScene to scene.py (largest component)
3. Update dashboard.py imports incrementally
4. Add integration tests for modular structure
5. Update __init__.py for backward compatibility
