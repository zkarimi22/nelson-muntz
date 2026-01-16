#!/bin/bash
#
# Nelson Muntz Stop Hook
# Implements the adversarial loop - keeps attacking until no issues found
#
# Exit codes:
#   0 = Allow exit (no issues or max iterations reached)
#   2 = Block exit and continue loop (issues still found)
#

set -e

# Configuration
ITERATION_FILE=".nelson_iterations"
STATE_FILE=".nelson_state.json"
MAX_ITERATIONS="${NELSON_MAX_ITERATIONS:-15}"

# Get current iteration count
CURRENT_ITERATION=0
if [ -f "$ITERATION_FILE" ]; then
    CURRENT_ITERATION=$(cat "$ITERATION_FILE" 2>/dev/null || echo 0)
fi

# Check if we've hit max iterations
if [ "$CURRENT_ITERATION" -ge "$MAX_ITERATIONS" ]; then
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "Nelson hit max iterations ($MAX_ITERATIONS). Giving up... for now."
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    # Cleanup
    rm -f "$ITERATION_FILE"
    rm -f "$STATE_FILE"

    exit 0  # Allow exit
fi

# Check if Nelson found issues in the output
# The command output contains "NELSON FOUND:" when issues are discovered
if [ -n "$CLAUDE_OUTPUT" ]; then
    if echo "$CLAUDE_OUTPUT" | grep -q "NELSON FOUND:"; then
        # Issues found - increment counter and continue loop
        NEXT_ITERATION=$((CURRENT_ITERATION + 1))
        echo "$NEXT_ITERATION" > "$ITERATION_FILE"

        echo ""
        echo "───────────────────────────────────────────────────────────────"
        echo "Ha-ha! Nelson found issues! Re-attacking... (Iteration $NEXT_ITERATION/$MAX_ITERATIONS)"
        echo "───────────────────────────────────────────────────────────────"
        echo ""

        exit 2  # Block exit, continue loop
    fi
fi

# Check if final victory message was displayed
if [ -n "$CLAUDE_OUTPUT" ]; then
    if echo "$CLAUDE_OUTPUT" | grep -q "Nelson Admits Defeat"; then
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "Nelson's attack complete. Your code survived... barely."
        echo "═══════════════════════════════════════════════════════════════"
        echo ""

        # Cleanup
        rm -f "$ITERATION_FILE"
        rm -f "$STATE_FILE"

        exit 0  # Allow exit
    fi
fi

# No explicit markers found - check state file for status
if [ -f "$STATE_FILE" ]; then
    OPEN_ISSUES=$(grep -c '"status": "open"' "$STATE_FILE" 2>/dev/null || echo 0)

    if [ "$OPEN_ISSUES" -gt 0 ]; then
        NEXT_ITERATION=$((CURRENT_ITERATION + 1))
        echo "$NEXT_ITERATION" > "$ITERATION_FILE"

        echo ""
        echo "───────────────────────────────────────────────────────────────"
        echo "Ha-ha! $OPEN_ISSUES issues still open! Re-attacking... (Iteration $NEXT_ITERATION/$MAX_ITERATIONS)"
        echo "───────────────────────────────────────────────────────────────"
        echo ""

        exit 2  # Block exit, continue loop
    fi
fi

# No issues found, cleanup and allow exit
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Nelson found nothing. You win this time... but I'll be back!"
echo "═══════════════════════════════════════════════════════════════"
echo ""

rm -f "$ITERATION_FILE"
rm -f "$STATE_FILE"

exit 0  # Allow exit
