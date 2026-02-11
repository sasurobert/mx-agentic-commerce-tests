#!/usr/bin/env bash
#
# run_all_tests.sh — Full Ecosystem Test Runner
#
# Runs ALL tests across the agentic-payments ecosystem sequentially
# with proper port cleanup, retry logic, and timing.
#
# Usage:
#   ./run_all_tests.sh              # Run everything
#   ./run_all_tests.sh --suites     # Run only chain-sim suites (A-T)
#   ./run_all_tests.sh --offchain   # Run only off-chain suites (U-Y)
#   ./run_all_tests.sh --ts         # Run only TypeScript service tests
#   ./run_all_tests.sh --rust       # Run only mx-8004 Rust SC tests
#   ./run_all_tests.sh --pkg        # Run only package-level tests (pkg_1-9)
#

set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SIM_PORT=8085
MAX_PORT_WAIT=30        # seconds to wait for port release
RETRY_DELAY=5           # seconds before retry
COOLDOWN=3              # seconds between suites

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ─── Results tracking ────────────────────────────────────────────
declare -a RESULTS=()
PASS_COUNT=0
FAIL_COUNT=0
RETRY_COUNT=0

# ─── Helper functions ────────────────────────────────────────────

log_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
}

log_suite() {
    echo -e "\n${BOLD}▸ $1${NC}"
}

log_pass() {
    echo -e "  ${GREEN}✅ PASS${NC} ($1)"
}

log_fail() {
    echo -e "  ${RED}❌ FAIL${NC} ($1)"
}

log_retry() {
    echo -e "  ${YELLOW}🔄 RETRY${NC} ($1)"
}

# Kill all chain-simulator and related test processes
kill_test_processes() {
    pkill -f "mx-chain-simulator-go" 2>/dev/null || true
    # Kill any node processes on test ports (facilitator, relayer, moltbot, MCP)
    for port in $SIM_PORT 3000 3001 3002 3004 4000; do
        lsof -ti:$port 2>/dev/null | xargs kill -9 2>/dev/null || true
    done
}

# Wait until a port is free
wait_for_port_free() {
    local port=$1
    local max_wait=${2:-$MAX_PORT_WAIT}
    local waited=0

    while [ $waited -lt $max_wait ]; do
        if ! nc -z 127.0.0.1 "$port" 2>/dev/null; then
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done

    echo -e "  ${YELLOW}⚠ Port $port still occupied after ${max_wait}s${NC}"
    # Force kill anything on the port
    lsof -ti:"$port" 2>/dev/null | xargs kill -9 2>/dev/null || true
    sleep 2
}

# Run a single test suite with retry logic
# Arguments: $1=name, $2=command, $3=working_dir
run_test() {
    local name="$1"
    local cmd="$2"
    local cwd="${3:-$SCRIPT_DIR}"
    local start_time end_time duration exit_code

    log_suite "$name"

    start_time=$(date +%s)
    set +e
    (cd "$cwd" && eval "$cmd") > /tmp/test_output_$$.log 2>&1
    exit_code=$?
    set -e
    end_time=$(date +%s)
    duration="$((end_time - start_time))s"

    if [ $exit_code -eq 0 ]; then
        log_pass "$duration"
        RESULTS+=("${GREEN}✅${NC} | $name | $duration")
        PASS_COUNT=$((PASS_COUNT + 1))
        return 0
    fi

    # First failure — retry once after cleanup
    log_retry "failed, retrying after cleanup..."
    RETRY_COUNT=$((RETRY_COUNT + 1))

    kill_test_processes
    wait_for_port_free $SIM_PORT
    sleep $RETRY_DELAY

    start_time=$(date +%s)
    set +e
    (cd "$cwd" && eval "$cmd") > /tmp/test_output_retry_$$.log 2>&1
    exit_code=$?
    set -e
    end_time=$(date +%s)
    duration="$((end_time - start_time))s"

    if [ $exit_code -eq 0 ]; then
        log_pass "$duration (retry)"
        RESULTS+=("${YELLOW}🔄${NC} | $name | $duration (retry)")
        PASS_COUNT=$((PASS_COUNT + 1))
        return 0
    fi

    log_fail "$duration"
    echo "  Last 20 lines of output:"
    tail -20 /tmp/test_output_retry_$$.log 2>/dev/null | sed 's/^/    /'
    RESULTS+=("${RED}❌${NC} | $name | $duration")
    FAIL_COUNT=$((FAIL_COUNT + 1))
    return 1
}

# Cleanup between chain-sim suites
between_suites() {
    wait_for_port_free $SIM_PORT 10
    sleep $COOLDOWN
}

# ─── Test Groups ──────────────────────────────────────────────────

run_typescript_tests() {
    log_header "TypeScript Service Unit Tests"

    local services=(
        "moltbot-starter-kit|npm test|$ROOT_DIR/moltbot-starter-kit"
        "x402_facilitator|npm test|$ROOT_DIR/x402_integration/x402_facilitator"
        "multiversx-openclaw-relayer|npm test|$ROOT_DIR/x402_integration/multiversx-openclaw-relayer"
        "multiversx-acp-adapter|npm test|$ROOT_DIR/multiversx-acp-adapter"
        "multiversx-mcp-server|npm test|$ROOT_DIR/multiversx-mcp-server"
        "multiversx-openclaw-skills|npm test|$ROOT_DIR/multiversx-openclaw-skills"
    )

    for svc in "${services[@]}"; do
        IFS='|' read -r name cmd cwd <<< "$svc"
        if [ -d "$cwd" ]; then
            run_test "TS: $name" "$cmd" "$cwd" || true
        else
            echo -e "  ${YELLOW}⏭ Skipped $name (dir not found)${NC}"
        fi
    done
}

run_rust_sc_tests() {
    log_header "Rust Smart Contract Tests (mx-8004)"

    local mx8004_dir="$ROOT_DIR/mx-8004"
    if [ -d "$mx8004_dir" ]; then
        run_test "Rust SC: mx-8004 (18 tests)" "cargo test 2>&1" "$mx8004_dir" || true
    fi
}

run_chain_sim_suites() {
    log_header "Chain-Sim Integration Suites (A–T)"

    # Clean start
    kill_test_processes
    wait_for_port_free $SIM_PORT
    sleep 2

    local suites=(
        "Suite A — Identity Registry|suite_a_identity"
        "Suite D — Facilitator|suite_d_facilitator"
        "Suite E — Moltbot Lifecycle|suite_e_moltbot_lifecycle"
        "Suite E2 — Moltbot Update|suite_e2_moltbot_update"
        "Suite F — Multi Agent|suite_f_multi_agent"
        "Suite G — MCP Features|suite_g_mcp_features"
        "Suite H — Relayed Registration|suite_h_relayed_registration"
        "Suite I — Relayed Agent Ops|suite_i_relayed_agent_ops"
        "Suite J — Relayed Facilitator Settle|suite_j_relayed_facilitator_settle"
        "Suite K — Relayed Moltbot Lifecycle|suite_k_relayed_moltbot_lifecycle"
        "Suite L — MCP Agent Discovery|suite_l_mcp_agent_discovery"
        "Suite M — Agent to Agent Flow|suite_m_agent_to_agent_flow"
        "Suite N — Reputation Validation|suite_n_reputation_validation"
        "Suite O — MCP Tool Coverage|suite_o_mcp_tool_coverage"
        "Suite P — Identity Extended|suite_p_identity_extended"
        "Suite Q — Validation Extended|suite_q_validation_extended"
        "Suite R — Reputation Extended|suite_r_reputation_extended"
        "Suite S — Full Economy Loop|suite_s_full_economy_loop"
        "Suite T — MCP Extended|suite_t_mcp_extended"
    )

    for suite in "${suites[@]}"; do
        IFS='|' read -r name test_name <<< "$suite"
        run_test "$name" "cargo test --test $test_name -- --nocapture 2>&1" "$SCRIPT_DIR" || true
        between_suites
    done
}

run_offchain_suites() {
    log_header "Off-Chain Integration Suites (U–Y)"

    # Clean start
    kill_test_processes
    wait_for_port_free $SIM_PORT
    sleep 2

    local suites=(
        "Suite U — Facilitator Extended|suite_u_facilitator_extended"
        "Suite U2 — Facilitator Advanced|suite_u2_facilitator_advanced"
        "Suite V — Relayer Extended|suite_v_relayer_extended"
        "Suite V2 — Relayer Advanced|suite_v2_relayer_advanced"
        "Suite W — Moltbot Extended|suite_w_moltbot_extended"
        "Suite X — E2E Lifecycle|suite_x_e2e_lifecycle"
        "Suite Y — E2E Flows|suite_y_e2e_flows"
    )

    for suite in "${suites[@]}"; do
        IFS='|' read -r name test_name <<< "$suite"
        run_test "$name" "cargo test --test $test_name -- --nocapture 2>&1" "$SCRIPT_DIR" || true
        between_suites
    done
}

run_package_tests() {
    log_header "Package-Level Tests (pkg_1 – pkg_9)"

    # Clean start
    kill_test_processes
    wait_for_port_free $SIM_PORT
    sleep 2

    local pkgs=(
        "pkg_1 — Identity|pkg_1_identity"
        "pkg_2 — Validation|pkg_2_validation"
        "pkg_3 — Reputation|pkg_3_reputation"
        "pkg_4 — Facilitator|pkg_4_facilitator"
        "pkg_5 — MCP|pkg_5_mcp"
        "pkg_6 — Moltbot|pkg_6_moltbot"
        "pkg_7 — E2E|pkg_7_e2e"
        "pkg_8 — Escrow|pkg_8_escrow"
        "pkg_9 — Escrow Lifecycle|pkg_9_escrow_lifecycle"
    )

    for pkg in "${pkgs[@]}"; do
        IFS='|' read -r name test_name <<< "$pkg"
        run_test "$name" "cargo test --test $test_name -- --nocapture 2>&1" "$SCRIPT_DIR" || true
        between_suites
    done
}

# ─── Summary ──────────────────────────────────────────────────────

print_summary() {
    log_header "Test Results Summary"

    echo ""
    printf "%-4s | %-40s | %s\n" "   " "Test" "Duration"
    echo "-----+------------------------------------------+-----------"
    for result in "${RESULTS[@]}"; do
        echo -e "$result"
    done
    echo ""
    echo -e "${BOLD}Total:${NC} $((PASS_COUNT + FAIL_COUNT)) tests"
    echo -e "${GREEN}Passed:${NC} $PASS_COUNT"
    if [ $FAIL_COUNT -gt 0 ]; then
        echo -e "${RED}Failed:${NC} $FAIL_COUNT"
    fi
    if [ $RETRY_COUNT -gt 0 ]; then
        echo -e "${YELLOW}Retried:${NC} $RETRY_COUNT"
    fi
    echo ""

    if [ $FAIL_COUNT -eq 0 ]; then
        echo -e "${GREEN}${BOLD}🎉 ALL TESTS PASSED!${NC}"
    else
        echo -e "${RED}${BOLD}⚠ SOME TESTS FAILED — see output above${NC}"
        exit 1
    fi
}

# ─── Main ─────────────────────────────────────────────────────────

TOTAL_START=$(date +%s)

case "${1:-all}" in
    --suites)
        run_chain_sim_suites
        ;;
    --offchain)
        run_offchain_suites
        ;;
    --ts)
        run_typescript_tests
        ;;
    --rust)
        run_rust_sc_tests
        ;;
    --pkg)
        run_package_tests
        ;;
    all|*)
        run_typescript_tests
        run_rust_sc_tests
        run_chain_sim_suites
        run_offchain_suites
        run_package_tests
        ;;
esac

TOTAL_END=$(date +%s)
TOTAL_DURATION=$((TOTAL_END - TOTAL_START))

print_summary
echo -e "\nTotal wall time: ${BOLD}${TOTAL_DURATION}s${NC} ($((TOTAL_DURATION / 60))m $((TOTAL_DURATION % 60))s)"

# Cleanup
kill_test_processes 2>/dev/null || true
rm -f /tmp/test_output_$$.log /tmp/test_output_retry_$$.log
