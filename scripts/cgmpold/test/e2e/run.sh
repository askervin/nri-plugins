#!/bin/bash

# E2E test runner for cgmpold
# This script copies binaries to E2E_HOST and runs test scripts

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if E2E_HOST is set
if [ -z "$E2E_HOST" ]; then
    echo -e "${RED}ERROR: E2E_HOST environment variable is not set${NC}"
    echo ""
    echo "Usage: E2E_HOST=<hostname> $0 <test_directory>"
    echo ""
    echo "Example:"
    echo "  E2E_HOST=n4c16-fedora-43-containerd $0 ."
    echo ""
    echo "This will run all e2e tests found under the specified directory."
    exit 1
fi

# Get the directory containing this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Test directory is the first argument, default to current directory
TEST_DIR="${1:-.}"
TEST_DIR="$(cd "$TEST_DIR" && pwd)"

echo -e "${BLUE}=== cgmpold E2E Test Runner ===${NC}"
echo "E2E_HOST: $E2E_HOST"
echo "Project root: $PROJECT_ROOT"
echo "Test directory: $TEST_DIR"
echo ""

# Check if binaries exist
if [ ! -f "$PROJECT_ROOT/cgmpold" ]; then
    echo -e "${RED}ERROR: cgmpold not found. Run 'make' first.${NC}"
    exit 1
fi

echo -e "${YELLOW}Building binaries...${NC}"
cd "$PROJECT_ROOT"
make clean && make
echo ""

echo -e "${YELLOW}Cleaning up $E2E_HOST...${NC}"
ssh "$E2E_HOST" 'for d in /tmp/cgmpold-e2e-*; do
    [[ -d "$d" ]] || continue
    sudo kill $(cat $d/*.pid)
    rm -rf "$d"
done
'

echo -e "${YELLOW}Copying binaries to $E2E_HOST...${NC}"
# Create a temporary directory and copy binaries
REMOTE_DIR="/tmp/cgmpold-e2e-$$"
ssh "$E2E_HOST" "mkdir -p $REMOTE_DIR"

# Create tarball and copy
tar -czf /tmp/cgmpold-binaries.tar.gz -C "$PROJECT_ROOT" cgmpold
scp /tmp/cgmpold-binaries.tar.gz "$E2E_HOST:$REMOTE_DIR/"
ssh "$E2E_HOST" "cd $REMOTE_DIR && tar -xzf cgmpold-binaries.tar.gz"
rm /tmp/cgmpold-binaries.tar.gz

echo -e "${GREEN}Binaries copied to $E2E_HOST:$REMOTE_DIR${NC}"
echo ""

# Export remote directory for tests to use
export E2E_REMOTE_DIR="$REMOTE_DIR"

# Function to execute commands on E2E_HOST
# This function is available to all test scripts
vm() {
    ssh "$E2E_HOST" "$@"
}
export -f vm

vm-wait() {
    local timeout=$1
    local cmd=$2
    vm "cat > $E2E_REMOTE_DIR/vm-wait.bash <<EOF
$cmd
EOF
        timeout $timeout sh -c 'until bash $E2E_REMOTE_DIR/vm-wait.bash; do sleep 0.1; done'"
}
export -f vm-wait

# Function to copy files to E2E_HOST
vm_copy() {
    local src="$1"
    local dst="$2"
    scp "$src" "$E2E_HOST:$dst"
}
export -f vm_copy

# Function to copy files from E2E_HOST
vm_fetch() {
    local src="$1"
    local dst="$2"
    scp "$E2E_HOST:$src" "$dst"
}
export -f vm_fetch

# Global counter for unique Python ports
PYTHON3_PORT_BASE=33720
PYTHON3_PORT_COUNTER=0

# Function to start an interactive Python3 process on E2E_HOST
# Returns the port number to use with python-input
# Usage: PORT=$(python-start OUTPUT_FILE [CGROUP_PATH])
python-start() {
    local cgroup_path="${1:-}"

    # Allocate a unique port
    PYTHON3_PORT_COUNTER=$((PYTHON3_PORT_COUNTER + 1))
    local port=$((PYTHON3_PORT_BASE + PYTHON3_PORT_COUNTER))

    local output_file="$E2E_REMOTE_DIR/$port.out"

    # Start socat+python on the remote host
    if [ -n "$cgroup_path" ]; then
        # Start Python process in the cgroup
        vm "nohup sudo sh -c 'echo \$\$ > $cgroup_path/cgroup.procs && socat tcp4-listen:${port},fork,reuseaddr - | (python3 -i -u; pkill -f \"socat tcp4-listen:${port}\")' >& ${output_file} &" > /dev/null 2>&1
    else
        # Start Python without cgroup
        vm "nohup sh -c 'socat tcp4-listen:${port},fork,reuseaddr - | (python3 -i -u; pkill -f \"socat tcp4-listen:${port}\")' >& ${output_file} &" > /dev/null 2>&1
    fi

    # Disable prompts and get PID
    # vm "echo -e 'import os,sys\nsys.ps1=\"\"\nsys.ps2=\"\"\nprint(\"PYTHON_READY\")\nprint(\"PID:\",os.getpid())\nsys.stdout.flush()' | socat - tcp4:localhost:${port}" 2>/dev/null || true
    while ! python-input "$port" "
import os,sys,time
sys.ps1=''
sys.ps2=''
log=lambda *args:print('%.06f' % time.time(),'python $port', *args)
log('READY PID:',os.getpid())" 2>/dev/null; do
        sleep 0.1
    done

    # Return the port number
    echo "$port"
}
export -f python-start

# Function to send input to an interactive Python3 process
# Usage: python-input PORT "python code"
python-input() {
    local port="$1"
    local code="$2"
    vm "socat tcp4:localhost:${port} - <<EOCODE
$code
sys.stdout.flush()
EOCODE
" 2>/dev/null
}
export -f python-input

# Function to stop a Python3 process
# Usage: python-stop PORT
python-stop() {
    local port="$1"

    vm "echo 'sys.exit(0)' | socat - tcp4:localhost:${port}" 2>/dev/null || true
    vm "while fuser $E2E_REMOTE_DIR/$port.out; do sleep 0.1; done" >/dev/null
}
export -f python-stop

# Function to enter the interactive mode: read next script commands
# from the standard input until "exit".
# Usage: interactive
interactive() {
    echo "Entering the interactive mode until \"exit\"."
    # shellcheck disable=SC2162
    while read -e -p "run.sh> " -a commands; do
        if [ "${commands[0]}" == "exit" ]; then
            break
        fi
        eval "${commands[@]}"
    done
}


# Cleanup function
cleanup_remote() {
    status=$?
    if [[ "$DEBUG" != "1" ]]; then
        echo -e "(status $status) ${YELLOW}Cleaning up remote directory...${NC}"
        vm "rm -rf $REMOTE_DIR"
        wait || true
    fi
    return $status
}

# Register cleanup on exit
trap cleanup_remote EXIT

# Find all code.sh scripts under TEST_DIR
mapfile -t TEST_SCRIPTS < <(find "$TEST_DIR" -type f -name "code.sh" | sort)

if [ ${#TEST_SCRIPTS[@]} -eq 0 ]; then
    echo -e "${YELLOW}WARNING: No test scripts (code.sh) found under $TEST_DIR${NC}"
    exit 0
fi

echo -e "${BLUE}Found ${#TEST_SCRIPTS[@]} test script(s):${NC}"
for script in "${TEST_SCRIPTS[@]}"; do
    echo "  - $script"
done
echo ""

# Run each test script
PASSED=0
FAILED=0
FAILED_TESTS=()

for TEST_SCRIPT in "${TEST_SCRIPTS[@]}"; do
    TEST_NAME="$(basename "$(dirname "$TEST_SCRIPT")")"
    TEST_PATH="$(dirname "$TEST_SCRIPT")"

    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}Running test: $TEST_NAME${NC}"
    echo -e "${BLUE}========================================${NC}"

    # Export test information for the script
    export TEST_NAME
    export TEST_PATH
    export E2E_REMOTE_DIR

    # Run the test in a subshell so it can use our functions but can't affect other tests
    if ( cd "$TEST_PATH" && source code.sh ); then
        echo -e "${GREEN}✓ PASSED: $TEST_NAME${NC}"
        ((PASSED++))
    else
        echo -e "${RED}✗ FAILED: $TEST_NAME${NC}"
        ((FAILED++))
        FAILED_TESTS+=("$TEST_NAME")
    fi
    echo ""
done

# Print summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Test Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"

if [ $FAILED -gt 0 ]; then
    echo ""
    echo -e "${RED}Failed tests:${NC}"
    for test in "${FAILED_TESTS[@]}"; do
        echo -e "  ${RED}- $test${NC}"
    done
    exit 1
fi

echo ""
echo -e "${GREEN}All tests passed!${NC}"
exit 0
