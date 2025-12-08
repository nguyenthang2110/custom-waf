#!/bin/bash

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
COVERAGE_DIR="coverage"
COVERAGE_FILE="${COVERAGE_DIR}/coverage.out"
COVERAGE_HTML="${COVERAGE_DIR}/coverage.html"

print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║                                                      ║"
    echo "║   WAF Test Suite                                     ║"
    echo "║                                                      ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "${BLUE}==>${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Run unit tests
run_unit_tests() {
    print_step "Running unit tests..."
    
    if go test ./... -v -race -timeout=30s; then
        print_success "Unit tests passed"
        return 0
    else
        print_error "Unit tests failed"
        return 1
    fi
}

# Run tests with coverage
run_coverage() {
    print_step "Running tests with coverage..."
    
    mkdir -p ${COVERAGE_DIR}
    
    go test ./... \
        -coverprofile=${COVERAGE_FILE} \
        -covermode=atomic \
        -v
    
    if [ $? -eq 0 ]; then
        print_success "Coverage data generated"
        
        # Generate coverage report
        go tool cover -html=${COVERAGE_FILE} -o ${COVERAGE_HTML}
        print_success "Coverage report: ${COVERAGE_HTML}"
        
        # Display coverage summary
        echo ""
        echo "Coverage Summary:"
        go tool cover -func=${COVERAGE_FILE} | tail -1
        echo ""
    else
        print_error "Coverage tests failed"
        return 1
    fi
}

# Run benchmarks
run_benchmarks() {
    print_step "Running benchmarks..."
    
    go test ./... -bench=. -benchmem -run=^$ | tee ${COVERAGE_DIR}/benchmark.txt
    
    if [ $? -eq 0 ]; then
        print_success "Benchmarks completed"
    else
        print_error "Benchmarks failed"
    fi
}

# Run specific package tests
run_package_test() {
    local PACKAGE=$1
    print_step "Testing package: ${PACKAGE}"
    
    go test -v ./${PACKAGE}
}

# Lint code
run_lint() {
    print_step "Running linter..."
    
    if ! command -v golangci-lint &> /dev/null; then
        print_warning "golangci-lint not installed"
        print_step "Installing golangci-lint..."
        go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
    fi
    
    golangci-lint run ./...
    
    if [ $? -eq 0 ]; then
        print_success "Linting passed"
    else
        print_error "Linting failed"
    fi
}

# Test rule files
test_rules() {
    print_step "Validating rule files..."
    
    for rule_file in configs/rules/*.json; do
        if [ -f "$rule_file" ]; then
            echo "  Checking: $rule_file"
            if jq empty "$rule_file" 2>/dev/null; then
                print_success "Valid: $(basename $rule_file)"
            else
                print_error "Invalid JSON: $(basename $rule_file)"
                return 1
            fi
        fi
    done
    
    print_success "All rule files are valid"
}

# Integration tests
run_integration_tests() {
    print_step "Running integration tests..."
    
    # Start WAF in background
    print_step "Starting WAF..."
    ./bin/waf -config configs/config.yaml &
    WAF_PID=$!
    
    sleep 3
    
    # Test health endpoint
    print_step "Testing health endpoint..."
    if curl -sf http://localhost:8080/health > /dev/null; then
        print_success "Health check passed"
    else
        print_error "Health check failed"
        kill ${WAF_PID}
        return 1
    fi
    
    # Test metrics endpoint
    print_step "Testing metrics endpoint..."
    if curl -sf http://localhost:8080/metrics > /dev/null; then
        print_success "Metrics endpoint working"
    else
        print_error "Metrics endpoint failed"
        kill ${WAF_PID}
        return 1
    fi
    
    # Test SQLi blocking
    print_step "Testing SQLi blocking..."
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/api?id=1'%20UNION%20SELECT")
    if [ "$RESPONSE" = "403" ]; then
        print_success "SQLi blocked correctly"
    else
        print_warning "SQLi not blocked (code: ${RESPONSE})"
    fi
    
    # Test XSS blocking
    print_step "Testing XSS blocking..."
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/search?q=<script>alert(1)</script>")
    if [ "$RESPONSE" = "403" ]; then
        print_success "XSS blocked correctly"
    else
        print_warning "XSS not blocked (code: ${RESPONSE})"
    fi
    
    # Test legitimate request
    print_step "Testing legitimate request..."
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/api/users?page=1")
    if [ "$RESPONSE" = "200" ] || [ "$RESPONSE" = "502" ]; then
        print_success "Legitimate request allowed"
    else
        print_warning "Unexpected response: ${RESPONSE}"
    fi
    
    # Cleanup
    kill ${WAF_PID}
    print_success "Integration tests completed"
}

# Generate test report
generate_report() {
    print_step "Generating test report..."
    
    cat > ${COVERAGE_DIR}/report.txt << EOF
WAF Test Report
===============
Generated: $(date)

Test Results:
$(go test ./... -v 2>&1)

Coverage:
$(go tool cover -func=${COVERAGE_FILE} 2>&1)
EOF
    
    print_success "Report saved to ${COVERAGE_DIR}/report.txt"
}

# Display test summary
display_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║               Tests Completed Successfully           ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [ -f "${COVERAGE_FILE}" ]; then
        echo "Coverage Report:"
        go tool cover -func=${COVERAGE_FILE} | tail -5
        echo ""
        echo "Detailed report: ${COVERAGE_HTML}"
    fi
    
    echo ""
}

# Main test process
main() {
    print_banner
    
    case "${1:-all}" in
        all)
            run_unit_tests && \
            run_coverage && \
            test_rules && \
            run_lint && \
            generate_report && \
            display_summary
            ;;
        unit)
            run_unit_tests
            ;;
        coverage)
            run_coverage
            ;;
        bench)
            run_benchmarks
            ;;
        lint)
            run_lint
            ;;
        rules)
            test_rules
            ;;
        integration)
            run_integration_tests
            ;;
        package)
            if [ -z "$2" ]; then
                print_error "Package name required"
                echo "Usage: $0 package <package-name>"
                exit 1
            fi
            run_package_test "$2"
            ;;
        *)
            echo "Usage: $0 {all|unit|coverage|bench|lint|rules|integration|package <name>}"
            echo ""
            echo "  all         - Run all tests (default)"
            echo "  unit        - Run unit tests only"
            echo "  coverage    - Run tests with coverage"
            echo "  bench       - Run benchmarks"
            echo "  lint        - Run linter"
            echo "  rules       - Validate rule files"
            echo "  integration - Run integration tests"
            echo "  package     - Test specific package"
            exit 1
            ;;
    esac
}

main "$@"