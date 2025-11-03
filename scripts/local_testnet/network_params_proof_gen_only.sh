#!/bin/bash

# Helper script for monitoring execution proof generation and gossip
# Usage: ./network_params_proof_gen_only.sh [command]
#        ENCLAVE=my-testnet ./network_params_proof_gen_only.sh [command]
#
# Set ENCLAVE environment variable to use a different testnet.
# Default: local-testnet

ENCLAVE="${ENCLAVE:-local-testnet}"

# Color output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

case "${1:-help}" in
  generation)
    echo -e "${GREEN}=== Proof Generation and Publishing ===${NC}"
    for i in 1 2 3 4; do
      echo -e "\n${YELLOW}--- Node $i ---${NC}"
      kurtosis service logs $ENCLAVE cl-$i-lighthouse-geth -a 2>&1 | grep -E "(Generating execution proof|Proof successfully published)" | tail -5
    done
    ;;

  gossip-subscribe)
    echo -e "${GREEN}=== ExecutionProof Topic Subscriptions ===${NC}"
    for i in 1 2 3 4; do
      echo -e "\n${YELLOW}--- Node $i ---${NC}"
      kurtosis service logs $ENCLAVE cl-$i-lighthouse-geth -a 2>&1 | grep "Subscribed to topic.*execution_proof"
    done
    ;;

  gossip-receive)
    echo -e "${GREEN}=== Received Execution Proofs via Gossip ===${NC}"
    for i in 1 2 3 4; do
      count=$(kurtosis service logs $ENCLAVE cl-$i-lighthouse-geth -a 2>&1 | grep "Received execution proof via gossip" | wc -l)
      echo -e "${YELLOW}Node $i:${NC} $count proofs received"
    done
    ;;

  gossip-verified)
    echo -e "${GREEN}=== Verified Execution Proofs ===${NC}"
    for i in 1 2 3 4; do
      count=$(kurtosis service logs $ENCLAVE cl-$i-lighthouse-geth -a 2>&1 | grep "Successfully verified gossip execution proof" | wc -l)
      echo -e "${YELLOW}Node $i:${NC} $count proofs verified"
    done
    ;;

  errors)
    echo -e "${GREEN}=== Checking for Errors ===${NC}"
    for i in 1 2 3 4; do
      echo -e "\n${YELLOW}--- Node $i ---${NC}"
      no_peers=$(kurtosis service logs $ENCLAVE cl-$i-lighthouse-geth -a 2>&1 | grep "NoPeersSubscribedToTopic.*execution_proof" | wc -l)
      failed_sub=$(kurtosis service logs $ENCLAVE cl-$i-lighthouse-geth -a 2>&1 | grep "Failed to subscribe.*execution_proof" | wc -l)

      if [ "$no_peers" -gt 0 ]; then
        echo -e "${RED}NoPeersSubscribedToTopic errors: $no_peers${NC}"
      else
        echo -e "${GREEN}NoPeersSubscribedToTopic errors: 0${NC}"
      fi

      if [ "$failed_sub" -gt 0 ]; then
        echo -e "${RED}Failed subscription errors: $failed_sub${NC}"
      else
        echo -e "${GREEN}Failed subscription errors: 0${NC}"
      fi
    done
    ;;

  zkvm-logs)
    echo -e "${GREEN}=== ZKVM Debug Logs ===${NC}"
    for i in 1 2 3 4; do
      echo -e "\n${YELLOW}--- Node $i ---${NC}"
      kurtosis service logs $ENCLAVE cl-$i-lighthouse-geth -a 2>&1 | grep "ZKVM:" | head -5
    done
    ;;

  fork-transition)
    echo -e "${GREEN}=== Fork Transition Logs ===${NC}"
    for i in 1 2 3 4; do
      echo -e "\n${YELLOW}--- Node $i ---${NC}"
      kurtosis service logs $ENCLAVE cl-$i-lighthouse-geth -a 2>&1 | grep -E "(Subscribing to new fork|subscribe_new_fork_topics called)"
    done
    ;;

  stats)
    echo -e "${GREEN}=== Execution Proof Statistics ===${NC}"
    for i in 1 2 3 4; do
      generated=$(kurtosis service logs $ENCLAVE cl-$i-lighthouse-geth -a 2>&1 | grep "Generating execution proof" | wc -l)
      published=$(kurtosis service logs $ENCLAVE cl-$i-lighthouse-geth -a 2>&1 | grep "Proof successfully published" | wc -l)
      received=$(kurtosis service logs $ENCLAVE cl-$i-lighthouse-geth -a 2>&1 | grep "Received execution proof via gossip" | wc -l)
      verified=$(kurtosis service logs $ENCLAVE cl-$i-lighthouse-geth -a 2>&1 | grep "Successfully verified gossip execution proof" | wc -l)

      echo -e "${YELLOW}Node $i:${NC}"
      echo -e "  Generated: $generated"
      echo -e "  Published: $published"
      echo -e "  Received:  $received"
      echo -e "  Verified:  $verified"
    done
    ;;

  follow)
    NODE="${2:-1}"
    echo -e "${GREEN}=== Following Execution Proof Logs for Node $NODE ===${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
    kurtosis service logs $ENCLAVE cl-$NODE-lighthouse-geth -f | grep --line-buffered -E "(Generating execution proof|Proof successfully published|Received execution proof via gossip|Successfully verified gossip execution proof)"
    ;;

  all)
    echo -e "${GREEN}=== Complete Execution Proof Report ===${NC}\n"
    $0 zkvm-logs
    echo -e "\n"
    $0 fork-transition
    echo -e "\n"
    $0 gossip-subscribe
    echo -e "\n"
    $0 stats
    echo -e "\n"
    $0 errors
    ;;

  help|*)
    echo "Helper script for monitoring execution proof generation and gossip"
    echo ""
    echo "Usage: $0 [command]"
    echo "       ENCLAVE=name $0 [command]"
    echo ""
    echo "Environment Variables:"
    echo "  ENCLAVE  - Testnet enclave name (default: local-testnet)"
    echo ""
    echo "Commands:"
    echo "  generation        - Show proof generation and publishing logs"
    echo "  gossip-subscribe  - Show ExecutionProof topic subscriptions"
    echo "  gossip-receive    - Count received proofs on each node"
    echo "  gossip-verified   - Count verified proofs on each node"
    echo "  errors            - Check for gossip errors"
    echo "  zkvm-logs         - Show ZKVM debug logs"
    echo "  fork-transition   - Show fork transition logs"
    echo "  stats             - Show proof statistics for all nodes"
    echo "  follow [node]     - Follow proof logs in real-time (default: node 1)"
    echo "  all               - Show complete report"
    echo "  help              - Show this help message"
    echo ""
    echo "Examples:"
    echo "  # Use default testnet (local-testnet)"
    echo "  $0 stats"
    echo "  $0 follow 2"
    echo "  $0 all"
    echo ""
    echo "  # Use custom testnet enclave"
    echo "  ENCLAVE=my-testnet $0 stats"
    ;;
esac
