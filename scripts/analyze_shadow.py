#!/usr/bin/env python3
"""
GateBridge Shadow Analyzer
==========================
Usage: ./analyze_shadow.py [path_to_log]

Purpose:
  Parses policy-shadow.log to distinguish between "Safety Wins" (Gate0 is stricter)
  and "Critical Drifts" (Gate0 is looser or buggy).

Critical Filter Logic:
  - IGNORE: Legacy=Allow -> Gate0=Deny (This is a Safety Improvement)
  - ALERT:  Legacy=Deny  -> Gate0=Allow (This is a Security Hole)
  - ALERT:  Regex/Parsing Errors (This is a Bug)
"""

import sys
import re
from collections import Counter

# Default path
LOG_FILE = "policy-shadow.log" if len(sys.argv) < 2 else sys.argv[1]

# Regex to parse the standard GateBridge log format
# Example: [2026-01-21T12:00:00Z] MISMATCH user=jdoe legacy=Allow gate0=Deny(NO_MATCH)
LOG_PATTERN = re.compile(
    r"MISMATCH user=(?P<user>\S+) legacy=(?P<legacy>\w+) gate0=(?P<gate0>\w+)(\((?P<reason>.*)\))?"
)

def main():
    print(f"🔍 Analyzing {LOG_FILE}...\n")
    
    stats = Counter()
    safety_wins = 0
    critical_drifts = 0
    parsing_errors = 0

    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                if "MISMATCH" not in line:
                    continue
                
                match = LOG_PATTERN.search(line)
                if not match:
                    # Likely a parsing error or panic trace
                    parsing_errors += 1
                    print(f"⚠️  UNPARSABLE LINE: {line.strip()[:100]}...")
                    continue

                legacy = match.group("legacy")
                gate0 = match.group("gate0")
                reason = match.group("reason") or "Unknown"

                # ANALYSIS LOGIC
                if legacy == "Allow" and "Deny" in gate0:
                    # Scenario: Python allowed it, Rust blocked it.
                    # Verdict: Gate0 is safer. Expected behavior during hardening.
                    safety_wins += 1
                    stats[f"Safety Win ({reason})"] += 1
                
                elif legacy == "Deny" and "Allow" in gate0:
                    # Scenario: Python blocked it, Rust allowed it.
                    # Verdict: CRITICAL FAILURE. Gate0 is missing a rule.
                    critical_drifts += 1
                    print(f"🚨 CRITICAL DRIFT: {line.strip()}")
                
                else:
                    # Scenario: Weird edge cases (Error vs Deny)
                    stats[f"Divergence ({legacy}->{gate0})"] += 1

    except FileNotFoundError:
        print(f"✅ No log file found at {LOG_FILE}. Zero mismatches so far.")
        sys.exit(0)

    # REPORTING
    print("-" * 40)
    print(f"Total Mismatches: {sum(stats.values()) + parsing_errors + critical_drifts}")
    print("-" * 40)
    print(f"🟢 Safety Wins (Gate0 stricter): {safety_wins}")
    print(f"🔴 Critical Drifts (Gate0 looser): {critical_drifts}")
    print(f"⚠️  Parsing/Panic Errors:         {parsing_errors}")
    print("-" * 40)
    
    if stats:
        print("\nTop Categories:")
        for category, count in stats.most_common(5):
            print(f"  {count:4d} x {category}")

    if critical_drifts == 0 and parsing_errors == 0:
        print("\n✨ SYSTEM HEALTHY. All mismatches are safety improvements.")
        sys.exit(0)
    else:
        print("\nACTION REQUIRED: Investigate Critical Drifts immediately.")
        sys.exit(1)

if __name__ == "__main__":
    main()
