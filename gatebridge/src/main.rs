//! GateBridge CLI
//!
//! Commands:
//!   validate   - Check policy file syntax
//!   translate  - Convert to Gate0 (outputs Rust code)
//!   shadow     - Run dual evaluation and compare
//!   explain    - Show step-by-step evaluation for debugging

use std::env;
use std::io::{self, Read};
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return ExitCode::from(2);
    }

    match args[1].as_str() {
        "validate" => {
            if args.len() < 3 {
                eprintln!("Usage: gatebridge validate <policy.yaml>");
                return ExitCode::from(2);
            }
            cmd_validate(&args[2])
        }
        "translate" => {
            if args.len() < 3 {
                eprintln!("Usage: gatebridge translate <policy.yaml>");
                return ExitCode::from(2);
            }
            cmd_translate(&args[2])
        }
        "shadow" => {
            if args.len() < 4 {
                eprintln!("Usage: gatebridge shadow <policy.yaml> <request.json | ->");
                return ExitCode::from(2);
            }
            cmd_shadow(&args[2], &args[3])
        }
        "explain" => {
            if args.len() < 4 {
                eprintln!("Usage: gatebridge explain <policy.yaml> <request.json>");
                return ExitCode::from(2);
            }
            cmd_explain(&args[2], &args[3])
        }
        "help" | "--help" | "-h" => {
            print_usage();
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn print_usage() {
    eprintln!("GateBridge - Policy translator for Gate0");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  gatebridge validate <policy.yaml>              Check policy syntax");
    eprintln!("  gatebridge translate <policy.yaml>             Convert to Gate0");
    eprintln!("  gatebridge shadow <policy.yaml> <request.json> Dual evaluation");
    eprintln!("  gatebridge shadow <policy.yaml> -              Read request from stdin");
    eprintln!("  gatebridge explain <policy.yaml> <request.json> Debug evaluation");
    eprintln!("  gatebridge help                                Show this message");
    eprintln!();
    eprintln!("Exit codes:");
    eprintln!("  0 = success (shadow: decisions match)");
    eprintln!("  1 = mismatch (shadow: decisions differ)");
    eprintln!("  2 = error");
}

fn cmd_validate(path: &str) -> ExitCode {
    let path = Path::new(path);
    
    match gatebridge::load_policy_file(path) {
        Ok(policy) => {
            println!("Policy valid.");
            println!("  Default principals: {:?}", policy.default.principals);
            println!("  Policy count: {}", policy.policies.len());
            for (i, p) in policy.policies.iter().enumerate() {
                println!("  [{}] {}", i, p.name);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Validation failed: {}", e);
            ExitCode::from(2)
        }
    }
}

fn cmd_translate(path: &str) -> ExitCode {
    let path = Path::new(path);
    
    let policy_file = match gatebridge::load_policy_file(path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to load: {}", e);
            return ExitCode::from(2);
        }
    };

    match gatebridge::to_gate0(&policy_file) {
        Ok(gate0_policy) => {
            println!("Translation successful.");
            println!("Gate0 rule count: {}", gate0_policy.rule_count());
            println!();
            println!("// Generated Gate0 policy");
            println!("// ReasonCode mapping:");
            for (i, p) in policy_file.policies.iter().enumerate() {
                println!("//   ReasonCode({}) -> {}", i, p.name);
            }
            println!("//   ReasonCode({}) -> default", u32::MAX - 1);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Translation failed: {}", e);
            ExitCode::from(2)
        }
    }
}

fn cmd_shadow(policy_path: &str, request_source: &str) -> ExitCode {
    // Load policy
    let policy_file = match gatebridge::load_policy_file(Path::new(policy_path)) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{{\"error\": \"Failed to load policy: {}\"}}", e);
            return ExitCode::from(2);
        }
    };

    // Load request (from file or stdin)
    let request_json = if request_source == "-" {
        let mut buffer = String::new();
        if let Err(e) = io::stdin().read_to_string(&mut buffer) {
            eprintln!("{{\"error\": \"Failed to read stdin: {}\"}}", e);
            return ExitCode::from(2);
        }
        buffer
    } else {
        match std::fs::read_to_string(request_source) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{{\"error\": \"Failed to read request file: {}\"}}", e);
                return ExitCode::from(2);
            }
        }
    };

    // Parse request
    let request: gatebridge::EvalRequest = match serde_json::from_str(&request_json) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{{\"error\": \"Failed to parse request JSON: {}\"}}", e);
            return ExitCode::from(2);
        }
    };

    // Run shadow evaluation
    match gatebridge::shadow_evaluate(&policy_file, &request) {
        Ok(result) => {
            let json = serde_json::to_string_pretty(&result).unwrap();
            println!("{}", json);
            
            if result.decisions_match {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("{{\"error\": \"{}\"}}", e);
            ExitCode::from(2)
        }
    }
}

fn cmd_explain(policy_path: &str, request_path: &str) -> ExitCode {
    // Load policy
    let policy_file = match gatebridge::load_policy_file(Path::new(policy_path)) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to load policy: {}", e);
            return ExitCode::from(2);
        }
    };

    // Load request
    let request_json = match std::fs::read_to_string(request_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to read request file: {}", e);
            return ExitCode::from(2);
        }
    };

    let request: gatebridge::EvalRequest = match serde_json::from_str(&request_json) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to parse request JSON: {}", e);
            return ExitCode::from(2);
        }
    };

    // Run explain
    let result = gatebridge::explain(&policy_file, &request);
    let output = gatebridge::format_explain(&result);
    println!("{}", output);

    ExitCode::SUCCESS
}
