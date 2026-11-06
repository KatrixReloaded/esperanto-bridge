fn main() {
    if zz_watcher::unsafe_test::main().is_err() {
        // Fixed diagnostic only: errors may contain RPC data or local configuration.
        eprintln!(
            "UNSAFE TEST runner stopped; configuration, pin, lease or reconciliation check failed"
        );
        std::process::exit(1);
    }
}
