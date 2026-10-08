//! BenchmarkPassword: the standalone password tool.
//!
//! A small console utility that changes the Benchmark sign-in password on this
//! computer, for when it is forgotten at the keyboard or an administrator wants
//! to reset it. It reads and writes the same account record the app uses, and
//! always asks for the current password first.

use std::io::Write;
use std::process::exit;

use dca_core::{account, time};

fn main() {
    println!("Benchmark password tool");
    println!("-----------------------");

    let dir = match account::dir() {
        Some(d) => d,
        None => fail("Could not find the Benchmark folder on this computer."),
    };

    if !account::exists(&dir) {
        fail(
            "There is no Benchmark account on this computer yet. Create one by opening Benchmark.",
        );
    }

    let who = account::username(&dir).unwrap_or_default();
    println!("Changing the password for \"{who}\".\n");

    let current = prompt_hidden("Current password: ");
    if account::verify(&dir, &who, &current).is_err() {
        fail("That current password is not correct.");
    }

    let next = prompt_hidden("New password: ");
    let again = prompt_hidden("New password again: ");
    if next != again {
        fail("The two new passwords do not match.");
    }

    match account::change(&dir, &who, &current, &next, time::now()) {
        Ok(()) => println!("\nThe password has been changed. Open Benchmark and sign in with it."),
        Err(e) => fail(&e),
    }
}

fn prompt_hidden(label: &str) -> String {
    print!("{label}");
    let _ = std::io::stdout().flush();
    rpassword::read_password()
        .unwrap_or_else(|_| fail("Could not read the password from the console."))
}

fn fail(message: &str) -> ! {
    eprintln!("\n{message}");
    exit(1);
}
