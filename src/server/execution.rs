use crate::server::ServerState;
use std::env::{self};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;

struct Details {
    command: String,
    args: Vec<String>,
    input_file: String,
    output_file: String,
    append: bool,
    background: bool,
    input: String,
}

fn final_check(input: &str) -> Result<(), String> {
    let mut tokens = Vec::new();
    let mut i = 0;
    let chars: Vec<char> = input.chars().collect();

    let mut current = String::new();
    let mut in_quotes = false;
    let mut quote_char = '\0';

    while i < chars.len() {
        let c = chars[i];
        if in_quotes {
            if c == quote_char {
                in_quotes = false;
            }
            current.push(c);
            i += 1;
            continue;
        } else if c == '\'' || c == '\"' {
            in_quotes = true;
            quote_char = c;
            current.push(c);
            i += 1;
            continue;
        }
        if c.is_whitespace() {
            if !current.is_empty() {
                tokens.push(current);
                current = String::new();
            }
            i += 1;
            continue;
        }
        match c {
            '>' => {
                if !current.is_empty() {
                    tokens.push(current);
                    current = String::new();
                }
                if i + 1 < chars.len() && chars[i + 1] == '>' {
                    tokens.push(">>".to_string());
                    i += 2;
                } else {
                    tokens.push(">".to_string());
                    i += 1;
                }
            }
            '<' => {
                if !current.is_empty() {
                    tokens.push(current);
                    current = String::new();
                }
                tokens.push("<".to_string());
                i += 1;
            }
            '|' => {
                if !current.is_empty() {
                    tokens.push(current);
                    current = String::new();
                }
                if i + 1 < chars.len() && chars[i + 1] == '|' {
                    tokens.push("||".to_string());
                    i += 2;
                } else {
                    tokens.push("|".to_string());
                    i += 1;
                }
            }
            '&' => {
                if !current.is_empty() {
                    tokens.push(current);
                    current = String::new();
                }
                if i + 1 < chars.len() && chars[i + 1] == '&' {
                    tokens.push("&&".to_string());
                    i += 2;
                } else {
                    tokens.push("&".to_string());
                    i += 1;
                }
            }
            _ => {
                current.push(c);
                i += 1;
            }
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    let operators = [">", ">>", "<", "|", "||", "&&", "&"];

    for window in tokens.windows(2) {
        let left = &window[0];
        let right = &window[1];

        if operators.contains(&left.as_str()) && operators.contains(&right.as_str()) {
            return Err(format!(
                "Error: Two operators in a row: '{}' '{}'",
                left, right
            ));
        }
    }

    let invalid_end = [">", ">>", "<", "|", "||", "&&"];

    if let Some(last) = tokens.last() {
        if invalid_end.contains(&last.as_str()) {
            return Err(format!(
                "Error: Can't end command with an operator ({})",
                last
            ));
        }
    }
    Ok(())
}

fn split_quotes(input: &str, delimiter: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();

    let chars: Vec<char> = input.chars().collect();
    let len = delimiter.len();

    let mut i = 0;
    let mut in_quotes = false;
    let mut quote_char = '\0';

    while i < chars.len() {
        let c = chars[i];
        if in_quotes {
            if c == quote_char {
                in_quotes = false;
                quote_char = '\0';
            }
            current.push(c);
            i += 1;
        } else if c == '\'' || c == '\"' {
            in_quotes = true;
            quote_char = c;
            current.push(c);
            i += 1;
        } else {
            if i + len <= chars.len() {
                let next_sub: String = chars[i..i + len].iter().collect();

                if next_sub == delimiter {
                    result.push(current);
                    current = String::new();
                    i += len;
                    continue;
                }
            }
            current.push(c);
            i += 1;
        }
    }

    if !current.is_empty() {
        result.push(current);
    }

    result
}

fn split(input: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut quote_char = '\0';

    let mut greater = false;

    for c in input.chars() {
        if greater {
            if c == '>' && !in_quotes {
                if !current.is_empty() {
                    parts.push(current);
                    current = String::new();
                }
                parts.push(">>".to_string());
                greater = false;

                continue;
            } else {
                if !current.is_empty() {
                    parts.push(current);
                    current = String::new();
                }

                parts.push(">".to_string());
                greater = false;
            }
        }

        match c {
            '\'' | '\"' if in_quotes && c == quote_char => {
                in_quotes = false;
            }
            '\'' | '\"' if !in_quotes => {
                in_quotes = true;
                quote_char = c;
            }
            ' ' if !in_quotes => {
                if !current.is_empty() {
                    parts.push(current);
                    current = String::new();
                }
            }
            '<' if !in_quotes => {
                if !current.is_empty() {
                    parts.push(current);
                    current = String::new();
                }
                parts.push("<".to_string());
            }
            '>' if !in_quotes => {
                greater = true;
            }
            _ => {
                current.push(c);
            }
        }
    }

    if greater {
        if !current.is_empty() {
            parts.push(current);
        }
        parts.push(">".to_string());
    } else if !current.is_empty() {
        parts.push(current);
    }

    parts
}
fn parse_command(input: &str) -> (String, Vec<String>, String, String, bool, bool) {
    let mut parts = split(input);

    let mut background = false;
    if let Some(last) = parts.last() {
        if last == "&" {
            background = true;
            parts.pop();
        }
    }

    let mut command = String::new();
    let mut args = Vec::new();
    let mut input_file = String::new();
    let mut output_file = String::new();
    let mut append = false;

    let mut i = 0;
    while i < parts.len() {
        match parts[i].as_str() {
            "<" => {
                if i + 1 < parts.len() {
                    input_file = parts[i + 1].clone();
                    i += 1;
                }
            }
            ">" => {
                if i + 1 < parts.len() {
                    output_file = parts[i + 1].clone();
                    append = false;
                    i += 1;
                }
            }
            ">>" => {
                if i + 1 < parts.len() {
                    output_file = parts[i + 1].clone();
                    append = true;
                    i += 1;
                }
            }
            _ if command.is_empty() => command = parts[i].clone(),
            _ => args.push(parts[i].clone()),
        }
        i += 1;
    }

    (command, args, input_file, output_file, append, background)
}
fn execute_command(
    details: Details,
    client_id: &str,
    addr: &Arc<ServerState>,
) -> (bool, String) {
    let mut output = String::new();
    if details.command == "cd" {
        if details.args.len() != 1 {
            return (false, "cd: wrong number of arguments\n".to_string());
        }
        let new_dir = &details.args[0];
        let current_dir = addr.get_client_path(&client_id.to_string());

        let target_dir = if new_dir == ".." {
            let mut path = PathBuf::from(&current_dir);
            path.pop();
            path.to_string_lossy().to_string()
        } else if new_dir == "." {
            current_dir.clone()
        } else if new_dir.starts_with('/') {
            new_dir.to_string()
        } else {
            format!("{}/{}", current_dir, new_dir)
        };

        if env::set_current_dir(&target_dir).is_ok() {
            addr.set_client_path(client_id.to_string(), target_dir.clone());

            let real_path = env::current_dir()
                .unwrap_or_else(|_| PathBuf::from(&target_dir))
                .to_string_lossy()
                .to_string();
            output = format!("Changed directory to {}\n", real_path);
            return (true, output);
        } else {
            output = format!("cd: no such file or directory: {}\n", new_dir);
            return (false, output);
        }
    }

    let mut cmd = Command::new(details.command);
    cmd.args(details.args);

    if !details.input_file.is_empty() {
        if let Ok(input_file) = File::open(details.input_file) {
            cmd.stdin(Stdio::from(input_file));
        } else {
            return (false, "Error opening file".to_string());
        }
    } else if !details.input.is_empty() {
        cmd.stdin(Stdio::piped());
    }

    if !details.output_file.is_empty() {
        let file_result: Result<File, std::io::Error> = if details.append {
            File::options().append(true).create(true).open(details.output_file)
        } else {
            File::create(details.output_file)
        };

        if let Ok(file) = file_result {
            cmd.stdout(Stdio::from(file));
        } else {
            return (false, "Error opening output file".to_string());
        }
    } else {
        cmd.stdout(Stdio::piped());
    }

    cmd.stderr(Stdio::piped());

    if details.background {
        match cmd.spawn() {
            Ok(child) => {
                return (
                    true,
                    format!("Running in background with PID {}\n", child.id()),
                );
            }
            Err(_) => return (false, "Error running in background".to_string()),
        }
    }

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => return (false, format!("Error: {}\n", err)),
    };

    if !details.input.is_empty() {
        if let Some(mut stdin) = child.stdin.take() {
            if stdin.write_all(details.input.as_bytes()).is_err() {
                return (false, "Error writing to stdin\n".to_string());
            }
        }
    }

    let out = match child.wait_with_output() {
        Ok(out) => out,
        Err(err) => return (false, format!("Error: {}\n", err)),
    };

    if out.status.success() {
        let result = String::from_utf8_lossy(&out.stdout);
        output += &result;

        (true, output)
    } else {
        let result = String::from_utf8_lossy(&out.stderr);
        output += &result;

        (false, output)
    }
}

fn execute_pipeline(pipe: Vec<&str>, client_id: &str, addr: &Arc<ServerState>) -> (bool, String) {
    let mut last_output = String::new();
    let mut succes = true;

    for cmd in pipe {
        let (command, args, input_file, output_file, append, background) =
            parse_command(cmd.trim());
        if command.is_empty() {
            continue;
        }

        let details = Details {
            command: command.clone(),
            args,
            input_file,
            output_file,
            append,
            background,
            input: last_output.clone(),
        };
        let (cmd_succes, output) = execute_command(
            details,
            client_id,
            addr,
        );

        succes = cmd_succes;
        last_output = output;

        if !succes {
            break;
        }
    }
    (succes, last_output)
}
fn process_command(input: &str, client_id: &str, addr: &Arc<ServerState>) -> String {
    let mut output = String::new();

    let splitted = split_quotes(input, ";");
    for group in splitted {
        let mut status = true;
        let segs = split_quotes(&group, "&&");

        for subcommand in segs {
            if status {
                let or_operator = split_quotes(&subcommand, "||");

                for or_command in or_operator {
                    if or_command == "true" {
                        status = true;
                        break;
                    } else if or_command == "false" {
                        status = false;
                        continue;
                    }
                    let or_operator_string = split_quotes(&or_command, "|");
                    let or_operator: Vec<&str> =
                        or_operator_string.iter().map(|s| s.as_str()).collect();

                    let (success, result) = execute_pipeline(or_operator, client_id, addr);

                    if !result.is_empty() {
                        output.push_str(&result);
                    }
                    status = success;
                    if success {
                        break;
                    }
                }
            } else {
                let mut found_or_command = false;
                let or_operator = split_quotes(&subcommand, "||");
                for or_command in or_operator {
                    if found_or_command {
                        let or_operator_string = split_quotes(&or_command, "|");
                        let or_operator: Vec<&str> =
                            or_operator_string.iter().map(|s| s.as_str()).collect();
                        let (success, result) = execute_pipeline(or_operator, client_id, addr);
                        if !result.is_empty() {
                            output.push_str(&result);
                        }
                        status = success;
                        if success {
                            break;
                        }
                    } else {
                        found_or_command = true;
                    }
                }
            }
        }
    }

    output
}

pub fn execution(command: String, client_id: String, addr: Arc<ServerState>) -> String {
    let mut output = String::new();
    let input = command.trim();

    if input == "exit" {
        output.push_str("exit");
    } else {
        if let Err(error) = final_check(input) {
            output += error.as_str();
            return output;
        }

        output = process_command(input, &client_id, &addr);
    }
    output
}
