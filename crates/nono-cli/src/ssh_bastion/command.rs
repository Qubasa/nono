//! Exact-argv matching of a requested remote command against the command list
//! an `allow_ssh` entry carries.
//!
//! What an SSH client sends in an `exec` request is not an argv, it is one
//! string that the remote host hands to a shell. nono never evaluates that
//! string, so anything in it that lets one command become two is refused
//! before matching is attempted rather than after: tokenising first and
//! inspecting the tokens afterwards invites a rule that looks satisfied while
//! the string still carries a separator the remote shell will act on.
//!
//! What survives the refusal is tokenised the same way on both sides and
//! compared element by element. Every softer form of matching (prefix, glob,
//! argv0 only) turns "allow one command" into "allow a family of commands
//! nobody enumerated".

use std::str::from_utf8;

/// Outcome of checking a requested command against an allowance's list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CommandDecision {
    Allowed,
    Refused(String),
}

/// Characters through which one command line becomes two, reaches a second
/// process, or redirects a stream. The remote shell acts on every one of them.
const METACHARACTERS: &[char] = &[
    ';', '|', '&', '$', '`', '(', ')', '<', '>', '{', '}', '\n', '\r',
];

/// Check a requested `exec` command line against an endpoint's allowed
/// commands.
pub(crate) fn command_matches(rules: &[String], requested: &[u8]) -> CommandDecision {
    let requested = match from_utf8(requested) {
        Ok(text) => text,
        Err(_) => {
            return CommandDecision::Refused(format!(
                "network.allow_ssh refused the remote command `{}`: it is not valid UTF-8, so it cannot be tokenised or matched against this endpoint's allowed commands",
                display_command(&String::from_utf8_lossy(requested))
            ));
        }
    };

    if let Some(found) = requested.chars().find(|ch| METACHARACTERS.contains(ch)) {
        return CommandDecision::Refused(format!(
            "network.allow_ssh refused the remote command `{}`: it contains the shell metacharacter {}, one of the separators, pipes, redirections, substitutions and newlines that nono cannot evaluate because the remote shell is what interprets the command line",
            display_command(requested),
            name_metacharacter(found)
        ));
    }

    let Some(requested_argv) = shlex::split(requested) else {
        return CommandDecision::Refused(format!(
            "network.allow_ssh refused the remote command `{}`: it does not tokenise as a POSIX command line, so it cannot be compared with this endpoint's allowed commands",
            display_command(requested)
        ));
    };

    if rules.is_empty() {
        return CommandDecision::Refused(format!(
            "network.allow_ssh refused the remote command `{}`: this endpoint's allowance names no commands at all",
            display_command(requested)
        ));
    }

    for rule in rules {
        let rule_argv = match shlex::split(rule) {
            Some(argv) if !argv.is_empty() => argv,
            _ => {
                return CommandDecision::Refused(format!(
                    "network.allow_ssh refused the remote command `{}`: the allowed command `{}` does not tokenise as a POSIX command line, so it can never match anything",
                    display_command(requested),
                    display_command(rule)
                ));
            }
        };
        if rule_argv == requested_argv {
            return CommandDecision::Allowed;
        }
    }

    CommandDecision::Refused(format!(
        "network.allow_ssh refused the remote command `{}`: this endpoint's allowance names {}, and a command matches only when its whole argument vector is identical",
        display_command(requested),
        command_list(rules)
    ))
}

/// Render an allowance's command list for a refusal message.
pub(crate) fn command_list(rules: &[String]) -> String {
    if rules.is_empty() {
        return "no commands".to_string();
    }
    let mut out = String::new();
    for (index, rule) in rules.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push('`');
        out.push_str(&display_command(rule));
        out.push('`');
    }
    out
}

fn name_metacharacter(found: char) -> String {
    match found {
        '\n' => "a newline".to_string(),
        '\r' => "a carriage return".to_string(),
        other => format!("`{other}`"),
    }
}

/// Keep a refused command readable on one line: a refusal names the command,
/// and a raw newline or control byte in it would otherwise reshape the message
/// the user reads.
fn display_command(command: &str) -> String {
    let mut out = String::with_capacity(command.len());
    for ch in command.chars() {
        if ch.is_control() {
            out.extend(ch.escape_debug());
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn rules(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|entry| (*entry).to_string()).collect()
    }

    fn refusal(decision: CommandDecision) -> String {
        match decision {
            CommandDecision::Refused(reason) => reason,
            CommandDecision::Allowed => panic!("expected a refusal, got Allowed"),
        }
    }

    #[test]
    fn quoting_differences_reach_the_same_rule() {
        let rules = rules(&["git-upload-pack /srv/repo.git"]);
        assert_eq!(
            command_matches(&rules, b"git-upload-pack '/srv/repo.git'"),
            CommandDecision::Allowed
        );
        assert_eq!(
            command_matches(&rules, b"git-upload-pack /srv/repo.git"),
            CommandDecision::Allowed
        );
    }

    #[test]
    fn an_extra_argument_does_not_match() {
        let rules = rules(&["git-upload-pack /srv/repo.git"]);
        let reason = refusal(command_matches(
            &rules,
            b"git-upload-pack /srv/repo.git --strict",
        ));
        assert!(
            reason.contains("git-upload-pack /srv/repo.git --strict"),
            "{reason}"
        );
        assert!(reason.contains("argument vector"), "{reason}");
    }

    #[test]
    fn a_missing_argument_does_not_match() {
        let rules = rules(&["git-upload-pack /srv/repo.git"]);
        let reason = refusal(command_matches(&rules, b"git-upload-pack"));
        assert!(reason.contains("git-upload-pack"), "{reason}");
    }

    #[test]
    fn a_different_argv0_does_not_match() {
        let rules = rules(&["git-upload-pack /srv/repo.git"]);
        let reason = refusal(command_matches(&rules, b"git-receive-pack /srv/repo.git"));
        assert!(
            reason.contains("git-receive-pack /srv/repo.git"),
            "{reason}"
        );
    }

    #[test]
    fn a_separator_is_refused_before_matching() {
        let rules = rules(&["git-upload-pack /srv/repo.git"]);
        let reason = refusal(command_matches(
            &rules,
            b"git-upload-pack /srv/repo.git; curl evil",
        ));
        assert!(reason.contains("metacharacter `;`"), "{reason}");
        assert!(reason.contains("curl evil"), "{reason}");
        assert!(!reason.contains("argument vector"), "{reason}");
    }

    #[test]
    fn a_backgrounded_command_is_refused_even_when_the_prefix_matches() {
        let rules = rules(&["git-upload-pack /srv/repo.git"]);
        let reason = refusal(command_matches(&rules, b"git-upload-pack /srv/repo.git &"));
        assert!(reason.contains("metacharacter `&`"), "{reason}");
    }

    #[test]
    fn non_utf8_bytes_are_refused() {
        let rules = rules(&["git-upload-pack /srv/repo.git"]);
        let reason = refusal(command_matches(
            &rules,
            b"git-upload-pack /srv/\xffrepo.git",
        ));
        assert!(reason.contains("not valid UTF-8"), "{reason}");
    }

    #[test]
    fn an_empty_rule_list_refuses_everything() {
        let reason = refusal(command_matches(&[], b"git-upload-pack /srv/repo.git"));
        assert!(reason.contains("git-upload-pack /srv/repo.git"), "{reason}");
        assert!(reason.contains("names no commands"), "{reason}");
    }

    #[test]
    fn an_unusable_rule_matches_nothing() {
        let rules = rules(&["git-upload-pack 'unterminated"]);
        let reason = refusal(command_matches(&rules, b"git-upload-pack /srv/repo.git"));
        assert!(reason.contains("can never match"), "{reason}");
    }

    #[test]
    fn a_refusal_reads_as_policy_and_not_as_a_remote_failure() {
        let rules = rules(&["git-upload-pack /srv/repo.git"]);
        let reason = refusal(command_matches(&rules, b"uname -a"));
        assert!(reason.starts_with("network.allow_ssh refused"), "{reason}");
        assert!(reason.contains("uname -a"), "{reason}");
    }

    fn command_with_metacharacter() -> impl Strategy<Value = String> {
        (
            "[ -~]{0,16}",
            proptest::sample::select(METACHARACTERS),
            "[ -~]{0,16}",
        )
            .prop_map(|(prefix, found, suffix)| format!("{prefix}{found}{suffix}"))
    }

    proptest! {
        #[test]
        fn any_command_carrying_a_metacharacter_is_refused(
            rule in "[ -~]{0,32}",
            requested in command_with_metacharacter(),
        ) {
            let decision = command_matches(&[rule], requested.as_bytes());
            prop_assert!(matches!(decision, CommandDecision::Refused(_)), "{decision:?}");
        }
    }
}
