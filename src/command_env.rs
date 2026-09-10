//! Environment handling for the child process, matching `std::process`:
//! unmodified commands inherit the parent environment wholesale; any explicit
//! mutation captures a full effective environment before fork.

use std::collections::BTreeMap;
use std::env;
use std::ffi::{OsStr, OsString};

#[derive(Debug, Default, Clone)]
pub struct CommandEnv {
    clear: bool,
    vars: BTreeMap<OsString, Option<OsString>>,
}

impl CommandEnv {
    pub fn set(&mut self, key: &OsStr, value: &OsStr) {
        self.vars.insert(key.to_owned(), Some(value.to_owned()));
    }

    pub fn remove(&mut self, key: &OsStr) {
        self.vars.insert(key.to_owned(), None);
    }

    pub fn clear(&mut self) {
        self.vars.clear();
        self.clear = true;
    }

    pub fn get_does_clear(&self) -> bool {
        self.clear
    }

    /// The effective environment if the command was spawned right now, or
    /// None when nothing was explicitly changed and the child should simply
    /// inherit the parent's `environ`.
    pub fn capture_if_changed(&self) -> Option<BTreeMap<OsString, OsString>> {
        (self.get_does_clear() || !self.vars.is_empty()).then(|| self.capture())
    }

    fn capture(&self) -> BTreeMap<OsString, OsString> {
        let mut result = BTreeMap::new();
        if !self.clear {
            for (k, v) in env::vars_os() {
                result.insert(k, v);
            }
        }
        for (k, maybe) in &self.vars {
            match maybe {
                Some(v) => {
                    result.insert(k.clone(), v.clone());
                }
                None => {
                    result.remove(k);
                }
            }
        }
        result
    }

    /// Whether any change has touched PATH (mirrors std's diagnostics hook).
    pub fn have_changed_path(&self) -> bool {
        self.vars.iter().any(|(k, _)| k == "PATH")
    }
}
