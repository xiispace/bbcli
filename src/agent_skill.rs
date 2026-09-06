//! The agent skill shipped inside the binary. `bbcli install-skill` writes a
//! copy into the agent's skills directory.
//!
//! The text is embedded from `skills/bytebase/SKILL.md` at build time, so an
//! installed copy can never describe a different bbcli than the one that wrote
//! it. That is the whole point: the skill is the agent's only description of
//! this CLI's surface, and a hand-copied one silently rots the moment a
//! command changes. Re-running `install-skill` after an upgrade is the entire
//! sync story.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};

/// The agent skill, embedded at build time. `skills/bytebase/SKILL.md` stays
/// the reviewable source of truth; this is the copy that ships.
pub const SKILL_MD: &str = include_str!("../skills/bytebase/SKILL.md");

/// Directory name for the installed skill. Must equal the `name:` in the
/// frontmatter — that is what the agent host matches on.
const SKILL_NAME: &str = "bytebase";

/// What `install` did, so the caller reports it without re-reading the file.
#[derive(Debug)]
pub enum Installed {
    /// Created, or rewritten over a differing copy.
    Written(PathBuf),
    /// Already byte-identical with the bundled skill; nothing done.
    Unchanged(PathBuf),
}

/// Writes the bundled skill to `dest` (default: Claude Code's user-level
/// skills directory), creating parent directories as needed.
///
/// An existing file that already matches is reported as `Unchanged` rather
/// than refused: re-running this after every upgrade is the intended habit, so
/// the no-op case must not demand `--force`. A file that *differs* is someone's
/// edit — that one needs `--force`.
pub fn install(dest: Option<PathBuf>, force: bool) -> Result<Installed> {
    let path = match dest {
        Some(p) => p,
        None => default_install_path()?,
    };

    if let Ok(existing) = std::fs::read_to_string(&path) {
        if existing == SKILL_MD {
            return Ok(Installed::Unchanged(path));
        }
        if !force {
            bail!(
                "{} exists and differs from the bundled skill; pass --force to overwrite",
                path.display()
            );
        }
    }

    // `parent()` is `Some("")` for a bare filename, which create_dir_all rejects.
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    std::fs::write(&path, SKILL_MD)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(Installed::Written(path))
}

/// `~/.claude/skills/bytebase/SKILL.md` — Claude Code's user-level skill
/// directory. Project-level installs and other agent hosts go through
/// `--dest`; there is no host table until a second host actually needs one.
pub fn default_install_path() -> Result<PathBuf> {
    let home = dirs::home_dir()
        .context("could not determine the home directory; pass --dest with a path")?;
    Ok(home
        .join(".claude")
        .join("skills")
        .join(SKILL_NAME)
        .join("SKILL.md"))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DirGuard(PathBuf);
    impl Drop for DirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Unique scratch dir per test, same idiom as the store tests (no
    /// dev-dependency for a directory).
    fn scratch(line: u32) -> (PathBuf, DirGuard) {
        let dir = std::env::temp_dir().join(format!("bbcli-skill-{}-{line}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        (dir.clone(), DirGuard(dir))
    }

    /// The host discovers and triggers the skill from these two frontmatter
    /// fields. If either is lost the skill installs fine and never fires, so
    /// assert on them rather than on the file merely being non-empty.
    #[test]
    fn bundled_skill_carries_the_frontmatter_the_host_matches_on() {
        assert!(
            SKILL_MD.starts_with("---\n"),
            "frontmatter must open the file"
        );
        let name = SKILL_MD
            .lines()
            .find_map(|l| l.strip_prefix("name: "))
            .expect("frontmatter has a name");
        assert_eq!(name.trim(), SKILL_NAME, "name must match the install dir");
        let desc = SKILL_MD
            .lines()
            .find_map(|l| l.strip_prefix("description: "))
            .expect("frontmatter has a description");
        assert!(
            desc.len() > 40,
            "description is what the model matches on; got {} chars",
            desc.len()
        );
    }

    #[test]
    fn writes_the_bundled_skill_creating_parent_dirs() {
        let (dir, _guard) = scratch(line!());
        let dest = dir.join("skills").join("bytebase").join("SKILL.md");

        let out = install(Some(dest.clone()), false).unwrap();
        assert!(matches!(out, Installed::Written(_)));
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), SKILL_MD);
    }

    /// Re-running after an upgrade must be a safe no-op — if this needed
    /// --force, nobody would keep the installed copy in sync.
    #[test]
    fn reinstalling_an_identical_copy_is_a_no_op() {
        let (dir, _guard) = scratch(line!());
        let dest = dir.join("SKILL.md");
        install(Some(dest.clone()), false).unwrap();

        let out = install(Some(dest.clone()), false).unwrap();
        assert!(matches!(out, Installed::Unchanged(_)));
    }

    #[test]
    fn refuses_to_clobber_a_differing_file_without_force() {
        let (dir, _guard) = scratch(line!());
        let dest = dir.join("SKILL.md");
        std::fs::write(&dest, "hand-edited\n").unwrap();

        let err = install(Some(dest.clone()), false).unwrap_err();
        assert!(err.to_string().contains("--force"), "{err}");
        assert_eq!(
            std::fs::read_to_string(&dest).unwrap(),
            "hand-edited\n",
            "a refused install must not have written"
        );
    }

    #[test]
    fn force_overwrites_a_differing_file() {
        let (dir, _guard) = scratch(line!());
        let dest = dir.join("SKILL.md");
        std::fs::write(&dest, "hand-edited\n").unwrap();

        install(Some(dest.clone()), true).unwrap();
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), SKILL_MD);
    }

    #[test]
    fn default_path_is_the_claude_code_user_skill_dir() {
        let p = default_install_path().unwrap();
        let tail: PathBuf = [".claude", "skills", "bytebase", "SKILL.md"]
            .iter()
            .collect();
        assert!(p.ends_with(&tail), "got {}", p.display());
    }
}
