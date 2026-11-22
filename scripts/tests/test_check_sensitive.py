"""
Tests for the pre-commit sensitive-data check (scripts/install-sensitive-hooks.sh
-> .git/hooks/pre-commit -> scripts/check_sensitive.py at the trusted ref).

Every test drives a REAL `git commit` in a throwaway repository set up the way
scripts/README.md documents: the scanner is committed, `origin/main` points at
that commit, and this checkout's installer has written the hook wrappers into
the repository's own hooks directory. What is exercised is the installed hook
path end to end, not the scanner in isolation.

All sensitive-looking values below are synthetic (documentation IP ranges,
AWS's own example-shaped ids, a made-up org term). They are assembled by
concatenation so this file does not trip the check it tests.

Run: python3 -m pytest scripts/tests/test_check_sensitive.py
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
HOOKS_DIR = REPO_ROOT / ".githooks"
SCANNER = REPO_ROOT / "scripts" / "check_sensitive.py"
INSTALLER = REPO_ROOT / "scripts" / "install-sensitive-hooks.sh"
SCANNER_PATH = "scripts/check_sensitive.py"
TEMPLATE = REPO_ROOT / ".check_sensitive_local.example.yaml"
LOCAL_YAML = ".check_sensitive_local.yaml"

FAKE_TERM = "zz-fake-org-term"
INSTANCE_ID = "i-" + "0123456789abcdef0"
SHORT_VOLUME_ID = "vol-" + "0a1b2c3d"
SECURITY_GROUP_ID = "sg-" + "0123456789abcdef0"
EC2_PUBLIC_US_EAST_1 = "ec2-" + "203-0-113-1.compute-1.amazonaws.com"
EC2_PUBLIC_REGIONAL = "ec2-" + "198-51-100-7.us-west-2.compute.amazonaws.com"
EC2_PRIVATE_US_EAST_1 = "ip-" + "10-0-0-12.ec2.internal"
EC2_PRIVATE_REGIONAL = "ip-" + "10-0-0-12.us-west-2.compute.internal"
ARN_WITH_ACCOUNT = "arn:aws:iam::" + "123456789012" + ":role/example-role"
ECR_REGISTRY = "123456789012" + ".dkr.ecr.us-east-1.amazonaws.com/example:latest"

GENERIC_HITS = [
    INSTANCE_ID,
    SHORT_VOLUME_ID,
    SECURITY_GROUP_ID,
    EC2_PUBLIC_US_EAST_1,
    EC2_PUBLIC_REGIONAL,
    EC2_PRIVATE_US_EAST_1,
    EC2_PRIVATE_REGIONAL,
    ARN_WITH_ACCOUNT,
    ECR_REGISTRY,
]


def _env():
    env = dict(os.environ)
    # Never let the operator's global/system git config (signing, hooks,
    # templates) or an enclosing hook's GIT_* variables leak into the repo
    # under test.
    for var in ("GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE", "GIT_PREFIX",
                "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"):
        env.pop(var, None)
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    return env


def git(repo, *args, check=True):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, env=_env(), check=check,
    )


def install_hooks(repo, env=None):
    return subprocess.run(
        ["bash", str(INSTALLER)],
        cwd=repo, capture_output=True, text=True, env=env or _env(),
    )


def init_repo(path):
    """A repository shaped like a maintainer's clone: the scanner committed on
    main, `origin/main` pointing at it, and the hooks installed."""
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q", "-b", "main")
    git(path, "config", "user.name", "Test")
    git(path, "config", "user.email", "test@example.invalid")
    git(path, "config", "commit.gpgsign", "false")
    (path / "README").write_text("baseline\n")
    (path / "scripts").mkdir()
    shutil.copy2(SCANNER, path / SCANNER_PATH)
    git(path, "add", "README", SCANNER_PATH)
    git(path, "commit", "-q", "--no-verify", "-m", "baseline")
    git(path, "update-ref", "refs/remotes/origin/main", "HEAD")
    installed = install_hooks(path)
    assert installed.returncode == 0, installed.stdout + installed.stderr
    return path


@pytest.fixture
def repo(tmp_path):
    return init_repo(tmp_path / "repo")


def write_local_yaml(repo, text):
    (repo / LOCAL_YAML).write_text(text)


def commit_file(repo, name, content):
    (repo / name).write_text(content)
    git(repo, "add", name)
    return git(repo, "commit", "-m", "add " + name, check=False)


def head_count(repo):
    return int(git(repo, "rev-list", "--count", "HEAD").stdout.strip())


def assert_blocked(result, repo, before):
    assert result.returncode != 0, (
        "expected the pre-commit check to reject the commit, got rc=0\n"
        + result.stdout + result.stderr
    )
    assert head_count(repo) == before, "a rejected commit must not land"


def assert_not_echoed(result, *values):
    out = (result.stdout + result.stderr).casefold()
    for value in values:
        assert value.casefold() not in out, (
            "the check must report rule + location only, never the matched value"
        )


def test_org_term_from_local_yaml_blocks_case_insensitively(repo):
    write_local_yaml(repo, "terms:\n  - " + FAKE_TERM + "\n")
    before = head_count(repo)
    result = commit_file(repo, "notes.txt", "ok\nsee " + FAKE_TERM.upper() + " here\n")
    assert_blocked(result, repo, before)
    assert "notes.txt:2" in result.stderr
    assert "org term #1" in result.stderr
    assert_not_echoed(result, FAKE_TERM)


def test_org_pattern_from_local_yaml_blocks_case_insensitively(repo):
    write_local_yaml(repo, "patterns:\n  - 'zz-cluster-[0-9]+'\n")
    before = head_count(repo)
    result = commit_file(repo, "notes.txt", "node ZZ-CLUSTER-42 is up\n")
    assert_blocked(result, repo, before)
    assert "notes.txt:1" in result.stderr
    assert "org pattern #1" in result.stderr
    assert_not_echoed(result, "zz-cluster-42")


@pytest.mark.parametrize("value", GENERIC_HITS)
def test_generic_aws_identifier_blocks(repo, value):
    write_local_yaml(repo, "terms:\n  - " + FAKE_TERM + "\n")
    before = head_count(repo)
    result = commit_file(repo, "infra.md", "# notes\n\nhost: " + value + "\n")
    assert_blocked(result, repo, before)
    assert "infra.md:3" in result.stderr
    assert_not_echoed(result, value)


@pytest.mark.parametrize("value", [
    # Near-misses that must NOT trip the generic rules.
    "i-" + "0123456",                       # too short for an instance id
    "i-" + "0123456789abcdef",              # 16 hex: neither 8 nor 17
    "my-image-v2",                          # ordinary hyphenated words
    "arn:aws:s3:::example-bucket/key",      # S3 ARN has no account field
    "ec2 instance at 203.0.113.1",          # dotted IP is not an EC2 hostname
    "public.ecr.aws/example/image:latest",  # public ECR alias, no account id
])
def test_near_misses_pass(repo, value):
    write_local_yaml(repo, "terms:\n  - " + FAKE_TERM + "\n")
    before = head_count(repo)
    result = commit_file(repo, "notes.txt", "value: " + value + "\n")
    assert result.returncode == 0, result.stdout + result.stderr
    assert head_count(repo) == before + 1


def test_clean_file_passes_and_lands(repo):
    write_local_yaml(repo, "terms:\n  - " + FAKE_TERM + "\n")
    before = head_count(repo)
    result = commit_file(repo, "notes.txt", "nothing sensitive here\n")
    assert result.returncode == 0, result.stdout + result.stderr
    assert head_count(repo) == before + 1


def test_missing_local_yaml_warns_and_still_applies_generic_rules(repo):
    assert not (repo / LOCAL_YAML).exists()

    before = head_count(repo)
    clean = commit_file(repo, "clean.txt", "nothing sensitive here\n")
    assert clean.returncode == 0, clean.stdout + clean.stderr
    assert head_count(repo) == before + 1
    assert LOCAL_YAML in clean.stderr
    assert "warning" in clean.stderr.lower()

    before = head_count(repo)
    dirty = commit_file(repo, "dirty.txt", "host " + INSTANCE_ID + "\n")
    assert_blocked(dirty, repo, before)
    assert "dirty.txt:1" in dirty.stderr


@pytest.mark.parametrize("text", [
    "terms: []\npatterns: []\n",
    "# every entry deleted\nterms:\npatterns:\n",
])
def test_local_yaml_with_no_entries_warns_like_a_missing_one(repo, text):
    # An empty list gives generic-only coverage; say so, so the operator does
    # not believe org terms are being checked.
    write_local_yaml(repo, text)
    before = head_count(repo)
    result = commit_file(repo, "clean.txt", "nothing sensitive here\n")
    assert result.returncode == 0, result.stdout + result.stderr
    assert head_count(repo) == before + 1
    assert "warning" in result.stderr.lower()
    assert "no org terms" in result.stderr
    assert "generic AWS rules only" in result.stderr


def test_local_yaml_with_entries_does_not_warn(repo):
    write_local_yaml(repo, "terms:\n  - " + FAKE_TERM + "\n")
    result = commit_file(repo, "clean.txt", "nothing sensitive here\n")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "warning" not in result.stderr.lower()


def commit_path(repo, relpath, content):
    target = repo / relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    git(repo, "add", relpath)
    return git(repo, "commit", "-m", "add a file", check=False)


def test_org_term_in_a_file_name_blocks_and_the_path_is_redacted(repo):
    # A path leaks as much as content. The report must not print the path
    # either, or it would echo the term it just matched.
    write_local_yaml(repo, "terms:\n  - " + FAKE_TERM + "\n")
    before = head_count(repo)
    result = commit_path(repo, "deploy/" + FAKE_TERM.upper() + ".conf",
                         "clean\nhost " + INSTANCE_ID + "\n")
    assert_blocked(result, repo, before)
    assert "path redacted" in result.stderr
    assert "org term #1 (in path)" in result.stderr
    # The content hit in the same file is reported under the redacted path.
    assert ":2: aws-resource-id" in result.stderr
    assert_not_echoed(result, FAKE_TERM, INSTANCE_ID)


def test_ec2_hostname_as_a_directory_name_blocks(repo):
    hostdir = EC2_PRIVATE_US_EAST_1.split(".")[0]
    before = head_count(repo)
    result = commit_path(repo, "hosts/" + hostdir + "/notes.txt", "clean\n")
    assert_blocked(result, repo, before)
    assert "ec2-hostname (in path)" in result.stderr
    assert_not_echoed(result, hostdir)


def test_all_files_mode_checks_tracked_paths(repo):
    write_local_yaml(repo, "terms:\n  - " + FAKE_TERM + "\n")
    (repo / (FAKE_TERM + ".md")).write_text("clean\n")
    git(repo, "add", FAKE_TERM + ".md")
    git(repo, "commit", "-q", "--no-verify", "-m", "pre-existing path leak")
    result = subprocess.run(
        ["python3", str(SCANNER), "--all-files"],
        cwd=repo, capture_output=True, text=True, env=_env(),
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "org term #1 (in path)" in result.stderr
    assert_not_echoed(result, FAKE_TERM)


def test_symlink_replaced_by_a_file_is_scanned(repo):
    # A symlink -> regular file change is a type change (status T), not a
    # modification; the new content is still about to be committed.
    os.symlink("README", repo / "link")
    git(repo, "add", "link")
    git(repo, "commit", "-q", "-m", "add a symlink")
    (repo / "link").unlink()
    (repo / "link").write_text("host " + INSTANCE_ID + "\n")
    git(repo, "add", "link")
    assert git(repo, "diff", "--cached", "--name-status").stdout.startswith("T")
    before = head_count(repo)
    result = git(repo, "commit", "-m", "symlink to file", check=False)
    assert_blocked(result, repo, before)
    assert "link:1: aws-resource-id" in result.stderr


def test_no_ff_merge_commit_is_scanned(repo):
    # `git merge` creating a merge commit runs pre-merge-commit, not
    # pre-commit; the content it brings in must still be checked.
    git(repo, "checkout", "-q", "-b", "side")
    (repo / "infra.md").write_text("host " + INSTANCE_ID + "\n")
    git(repo, "add", "infra.md")
    git(repo, "commit", "-q", "--no-verify", "-m", "dirty on side")
    git(repo, "checkout", "-q", "main")
    before = head_count(repo)
    result = git(repo, "merge", "--no-ff", "-m", "merge side", "side", check=False)
    assert_blocked(result, repo, before)
    assert "infra.md:1: aws-resource-id" in result.stderr
    assert_not_echoed(result, INSTANCE_ID)


def test_clean_no_ff_merge_lands(repo):
    git(repo, "checkout", "-q", "-b", "side")
    (repo / "notes.md").write_text("nothing sensitive here\n")
    git(repo, "add", "notes.md")
    git(repo, "commit", "-q", "-m", "clean on side")
    git(repo, "checkout", "-q", "main")
    before = head_count(repo)
    result = git(repo, "merge", "--no-ff", "-m", "merge side", "side", check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert head_count(repo) == before + 2  # side's commit + the merge commit


def test_scans_staged_content_not_working_tree(repo):
    write_local_yaml(repo, "terms:\n  - " + FAKE_TERM + "\n")

    # Staged blob is dirty, working tree was cleaned afterwards but not
    # re-staged: the commit would still publish the dirty blob, so block.
    (repo / "a.txt").write_text("host " + INSTANCE_ID + "\n")
    git(repo, "add", "a.txt")
    (repo / "a.txt").write_text("cleaned in the working tree only\n")
    before = head_count(repo)
    result = git(repo, "commit", "-m", "a", check=False)
    assert_blocked(result, repo, before)

    # Inverse: staged blob is clean, working tree is dirty afterwards. What
    # would be committed is clean, so the commit lands.
    (repo / "a.txt").write_text("clean staged content\n")
    git(repo, "add", "a.txt")
    (repo / "a.txt").write_text("host " + INSTANCE_ID + "\n")
    result = git(repo, "commit", "-m", "a", check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert head_count(repo) == before + 1


def test_commit_all_scans_the_auto_staged_content(repo):
    write_local_yaml(repo, "terms:\n  - " + FAKE_TERM + "\n")
    # README is tracked; `commit -a` stages the modification itself via a
    # temporary index (GIT_INDEX_FILE), which the scan must honour.
    (repo / "README").write_text("baseline\nnow mentions " + FAKE_TERM + "\n")
    before = head_count(repo)
    result = git(repo, "commit", "-a", "-m", "edit", check=False)
    assert_blocked(result, repo, before)
    assert "README:2" in result.stderr


def test_malformed_local_yaml_fails_closed(repo):
    # Missing the "- " list marker: the term list cannot be trusted, so the
    # commit is refused rather than silently scanned with no org terms.
    write_local_yaml(repo, "terms:\n  " + FAKE_TERM + "\n")
    before = head_count(repo)
    result = commit_file(repo, "notes.txt", "nothing sensitive here\n")
    assert_blocked(result, repo, before)
    assert LOCAL_YAML in result.stderr
    assert_not_echoed(result, FAKE_TERM)


def test_local_yaml_in_main_checkout_applies_to_linked_worktrees(repo, tmp_path):
    write_local_yaml(repo, "terms:\n  - " + FAKE_TERM + "\n")
    wt = tmp_path / "wt"
    git(repo, "worktree", "add", "-q", "-b", "side", str(wt))
    assert not (wt / LOCAL_YAML).exists()
    before = head_count(wt)
    result = commit_file(wt, "notes.txt", "see " + FAKE_TERM + "\n")
    assert_blocked(result, wt, before)
    assert "org term #1" in result.stderr


def test_worktree_local_yaml_takes_precedence_over_the_main_checkout(repo, tmp_path):
    # The worktree's own list replaces (does not merge with) the main
    # checkout's: a term only the main list has is not checked there.
    other_term = "zz-other-org-term"
    write_local_yaml(repo, "terms:\n  - " + FAKE_TERM + "\n")
    wt = tmp_path / "wt"
    git(repo, "worktree", "add", "-q", "-b", "side", str(wt))
    write_local_yaml(wt, "terms:\n  - " + other_term + "\n")

    before = head_count(wt)
    result = commit_file(wt, "a.txt", "see " + other_term + "\n")
    assert_blocked(result, wt, before)
    assert "org term #1" in result.stderr
    git(wt, "rm", "-q", "--cached", "a.txt")  # drop the rejected file

    result = commit_file(wt, "b.txt", "see " + FAKE_TERM + "\n")
    assert result.returncode == 0, result.stdout + result.stderr
    assert head_count(wt) == before + 1


def test_template_copied_verbatim_does_not_block_committing_the_template(repo):
    # The template's placeholders all carry the reserved `example-` prefix, so
    # a verbatim copy contributes no org entries: the template commits, and
    # the operator is told no org terms are in effect.
    shutil.copy(TEMPLATE, repo / LOCAL_YAML)
    shutil.copy(TEMPLATE, repo / TEMPLATE.name)
    git(repo, "add", TEMPLATE.name)
    before = head_count(repo)
    result = git(repo, "commit", "-m", "template", check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert head_count(repo) == before + 1
    assert "placeholder" in result.stderr
    assert "no org terms" in result.stderr


def test_real_term_added_to_the_template_is_blocked(repo):
    # The committed template is the tracked file most likely to receive the
    # real list by mistake; it is scanned like any other file. The placeholder
    # line is dropped from the local list first, so the real term is entry #1.
    write_local_yaml(repo, "terms:\n  - example-internal-project\n  - "
                     + FAKE_TERM + "\n")
    leaked = TEMPLATE.read_text().replace(
        "terms:\n", "terms:\n  - " + FAKE_TERM + "\n", 1)
    assert FAKE_TERM in leaked
    before = head_count(repo)
    result = commit_file(repo, TEMPLATE.name, leaked)
    assert_blocked(result, repo, before)
    assert TEMPLATE.name + ":" in result.stderr
    assert "org term #1" in result.stderr
    assert "org term #2" not in result.stderr
    assert_not_echoed(result, FAKE_TERM)


def test_placeholder_prefixed_local_entries_are_ignored(repo):
    write_local_yaml(repo, "terms:\n  - example-internal-project\n"
                     "patterns:\n  - 'example-host-[0-9]+'\n")
    before = head_count(repo)
    result = commit_file(repo, "notes.txt",
                         "example-internal-project on example-host-7\n")
    assert result.returncode == 0, result.stdout + result.stderr
    assert head_count(repo) == before + 1
    assert "2 placeholder" in result.stderr


def test_all_files_mode_audits_every_tracked_file(repo):
    write_local_yaml(repo, "terms:\n  - " + FAKE_TERM + "\n")
    (repo / "old.txt").write_text("legacy " + EC2_PRIVATE_REGIONAL + "\n")
    git(repo, "add", "old.txt")
    git(repo, "commit", "-q", "--no-verify", "-m", "pre-existing leak")

    result = subprocess.run(
        ["python3", str(SCANNER), "--all-files"],
        cwd=repo, capture_output=True, text=True, env=_env(),
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "old.txt:1" in result.stderr

    git(repo, "rm", "-q", "old.txt")
    git(repo, "commit", "-q", "--no-verify", "-m", "drop it")
    result = subprocess.run(
        ["python3", str(SCANNER), "--all-files"],
        cwd=repo, capture_output=True, text=True, env=_env(),
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_local_yaml_is_gitignored_and_template_is_tracked():
    ignored = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "check-ignore", "-q", LOCAL_YAML],
        env=_env(),
    )
    assert ignored.returncode == 0, LOCAL_YAML + " must be gitignored"
    template = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "check-ignore", "-q", TEMPLATE.name],
        env=_env(),
    )
    assert template.returncode == 1, TEMPLATE.name + " must NOT be ignored"
    tracked = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files", "--error-unmatch", TEMPLATE.name],
        capture_output=True, env=_env(),
    )
    assert tracked.returncode == 0, TEMPLATE.name + " must be tracked"
    assert "terms:" in TEMPLATE.read_text()


def copy_check_into(repo):
    """Vendor the hook, scanner, template and this test file into `repo` at
    their real relative paths, and stage them."""
    files = [
        HOOKS_DIR / "pre-commit",
        HOOKS_DIR / "pre-merge-commit",
        SCANNER,
        INSTALLER,
        Path(__file__).resolve(),
        TEMPLATE,
    ]
    for src in files:
        dst = repo / src.relative_to(REPO_ROOT)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)  # keeps the executable bit
        git(repo, "add", str(src.relative_to(REPO_ROOT)))


def test_this_change_does_not_trip_its_own_check(repo):
    # The hook, scanner, template and this test file must be committable with
    # the hook enabled (no local yaml: generic rules only).
    copy_check_into(repo)
    before = head_count(repo)
    result = git(repo, "commit", "-m", "self", check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert head_count(repo) == before + 1


# ── Hook code comes from the trusted ref, never the checked-out branch ──────
#
# A maintainer reviews a contributor's branch by checking it out. Whatever that
# branch carries in .githooks/ or scripts/check_sensitive.py must not run when
# the maintainer then commits or merges there: it would execute with the
# maintainer's privileges before anyone reviewed it.

HOSTILE_SCANNER = (
    "import pathlib, sys\n"
    "pathlib.Path({marker!r}).write_text('branch scanner ran')\n"
    "sys.exit(0)\n"
)
HOSTILE_HOOK = "#!/bin/sh\necho 'branch hook ran' > {marker!r}\nexit 0\n"


def contributor_branch(repo, tmp_path):
    """Check out a branch whose scanner and .githooks/ both drop a marker file
    and wave every commit through. Returns the marker paths."""
    markers = [tmp_path / "scanner-ran", tmp_path / "hook-ran"]
    git(repo, "checkout", "-q", "-b", "contrib")
    (repo / SCANNER_PATH).write_text(HOSTILE_SCANNER.format(marker=str(markers[0])))
    (repo / ".githooks").mkdir(exist_ok=True)
    for name in ("pre-commit", "pre-merge-commit"):
        hook = repo / ".githooks" / name
        hook.write_text(HOSTILE_HOOK.format(marker=str(markers[1])))
        hook.chmod(0o755)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--no-verify", "-m", "contributor change")
    return markers


def test_a_branch_cannot_replace_the_scanner_or_the_hooks(repo, tmp_path):
    markers = contributor_branch(repo, tmp_path)
    before = head_count(repo)
    result = commit_file(repo, "infra.md", "host " + INSTANCE_ID + "\n")
    # The trusted scanner ran (and blocked); the branch's code did not.
    assert_blocked(result, repo, before)
    assert "infra.md:1: aws-resource-id" in result.stderr
    for marker in markers:
        assert not marker.exists(), marker.read_text()


def test_a_branch_cannot_replace_the_scanner_for_a_merge_commit(repo, tmp_path):
    markers = contributor_branch(repo, tmp_path)
    git(repo, "checkout", "-q", "-b", "side", "main")
    (repo / "infra.md").write_text("host " + INSTANCE_ID + "\n")
    git(repo, "add", "infra.md")
    git(repo, "commit", "-q", "--no-verify", "-m", "dirty on side")
    git(repo, "checkout", "-q", "contrib")
    before = head_count(repo)
    result = git(repo, "merge", "--no-ff", "-m", "merge side", "side", check=False)
    assert_blocked(result, repo, before)
    assert "infra.md:1: aws-resource-id" in result.stderr
    for marker in markers:
        assert not marker.exists(), marker.read_text()


def test_the_trusted_ref_is_what_runs_after_it_moves(repo):
    # A reviewed change to the scanner reaches the hook once it is on the
    # trusted ref: here a main whose scanner rejects every commit.
    (repo / SCANNER_PATH).write_text("import sys\nsys.exit(7)\n")
    git(repo, "commit", "-q", "--no-verify", "-am", "scanner rejects all")
    before = head_count(repo)
    assert commit_file(repo, "a.txt", "clean\n").returncode == 0
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    assert_blocked(commit_file(repo, "b.txt", "clean\n"), repo, before + 1)


@pytest.mark.parametrize("shadow", ["refs/tags/origin/main", "refs/heads/origin/main"])
def test_a_ref_named_like_the_trusted_ref_does_not_shadow_it(repo, tmp_path, shadow):
    # A remote added to review a fork fetches that fork's tags, and a branch
    # can be named anything. A tag or branch spelled `origin/main` outranks
    # refs/remotes/origin/main in git's short-name lookup, so the hooks must
    # resolve the full refname.
    marker = tmp_path / "scanner-ran"
    git(repo, "checkout", "-q", "-b", "fork")
    (repo / SCANNER_PATH).write_text(HOSTILE_SCANNER.format(marker=str(marker)))
    git(repo, "commit", "-q", "--no-verify", "-am", "hostile scanner")
    git(repo, "update-ref", shadow, "HEAD")
    git(repo, "checkout", "-q", "main")
    before = head_count(repo)
    result = commit_file(repo, "infra.md", "host " + INSTANCE_ID + "\n")
    assert_blocked(result, repo, before)
    assert "infra.md:1: aws-resource-id" in result.stderr
    assert not marker.exists(), marker.read_text()


def test_the_scanner_does_not_import_modules_from_the_temp_dir(repo, tmp_path):
    # The scanner blob is written to a temp file; running it must not put a
    # shared temp directory on sys.path, where another local user could plant
    # a module the scanner imports (it imports `subprocess`).
    marker = tmp_path / "module-ran"
    shared = tmp_path / "shared-tmp"
    shared.mkdir()
    (shared / "subprocess.py").write_text(
        "import pathlib\npathlib.Path(%r).write_text('planted module ran')\n"
        "raise SystemExit(0)\n" % str(marker))
    (repo / "infra.md").write_text("host " + INSTANCE_ID + "\n")
    git(repo, "add", "infra.md")
    before = head_count(repo)
    result = subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "add infra.md"],
        capture_output=True, text=True, env=dict(_env(), TMPDIR=str(shared)),
    )
    assert not marker.exists(), marker.read_text()
    assert_blocked(result, repo, before)
    assert "infra.md:1: aws-resource-id" in result.stderr


def test_the_scanner_ignores_pythonpath(repo, tmp_path):
    # `python3 -I` keeps PYTHON* variables off sys.path. A committer whose
    # shell exports PYTHONPATH into a checkout (or anywhere a branch can write)
    # must not have the trusted scanner import that directory's modules in
    # place of the standard library. The private temp dir alone does not cover
    # this; only -I does.
    marker = tmp_path / "module-ran"
    planted = tmp_path / "on-pythonpath"
    planted.mkdir()
    (planted / "subprocess.py").write_text(
        "import pathlib\npathlib.Path(%r).write_text('planted module ran')\n"
        "raise SystemExit(0)\n" % str(marker))
    (repo / "infra.md").write_text("host " + INSTANCE_ID + "\n")
    git(repo, "add", "infra.md")
    before = head_count(repo)
    result = subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "add infra.md"],
        capture_output=True, text=True, env=dict(_env(), PYTHONPATH=str(planted)),
    )
    assert not marker.exists(), marker.read_text()
    assert_blocked(result, repo, before)
    assert "infra.md:1: aws-resource-id" in result.stderr


def test_a_configured_trusted_ref_is_honoured(repo):
    # Configured by short name, then expanded to its full refname by the
    # installer, which is what the hooks accept.
    git(repo, "branch", "reviewed")
    git(repo, "update-ref", "-d", "refs/remotes/origin/main")
    git(repo, "config", "epigraph.sensitiveHookRef", "reviewed")
    installed = install_hooks(repo)
    assert installed.returncode == 0, installed.stdout + installed.stderr
    assert git(repo, "config", "--get", "epigraph.sensitiveHookRef").stdout.strip() \
        == "refs/heads/reviewed"
    before = head_count(repo)
    result = commit_file(repo, "infra.md", "host " + INSTANCE_ID + "\n")
    assert_blocked(result, repo, before)
    assert "infra.md:1: aws-resource-id" in result.stderr


@pytest.mark.parametrize("value", ["origin/main", "HEAD", "--output=x", "refs/tags/v1"])
def test_a_configured_ref_that_is_not_a_full_branch_name_is_refused(repo, value):
    git(repo, "config", "epigraph.sensitiveHookRef", value)
    before = head_count(repo)
    result = commit_file(repo, "notes.txt", "nothing sensitive here\n")
    assert_blocked(result, repo, before)
    assert "refusing" in result.stderr


@pytest.mark.parametrize("value", ["refs/tags/v1", "-x"])
def test_installer_refuses_a_configured_ref_that_is_not_a_branch(repo, value):
    git(repo, "tag", "v1")
    git(repo, "config", "epigraph.sensitiveHookRef", value)
    result = install_hooks(repo)
    assert result.returncode != 0, result.stdout + result.stderr
    assert "epigraph.sensitiveHookRef" in result.stderr


def test_a_missing_trusted_ref_fails_closed(repo):
    git(repo, "update-ref", "-d", "refs/remotes/origin/main")
    before = head_count(repo)
    result = commit_file(repo, "notes.txt", "nothing sensitive here\n")
    assert_blocked(result, repo, before)
    assert "origin/main" in result.stderr
    assert "refusing" in result.stderr


def test_installer_drops_a_hookspath_into_the_tree(tmp_path):
    # The old setup, core.hooksPath=.githooks, runs the checked-out branch's
    # hooks; the installer must turn it off or its own hooks never run.
    repo = init_repo(tmp_path / "repo")
    git(repo, "config", "core.hooksPath", ".githooks")
    result = install_hooks(repo)
    assert result.returncode == 0, result.stdout + result.stderr
    assert git(repo, "config", "--get", "core.hooksPath", check=False).returncode == 1
    assert "core.hooksPath" in result.stdout + result.stderr


def test_installer_refuses_a_hookspath_it_cannot_unset(tmp_path):
    repo = init_repo(tmp_path / "repo")
    global_config = tmp_path / "global.gitconfig"
    global_config.write_text("[core]\n\thooksPath = " + str(tmp_path / "elsewhere") + "\n")
    env = dict(_env(), GIT_CONFIG_GLOBAL=str(global_config))
    result = install_hooks(repo, env=env)
    assert result.returncode != 0, result.stdout + result.stderr
    assert "core.hooksPath" in result.stderr


def test_installer_keeps_a_hook_it_did_not_write(tmp_path):
    repo = init_repo(tmp_path / "repo")
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\n# someone else's hook\nexit 0\n")
    result = install_hooks(repo)
    assert result.returncode != 0, result.stdout + result.stderr
    assert "someone else's hook" in hook.read_text()


def test_installer_is_idempotent(repo):
    result = install_hooks(repo)
    assert result.returncode == 0, result.stdout + result.stderr
    before = head_count(repo)
    assert_blocked(commit_file(repo, "infra.md", "host " + INSTANCE_ID + "\n"),
                   repo, before)


def test_the_retired_in_tree_hooks_refuse_and_point_at_the_installer(repo):
    # Anyone still on `core.hooksPath .githooks` is running branch-controlled
    # hook code; the in-tree hooks stop every commit and say how to migrate.
    copy_check_into(repo)
    git(repo, "commit", "-q", "--no-verify", "-m", "vendor the check")
    git(repo, "config", "core.hooksPath", ".githooks")
    before = head_count(repo)
    result = commit_file(repo, "notes.txt", "nothing sensitive here\n")
    assert_blocked(result, repo, before)
    assert "install-sensitive-hooks.sh" in result.stderr
    git(repo, "checkout", "-q", "-b", "side")
    git(repo, "commit", "-q", "--no-verify", "--allow-empty", "-m", "side")
    git(repo, "checkout", "-q", "main")
    before = head_count(repo)
    result = git(repo, "merge", "--no-ff", "-m", "merge side", "side", check=False)
    assert_blocked(result, repo, before)
    assert "install-sensitive-hooks.sh" in result.stderr


def test_this_checkout_passes_its_own_audit():
    # The hook is opt-in per clone, so this is the standing whole-tree audit:
    # every tracked file's content and path in THIS checkout, through the real
    # scanner. In CI no local list exists, so it applies the generic rules
    # only; locally it also applies the operator's gitignored list. Findings
    # print path:line and the rule name, never the matched value.
    result = subprocess.run(
        ["python3", str(SCANNER), "--all-files"],
        cwd=REPO_ROOT, capture_output=True, text=True, env=_env(),
    )
    assert result.returncode == 0, result.stderr
