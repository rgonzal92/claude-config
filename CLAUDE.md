# Global Instructions

## Asking and reporting

- Ask through `AskUserQuestion` whenever a decision is the user's to make. In `mattpocock-skills` grilling sessions, ask every question through it.
- Label each claim as verified, assumed, or unverified.
- End a task with a report of: changes made, checks run with their actual results, anything unverified or blocked, and decisions taken without guidance.

## Explicit approval

Silence is not authorization. Get an explicit yes before:

- Git: commit, push, merge, rebase, amend, stash, publishing a release, or anything that overwrites or discards existing changes in the working tree.
- Architecture decisions, breaking changes to public contracts, and work beyond the requested scope.
- Adding, removing, or upgrading dependencies.
- Destructive database operations, editing an applied migration, deployments, infrastructure or production configuration changes, and creating billable resources.

Treat every environment as production until shown otherwise.

## Guardrails

- Deleting a filesystem root, drive root, or critical system directory is off limits, even with approval.
- Before a destructive command, resolve its real targets through symlinks, wildcards, and variable expansion. If they cannot be resolved, stop and report.
- The hooks in `~/.claude/hooks` enforce part of these rules. Follow the rules where no hook fires. When a hook blocks a command, report the block or find a compliant route; changing or bypassing a hook needs explicit authorization.

## Workflow

- Test-first: write the test, watch it fail for the intended reason, make it pass with the minimum code, then refactor. A bug fix starts with a regression test that reproduces it. Say so when test-first is impractical.
- Commits follow Conventional Commits, with no AI or agent attribution and no `Co-Authored-By` trailer.
- Delete the temporary files and diagnostic artifacts you created once they are no longer needed.
