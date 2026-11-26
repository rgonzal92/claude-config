# claude-config

My global Claude Code instructions (`CLAUDE.md`) and safety hooks.

## Install

```sh
git clone https://github.com/rgonzal92/claude-config.git ~/Projects/claude-config
ln -s ~/Projects/claude-config/CLAUDE.md ~/.claude/CLAUDE.md
ln -s ~/Projects/claude-config/hooks ~/.claude/hooks
```

Then add this `hooks` block to `~/.claude/settings.json` (merge with any hooks already there):

```json
"hooks": {
  "PreToolUse": [
    {
      "matcher": "Bash",
      "hooks": [
        { "type": "command", "command": "python3 \"$HOME/.claude/hooks/protect-filesystem.py\"", "timeout": 10 }
      ]
    },
    {
      "matcher": "Read|Edit|Write|MultiEdit|NotebookEdit|Grep|Glob|Bash",
      "hooks": [
        { "type": "command", "command": "python3 \"$HOME/.claude/hooks/protect-secrets.py\"", "timeout": 10 }
      ]
    }
  ]
}
```

## Tests

```sh
python3 -m unittest discover -s tests
```
