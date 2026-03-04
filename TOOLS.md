# TOOLS.md - Local Notes

Skills define _how_ tools work. This file is for _your_ specifics — the stuff that's unique to your setup.

## What Goes Here

Things like:

- Camera names and locations
- SSH hosts and aliases
- Preferred voices for TTS
- Speaker/room names
- Device nicknames
- Anything environment-specific

## Examples

```markdown
### Cameras

- living-room → Main area, 180° wide angle
- front-door → Entrance, motion-triggered

### SSH

- home-server → 192.168.1.100, user: admin

### TTS

- Preferred voice: "Nova" (warm, slightly British)
- Default speaker: Kitchen HomePod
```

## Why Separate?

Skills are shared. Your setup is yours. Keeping them apart means you can update skills without losing your notes, and share skills without leaking your infrastructure.

---

Add whatever helps you do your job. This is your cheat sheet.

## Demo VM

- VM IP: `192.168.1.251`
- SSH user: `spatronn`
- SSH port: `22`
- Auth: password-based login (password not stored in this file)
- Notes: same subnet demo target
- Privilege flow: SSH as `spatronn`, then elevate with `sudo su` for root tasks
- SSH secret path (host): `/home/spatronn/.openclaw/secrets/ssh.env` (chmod 600)

## GitHub Access (demo-runbook)

- GitHub user: `spatronn`
- Repo: `https://github.com/spatronn/demo-runbook`
- Token policy: PAT is repo-scoped for demo project operations
- Security: PAT value is **not** stored in plaintext in workspace files
- Local secret path (host): `/home/spatronn/.openclaw/secrets/github.env` (chmod 600)
- Git credential store: `/home/spatronn/.git-credentials` (chmod 600)
