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

## TalonHound VM (aktif)

- VM IP: `192.168.1.190`
- Hostname: `talonhound`
- SSH user: `spatronn` (root: key ile erişim yok)
- SSH port: `22`
- Auth: Windows host `~/.ssh/id_ed25519`
- Web: `https://192.168.1.190` (self-signed cert beklenir)
- Stack path (sunucu): `/opt/demo-runbook` (henüz rename edilmemiş olabilir)

## Demo VM (arşiv)

- VM IP: `192.168.1.251`
- SSH users: `spatronn`, `root`
- Auth: `~/.ssh/demo_vm_ed25519` (Linux host)

## GitHub Access (TalonHound)

- GitHub user: `spatronn`
- Repo: `https://github.com/spatronn/TalonHound`
- Local path: `C:\Proje\TalonHound`
