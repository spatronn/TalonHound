# MEMORY.md - Long-Term Memory

## User Preferences

- Kullanıcıya hitap: **kirvem**.
- Tekrarlayan onboarding istemiyor; session başında mevcut kalıcı notlardan ilerlenmeli.
- Erişim/doğrulama istenirse önce sistemde kontrol edip net sonuç verilmeli.

## Infrastructure Facts (Persistent)

- Demo hedef host: `192.168.1.251`
  - SSH erişimi mevcut (`spatronn` ve `root`) via `~/.ssh/demo_vm_ed25519`.
- GitHub erişimi mevcut:
  - SSH key: `~/.ssh/demo_runbook_deploy`
  - Repo: `git@github.com:spatronn/demo-runbook.git`
- `~/.ssh/id_ed25519` GitHub auth için geçersiz.
