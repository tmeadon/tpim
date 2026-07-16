# tpim (Entra PIM TUI)

A simple, elegant, minimal Terminal User Interface (TUI) to browse, activate, deactivate, and extend your eligible roles in Microsoft Entra PIM (Privileged Identity Management).

Built in Go using the [Bubble Tea](https://github.com/charmbracelet/bubbletea) framework.

## Features

- **Asynchronous Operations**: Queries Azure PIM and Microsoft Graph APIs completely in the background using the Azure CLI. The TUI never freezes or blocks.
- **SSH & Headless Friendly**: Integrates Microsoft's secure **Device Code Flow** for Entra ID Directory roles, making it fully operational over SSH sessions.
- **Token Cache**: Persists Entra ID Graph tokens securely in `~/.gemini/antigravity-cli/pim_token.json` for 1 hour. Subsequent starts and refreshes are instant and silent.
- **Unified List**: Displays a consolidated list of your eligible and active roles across both Azure Resources (Subscriptions, Resource Groups, Management Groups) and Entra ID Directory Roles.
- **Deactivation**: Turn off active PIM assignments early when you are done with a task.
- **Extension**: Extend active role assignments that are nearing expiration directly from the TUI.
- **Real-time Countdown**: Active PIM assignments update and countdown their remaining duration second-by-second in real-time.
- **Interactive Form Modal**: Focus-switchable dialog for setting the activation/extension justification and duration (1-24 hours).
- **Clean Diagnostics**: Shows user, tenant, and refresh status details.

## Requirements

- [Go](https://go.dev/) (to build from source)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (`az` command-line tool, logged in to your account context)

## Installation & Building

To compile the application:

```bash
go build -o tpim
```

This generates a standalone binary `tpim` in the project root.

## Usage

1. Ensure you are signed in to the Azure CLI:
   ```bash
   az login
   ```
2. Run the PIM TUI:
   ```bash
   ./tpim
   ```

### Key Bindings

- `↑` / `↓` or `k` / `j` : Navigate the roles list.
- `Enter` / `a` : Open the self-activation dialog for the selected eligible role.
- `d` : Deactivate the selected active role.
- `e` : Extend the selected active role.
- `Tab` / `↑` / `↓` (inside dialog) : Switch between Justification and Duration input fields.
- `Enter` (inside dialog) : Confirm and submit the request.
- `Esc` (inside dialog) : Cancel the dialog.
- `r` : Manually refresh the roles list.
- `Esc` / `q` : Exit the application.
