# SerpiumVPN v1.0.21 — Global Button Theme Fix

- Adds one implicit Serpium button template at application level.
- Removes the default WPF light-blue hover state across MainWindow and SettingsWindow.
- Preserves each button's existing base color: dark, green, blue, or red.
- Hover uses a subtle neutral white overlay.
- Pressed uses a subtle dark overlay.
- Disabled buttons use consistent reduced opacity.
- Keyboard focus uses a Serpium-green border.
- Repairs RelayButtonStyle with the same interaction behavior.
- Does not change Relay logic, branding, settings layout, or session persistence.
