# Changelog

## 1.0.0 - 2026-10-28

- First release.
- Phishing-resistant MFA readiness per user from Microsoft Graph's registration report and sign-in logs: ready, needs registration, needs a security key, blocked, with single-credential warnings.
- Blockers from real traffic: legacy protocols, ROPC, device code flow, operating systems below Microsoft's minimums, Linux desktops.
- Token Protection readiness from each sign-in's binding status (tokenProtectionStatusDetails), with reason codes, inference when telemetry is missing, and the Android/Linux coverage gap.
- Personas from Microsoft's deployment guidance; wave plan sized to help desk capacity; 60-day communications countdown; .ics calendar.
- Report-only Conditional Access policies per wave (phishing-resistant authentication strength and Token Protection) in the Conditional Access Policy Library format.
