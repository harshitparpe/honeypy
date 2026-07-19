# HONEYPY Threat Intel Report

Generated: 2026-07-19T13:38:37

**Observation window:** 2026-07-19 13:26:54.107000 -> 2026-07-19 13:27:30.157000 (0:00:36.050000)

## Summary

- Total login attempts (SSH + HTTP): **7**
- Unique source IPs: **1**
- SSH login attempts: **3**
- HTTP login attempts: **4**
- Commands executed inside the fake shell: **2**

## Top Source IPs

| IP | Attempts |
| --- | --- |
| 127.0.0.1 | 7 |

## Top Usernames Attempted

| Username | Count |
| --- | --- |
| admin | 5 |
| root | 1 |
| johndoe | 1 |

## Top Passwords Attempted

| Password | Count |
| --- | --- |
| admin | 2 |
| lol | 1 |
| amirjohnson | 1 |
| password123 | 1 |
| pass | 1 |
| password | 1 |

## Top Username:Password Pairs

| Pair | Count |
| --- | --- |
| admin:admin | 2 |
| root:lol | 1 |
| johndoe:amirjohnson | 1 |
| admin:password123 | 1 |
| admin:pass | 1 |
| admin:password | 1 |

## Commands Executed by Attackers

| Command | Count |
| --- | --- |
| ls | 1 |
| whoami | 1 |

## IPs That Executed Commands (i.e. got past auth)

| IP | Commands Run |
| --- | --- |
| 127.0.0.1 | 2 |

- Attackers who read the canary file (`cat jumpbox1.conf`): **0**

## Notes for the Write-Up

- Cross-reference top IPs against an IP-reputation lookup (e.g. AbuseIPDB, Shodan) manually if you want attribution — this script stays offline by design.
- A high ratio of unique IPs to total attempts suggests broad automated scanning; a low ratio suggests a smaller number of persistent/targeted sources.
- Common username/password pairs matching known default-credential lists (e.g. admin/admin, root/123456) indicate credential-stuffing bots rather than targeted human attackers.
