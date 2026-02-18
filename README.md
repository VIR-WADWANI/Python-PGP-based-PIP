# PGP-Backed Policy Information Point (PIP) for ABAC Systems

## Overview
This project implements a custom Policy Information Point (PIP) for an Attribute-Based Access Control (ABAC) system.
The core idea is to use PGP certificates as decentralized identity carriers, extract embedded attributes from them, verify their cryptographic validity, and dynamically supply those attributes to a Policy Decision Point (PDP) during policy evaluation.
The system integrates with a Python-based ABAC engine and demonstrates how cryptographic identity artifacts (PGP keys) can serve as trusted attribute sources in modern authorization architectures.

## Project Goals
- Verify and validate PGP public keys
- Extract structured attributes embedded in PGP UID fields
- Convert extracted attributes into structured claims (optionally JWT)
- Provide those attributes to an ABAC PDP as a PIP
- Support validation checks such as:
- Signature integrity
- Expiry
- Revocation status

## Technologies & Libraries Used
### 1. python-gnupg
Used for:
- Generating and managing PGP keys
- Parsing certificates
- Extracting UID information
- Checking expiration and revocation
  
Why needed:
PGP provides cryptographic identity binding and decentralized trust without requiring centralized identity providers.

### 2. py-abac
Used as the ABAC engine:
- Evaluates policies
- Supports custom Attribute Providers (PIP integration)
- Implements XACML-inspired PDP logic
  
Why needed:
Provides a structured Policy Decision Point where attributes can be dynamically resolved via custom PIP logic.

### 3. PyJWT
Used for:
- Creating JSON Web Tokens containing extracted attributes
- Signing attribute claims
- Supporting secure attribute transport
  
Why needed:
JWT provides a compact, standardized representation of attribute claims, allowing separation between identity verification and authorization enforcement.



