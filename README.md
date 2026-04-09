# PGP-Backed Policy Information Point (PIP) for ABAC Systems

## Overview
This project implements a custom Policy Information Point (PIP) for an Attribute-Based Access Control (ABAC) system.
The core idea is to use PGP certificates as decentralized identity carriers, extract embedded attributes from them, verify their cryptographic validity, and dynamically supply those attributes to a Policy Decision Point (PDP) during policy evaluation.
The system integrates with a Python-based ABAC engine and demonstrates how cryptographic identity artifacts (PGP keys) can serve as trusted attribute sources in modern authorization architectures.

## Project Goals
- Verify and validate PGP public keys
- Extract structured attributes embedded in PGP UID fields
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

## Project Structure

The project consists of three main files:


### 1. `main.py`

This is the **entry point** of the system.

- Creates and configures the **Policy Decision Point (PDP)** using `py-abac`
- Defines **access control policies** in JSON format
- Constructs **requests** containing subject, resource, and action
- Calls the PDP using `.is_allowed()` to evaluate requests
- Automatically triggers the PIP when required attributes are missing
- Produces a final **Permit/Deny decision**

---

### 2. `PGPPIP.py`

This file contains the custom **Policy Information Point (PIP)** implementation.

- Defines the `PGPPIP` class which **inherits from `AttributeProvider`**
- Integrates with the `py-abac` PDP for dynamic attribute retrieval
- Implements the required method:

  ```python
  get_attribute_value(attribute_path, ctx, ace)
  ```
  **Key Responsibilities:**
  - Extract fingerprint from request context
  - Retrieve PGP certificate using GnuPG
  - Validate certificate:
    - Check existence
    - Check expiry
    - Verify trusted signers
  - Extract JWT embedded in certificate UID
  - Verify JWT signature
  - Decode JWT payload
  - Return requested attribute to the PDP

---

### 3. `Cert_Generation.py`

This file is used for **generating PGP certificates**.

- Uses the `python-gnupg` library
- Creates user certificates in the required format
- Encodes user attributes (e.g., role, department) into a JWT
- Embeds the JWT inside the certificate UID (`name_comment`)

## Certificate Signing Setup

Certificates are signed using GnuPG commands via the terminal.

**Generate Authority Keys:**
`gpg --full-generate-key`

Two Authority keys were created using this for testing purposes and example scenarios.

**Sign user certificate using authority key:**
`gpg --local-user <authority_fingerprint> --sign-key <user_fingerprint>`

This allows multiple authorities to sign a single certificate, thus enabling **decentralised trust model**.

**List all signers of a certificate:**
`gpg --list-sigs --with-colons <certificate_fingerprint>`

This command is used by the PIP to retrieve and validate certificate signers.

## System Workflow

Request → PDP → (missing attribute) → PIP → Extract PGP → Extract JWT → Decode attributes → Return attribute → PDP evaluates → Decision