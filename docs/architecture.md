# Architecture & Memory Model

`datamasking-core` is designed as a pure, stateless **AST transformation compiler** with zero network, database, or filesystem side effects.

---

## 1. Architectural Boundary

```text
+-------------------------------------------------------------------+
|  Caller Application (REST Gateway / Airflow / Spark / CLI)        |
|  - AuthN/AuthZ (OIDC, API Keys)   - Secret / KMS salt retrieval   |
|  - Rate limiting & HTTP routing   - Audit log persistence         |
+---------------------------------+---------------------------------+
                                  |
                     bytes / dict + MaskingPolicy
                                  v
+-------------------------------------------------------------------+
|                        datamasking-core                           |
|                                                                   |
|  [Policy Loader] ---> Immutable MaskingPolicy (Pydantic v2)       |
|                                                                   |
|  [FormatAdapter.parse] ---> Mutable AST (NodeWrapper / lxml)      |
|         |                                                         |
|         +--> Phase 0: Subtree Scope Resolution                    |
|         +--> Phase 1: Non-Mutating Selector Indexing              |
|         +--> Phase 2: Priority & Specificity Conflict Resolution  |
|         +--> Phase 3: Pluggable Technique Dispatch / Dry-Run      |
|         +--> Phase 4: Record-Level k-Anonymity Engine             |
|         v                                                         |
|  [FormatAdapter.serialize] ---> PipelineResult (UTF-8 bytes +     |
|                                 conflicts, warnings, k-report)    |
+-------------------------------------------------------------------+
```

### What Lives in `datamasking-core` vs. Upstream Services

| Concern | `datamasking-core` | Upstream Gateway / Data Pipeline |
| :--- | :---: | :---: |
| Policy schema & validation | Yes | Loads YAML from DB/Git/config |
| AST parsing, indexing, conflict resolution | Yes | No |
| Masking techniques & `k`-anonymity | Yes | No |
| Authentication, JWT/OIDC, RBAC identity mapping | No | Yes (passes resolved `role: str \| None`) |
| Secret storage / KMS rotation | No | Yes (passes `salt: str`) |
| Databases, Redis, HTTP servers, telemetry | No | Yes |

---

## 2. Why Multi-Phase AST Compilation Instead of Single-Pass Mutation?

Naive masking libraries iterate through rules one by one, mutating the document immediately as each rule runs. That approach breaks down on real policies for three reasons:

1. **Order-Dependent Bugs on Overlapping Selectors**: If rule 1 (`$..email` -> `redact`) runs before rule 2 (`$.patients[*].email` -> `pseudonymize`), rule 2 ends up pseudonymizing the literal string `"[REDACTED]"`. Separating **Phase 1 (Indexing)** and **Phase 2 (Conflict Resolution)** from **Phase 3 (Application)** guarantees every node is transformed at most once by its single highest-precedence rule.
2. **Filter Predicate Corruption**: If rule A generalizes `age` from `16` to `"15-19"` before rule B evaluates `$.patients[?(@.age < 18)].name`, rule B fails to match or crashes with a type comparison error. Indexing all selectors prior to mutation preserves exact predicate semantics.
3. **Subtree Suppression Safety**: Deleting a parent container (`suppress` or `drop_subtree`) severs child pointers in the AST. Phase 3 checks `adapter.is_attached(node)` on every candidate before applying leaf rules so orphaned descendants are cleanly skipped.

---

## 3. Compute, Memory Footprint, and Concurrency

### In-Memory Compute Characteristics
- **CPU-Bound & Synchronous**: Parsing, JSONPath/XPath evaluation, HMAC-SHA256 hashing, and serialization execute purely in memory with zero I/O waits. In `asyncio` web frameworks (such as FastAPI), run large payloads (> 1 MB) via `asyncio.to_thread(engine.mask, ...)` to avoid blocking the event loop.
- **Compiled Selector Caching**: `JSONAdapter` caches parsed `jsonpath_ng.ext` ASTs in an `@lru_cache(maxsize=512)`, amortizing grammar parsing cost across repeated calls.

### Memory Footprint
Because DOM/AST-based evaluation (such as recursive descent `..`, filter predicates, and dataset-wide `k`-anonymity equivalence classes) requires random access across the document tree, the full document resides in RAM during a `mask()` call:
- Peak memory per concurrent call is roughly **3x to 6x** the raw UTF-8 input size (raw input bytes + parsed AST wrapper nodes + serialized output bytes).
- Use `max_input_bytes` on `engine.mask(..., max_input_bytes=10_485_760)` in untrusted network services to bound per-request memory consumption.
- For multi-gigabyte tabular datasets, partition rows into batches upstream (note that `k`-anonymity guarantees apply per batch when partitioned).

### Thread Safety
- `MaskingPolicy` and `MaskingEngine` are **immutable after construction** and safe to share across threads and requests.
- Each `engine.mask(...)` invocation allocates its own AST, `MaskingContext`, and isolated `random.Random` instance, sharing zero mutable state with concurrent calls.

