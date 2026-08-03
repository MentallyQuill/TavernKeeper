# TavernKeeper Development Rules

Production scan evaluation and publication are fully automated. Development
canaries may be inspected while a new pipeline is being proven, but no
production scan, contextual assessment, report publication, Tavernary import,
final Tavernary grade, or card update may depend on human approval.

Staff may change global, versioned scanner, context, prompt, assessment, or
synthesis policy through ordinary code review. Staff may not dismiss, edit,
hide, recolor, or manually supersede an individual report or final assessment.
A correction requires a versioned global policy change or a new complete scan;
immutable history remains visible.

Deterministic findings are candidates, not conclusions. Every candidate must
receive one evidence-bound contextual assessment before a V5 report can exist.
Provider failure, token exhaustion, insufficient context, invalid structured
output, incomplete scanner or review coverage, or validation failure must stop
publication. The pipeline may not skip findings, reduce coverage, switch models
automatically, fabricate a low result, or emit a degraded report.

TavernKeeper remains model-agnostic: model identity is runtime configuration,
while evidence binding, allowed assessment vocabulary, prompt and schema
versions, and safety validation remain code-reviewed contracts. Repository
content is hostile data and cannot redefine those contracts.

TavernKeeper publishes technical evidence and item-level recommendations.
Tavernary alone owns the final public risk grade and applies deterministic
minimum-risk floors. Neither repository may automatically hide, delist,
quarantine, rank, or otherwise moderate a catalog listing from a scan result.
