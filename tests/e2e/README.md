# End to end scenarios

Real DSH + DeepSeek scenarios and user UI actors are implemented here.
See [the acceptance instructions](../README.md). Missing planned cases are listed by the runner and cannot produce a passing full result.

The implemented E01 journey prepares an isolated published identity as a fixture,
then sends only a natural-language read task to an actual DSH Agent running
DeepSeek. Assertions require successful model-selected protocol calls, a live
catalog result, and matching versions in the answer. Fixture registration uses
the deterministic user manager; this does not cover GUI identity creation or
write approval. Those journeys remain separate required cases.

The model and API origin are read from the protected match-service configuration
(`AWIKI_DEEPSEEK_CONFIG_FILE` may select an explicit file). Only the configured
model/base URL are read; `DEEPSEEK_API_KEY` remains a task-process credential.
The current API origin is adapted to DeepSeek's Messages endpoint. The runner
does not persist the key or fall back to another provider. Session logs exist
only in the owning temporary DSH home and are removed after cleanup.

E02 verifies the precise document actually fetched by the real model. E03 uses
the shipped Web profile and Chromium to approve exactly one model-requested
post through the real user dialog, checks its receipt and list read-back, and
verifies the consumed once grant. It then restores the exact post/quota scope
and removes the isolated test identity. This signed-out Session journey does
not claim account OAuth coverage.

E02 additionally compares the tool's full Markdown hash against the running
deployment's public catalog through the narrow read-only oracle. The oracle's
body/hash is not supplied to the model. The former nonempty-content assertion
alone could accept a fully redacted document and is insufficient evidence.


E05 reads a live catalog, disconnects through the real PAP Connections page,
restarts the actual Host and resumes the same model session. The disconnected
session must remain visible, the denied model turn must send no business request
and must not use alternate channels. A user page reconnect then permits a real
catalog read in that same model session. Manager RPCs do not make these UI decisions.
