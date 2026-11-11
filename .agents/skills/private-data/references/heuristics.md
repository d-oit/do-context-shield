# Heuristics
- **For automatic client-context adapter tests, use a fresh client HOME/session, verify the active session root and fake-provider endpoint before dispatch, block non-loopback network egress, and prove sanitizer failure produces zero provider requests.**: When validating a coding-client integration that automatically sanitizes outbound model context. (from trace 25)
