# Heuristics

Distilled from this repository's traces. Each entry is a verified fact plus the
action it implies.

- **When a specification contradicts itself, implement the invariant-consistent fail-closed reading and state the deviation in the completion report.** A missing judgment index is a decode error, not an abstention: abstention must fall back to the kind rule, never to keep (from the semantic-boundary slice).
- **Multi-source detection must resolve overlaps by source precedence before the pipeline longest-span-wins pass: a shorter, noisier fragment from a secondary detector can displace a longer authoritative primary span, leaving the uncovered middle of the value passing through sanitize (a model split an SSN into tax_id + partial ssn fragments around regex full match, and the naive merge kept the fragments).**: When composing two detectors or merging entity lists from more than one source behind the Detector trait. (from trace 6)
- **For Windows ACL test fixtures that read back a file DACL, use the .NET File.GetAccessControl API and assert the resulting SDDL directly; avoid PowerShell Get-Acl module autoload when the module is unreliable.**: When a Windows PowerShell fixture writes or validates file ACLs. (from trace 16)
- **When a crypto round-trip test must prove parsed key bytes match the original, generate the bytes with the OS CSPRNG and compare through encryption/decryption; never pin key material as a literal.**: In tests that validate key-file parsing without embedding reusable key bytes. (from trace 17)
