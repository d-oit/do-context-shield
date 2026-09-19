#!/usr/bin/env python3
"""Laya local-model judge sidecar for the do-context-shield process protocol.

Speaks the `judge` method of `docs/process-plugin.md`: one NDJSON request line
(`{"method":"judge","input":…,"entities":[…]}`) on stdin, one
`{"judgments":[{"index":i,"label":…,"confidence":…}, …]}` line on stdout.
Laya (https://huggingface.co/convaiinnovations/laya) is a local calibrated
decision model: it answers typed `choice` questions with probabilities in one
forward pass and never generates text, so this sidecar only ever forwards
labels and confidence — spans, transformations, and restoration stay with the
deterministic pipeline. One child is started per operation, so the checkpoint
is loaded once per process; a cold checkpoint build costs seconds.

Usage:
    python3 examples/laya-judge.py --stub       # offline deterministic agent
    python3 examples/laya-judge.py              # real model; needs `pip install laya`
    python3 examples/laya-judge.py --self-test  # canned assertions, then exit

Environment:
    LAYA_MODEL      model id or local path (default convaiinnovations/laya)
    LAYA_SUBFOLDER  checkpoint subfolder, e.g. typed-decisions
"""

import argparse
import json
import os
import re
import sys

#: Labels the pipeline's default policy understands.
LABEL_CHOICES = ("personal", "business", "test", "secret")
#: Abstention key; the policy then falls back to its kind rules.
ABSTAIN = "none"
#: Criteria sent with every `choice` question, keyed by answer label.
CRITERIA = {
    "personal": "identifies a specific private individual",
    "business": "a business, organization, or role address serving a business function",
    "test": "a documentation, fixture, example, or reserved-domain value",
    "secret": "a credential, key, token, or password-like value",
    ABSTAIN: "none of the above",
}
#: Stub-only heuristics mirroring the built-in `judge-heuristics` rules.
RESERVED_DOMAINS = ("example.com", "example.org", "example.net", ".invalid", ".test", ".example")
ROLE_ADDRESSES = ("support", "billing", "info", "contact", "admin", "sales", "help", "noreply")
STATE_TEXT_LIMIT = 2000
INSTRUCTION_VALUE_LIMIT = 64
#: `laya` names the offending question in its overflow error; keep only its id.
QUESTION_OVERFLOW = re.compile(r"question (?:'([^']*)'|\"([^\"]*)\")")


def fail(message):
    """Report a protocol error on stderr and exit 2 (fail closed)."""
    print(f"laya judge: {message}", file=sys.stderr)
    raise SystemExit(2)


def entity_value(text, entity, index):
    """Candidate text: the request's `value`, or the byte span it points at."""
    value = entity.get("value")
    if value is not None:
        if not isinstance(value, str):
            fail(f"entity {index} has a non-string value")
        return value
    raw = text.encode("utf-8")
    start, end = entity["start"], entity["end"]
    if start < 0 or start >= end or end > len(raw):
        fail(f"entity {index} has an invalid span")
    try:
        return raw[start:end].decode("utf-8")
    except UnicodeDecodeError:
        fail(f"entity {index} span does not fall on character boundaries")


def parse_request(line):
    """Parse and validate one `judge` request line; never echoes values."""
    try:
        request = json.loads(line)
    except ValueError:
        fail("request is not valid JSON")
    if not isinstance(request, dict) or request.get("method") != "judge":
        fail("only the judge method is supported")
    text = request.get("input")
    if not isinstance(text, str):
        fail("input must be a string")
    raw_entities = request.get("entities")
    if not isinstance(raw_entities, list):
        fail("entities must be a list")
    entities = []
    for index, entity in enumerate(raw_entities):
        if not isinstance(entity, dict):
            fail(f"entity {index} is not an object")
        kind = entity.get("kind")
        start = entity.get("start")
        end = entity.get("end")
        if (
            not isinstance(kind, str)
            or not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(end, int)
            or isinstance(end, bool)
        ):
            fail(f"entity {index} needs kind, start, and end")
        entities.append({"kind": kind, "value": entity_value(text, entity, index)})
    return text, entities


def classify_stub(kind, value):
    """Deterministic offline classification mirroring `judge-heuristics`."""
    lowered = value.lower()
    if any(lowered.endswith(domain) or domain in lowered for domain in RESERVED_DOMAINS):
        return ("test", 0.97)
    if lowered.split("@", 1)[0] in ROLE_ADDRESSES:
        return ("business", 0.95)
    return (ABSTAIN, 0.0)


def stub_judgments(entities):
    """Judgments from the offline stub agent; no model import, no network."""
    judgments = []
    for index, entity in enumerate(entities):
        label, confidence = classify_stub(entity["kind"], entity["value"])
        if label == ABSTAIN:
            judgments.append({"index": index, "label": None})
        else:
            judgments.append({"index": index, "label": label, "confidence": confidence})
    return judgments


def overflowing_question(error, questions):
    """Question id named by a Laya `head_max_len` overflow, if any."""
    match = QUESTION_OVERFLOW.search(str(error))
    if not match:
        return None
    qid = match.group(1) if match.group(1) is not None else match.group(2)
    return qid if qid in questions else None


def laya_answers(text, entities):
    """One batched Laya call: `choice` question per candidate -> answers map."""
    try:
        import laya
    except ImportError:
        fail("pip install laya (see docs/process-plugin.md)")
    model_id = os.environ.get("LAYA_MODEL", "convaiinnovations/laya")
    subfolder = os.environ.get("LAYA_SUBFOLDER")
    options = {"subfolder": subfolder} if subfolder else {}
    try:
        agent = laya.load(model_id, **options)
    except Exception as error:  # load failures stay value-free on stderr
        fail(f"cannot load model {model_id!r}: {type(error).__name__}")
    state = {"text": text[:STATE_TEXT_LIMIT]}
    questions = {
        str(index): {
            "type": "choice",
            "instructions": (
                f"Classify the candidate '{entity['value'][:INSTRUCTION_VALUE_LIMIT]}' "
                f"(detected kind: {entity['kind']}) found in the text."
            ),
            "criteria": dict(CRITERIA),
        }
        for index, entity in enumerate(entities)
    }
    answers = {}
    pending = dict(questions)
    while pending:
        try:
            result = agent.predict(state, pending)
        except ValueError as error:
            # A question over its option-token budget abstains instead of
            # failing the whole call; the policy then pseudonymizes.
            overflow = overflowing_question(error, pending)
            if overflow is None:
                fail(f"model inference failed: {type(error).__name__}")
            del pending[overflow]
            continue
        except Exception as error:
            fail(f"model inference failed: {type(error).__name__}")
        answers.update(result.get("answers") or {})
        break
    return answers


def judgments_from_answers(entities, answers):
    """Map Laya answers to protocol judgments; unknown shapes fail closed."""
    if not isinstance(answers, dict):
        fail("model answers are not an object")
    judgments = []
    for index in range(len(entities)):
        answer = answers.get(str(index))
        if answer is None:
            judgments.append({"index": index, "label": None})
            continue
        if not isinstance(answer, dict):
            fail(f"answer {index} is not an object")
        choice = answer.get("choice")
        if choice == ABSTAIN:
            judgments.append({"index": index, "label": None})
            continue
        if choice not in LABEL_CHOICES:
            fail(f"answer {index} has an unknown choice")
        confidence = answer.get("confidence")
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not 0.0 <= float(confidence) <= 1.0
        ):
            fail(f"answer {index} has a confidence outside 0..=1")
        judgments.append({"index": index, "label": choice, "confidence": float(confidence)})
    return judgments


def self_test():
    """Canned assertions for the stub path and the answer mapping."""
    request = {
        "method": "judge",
        "input": "email support@acme.com",
        "entities": [
            {
                "kind": "email",
                "start": 6,
                "end": 22,
                "value": "support@acme.com",
                "confidence": 0.99,
            }
        ],
    }
    _text, entities = parse_request(json.dumps(request))
    if stub_judgments(entities) != [{"index": 0, "label": "business", "confidence": 0.95}]:
        raise AssertionError("stub classification drifted")
    one = [{"kind": "email", "value": "alice@example.org"}]
    if judgments_from_answers(one, {"0": {"choice": "none", "confidence": 0.8}}) != [
        {"index": 0, "label": None}
    ]:
        raise AssertionError("abstention mapping drifted")
    if judgments_from_answers(one, {"0": {"choice": "personal", "confidence": 0.91}}) != [
        {"index": 0, "label": "personal", "confidence": 0.91}
    ]:
        raise AssertionError("label mapping drifted")
    if judgments_from_answers(one, {}) != [{"index": 0, "label": None}]:
        raise AssertionError("missing answer must abstain")
    try:
        judgments_from_answers(one, {"0": {"choice": "banana", "confidence": 0.9}})
    except SystemExit as error:
        if error.code != 2:
            raise AssertionError(f"invalid choice exited {error.code}, want 2")
    else:
        raise AssertionError("invalid choice did not exit 2")


def main():
    parser = argparse.ArgumentParser(
        description="Laya judge sidecar for the do-context-shield process protocol"
    )
    parser.add_argument(
        "--stub", action="store_true", help="offline deterministic agent (no model)"
    )
    parser.add_argument(
        "--self-test", action="store_true", help="run canned assertions, then exit"
    )
    args = parser.parse_args()

    if args.self_test:
        try:
            self_test()
        except Exception as error:  # any failure fails the self-test
            print(f"laya-judge self-test failed: {error}", file=sys.stderr)
            raise SystemExit(1)
        print("laya-judge self-test ok")
        return

    line = sys.stdin.readline()
    if not line.strip():
        fail("expected one NDJSON request line on stdin")
    text, entities = parse_request(line)
    if not entities:
        print(json.dumps({"judgments": []}))
        return
    if args.stub:
        judgments = stub_judgments(entities)
    else:
        judgments = judgments_from_answers(entities, laya_answers(text, entities))
    print(json.dumps({"judgments": judgments}))


if __name__ == "__main__":
    main()
