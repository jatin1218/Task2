"""Policy decision point: mandatory guards, deny overrides, default deny."""
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    policy_version: str
    policy_hash: str
    matched: tuple = ()
    reveal_pii: bool = False


class PolicyError(ValueError):
    pass


def resolve(context, path):
    value = context
    for part in path.split('.'):
        if not isinstance(value, dict) or part not in value:
            raise PolicyError('Missing attribute: ' + path)
        value = value[part]
    if value is None:
        raise PolicyError('Null attribute: ' + path)
    return value


def condition(test, context):
    left = resolve(context, test['left'])
    right = resolve(context, test['right']) if 'right' in test else test['value']
    op = test['op']
    if op == 'eq':
        return type(left) is type(right) and left == right
    if op == 'gte':
        if type(left) not in (int, float) or type(right) not in (int, float):
            raise PolicyError('Numeric attributes required')
        return left >= right
    if op == 'in':
        if not isinstance(right, list):
            raise PolicyError('List required for in')
        return any(type(left) is type(item) and left == item for item in right)
    if op == 'contains':
        if not isinstance(left, list):
            raise PolicyError('List required for contains')
        return any(type(right) is type(item) and right == item for item in left)
    raise PolicyError('Unsupported operator')


class PDP:
    def __init__(self, path):
        self.policy = json.loads(Path(path).read_text(encoding='utf-8'))
        self.validate()
        self.version = self.policy['version']
        encoded = json.dumps(self.policy, sort_keys=True).encode()
        self.digest = hashlib.sha256(encoded).hexdigest()

    def validate(self):
        policy = self.policy
        if set(policy) != {'version', 'required', 'deny', 'allow', 'pii'}:
            raise PolicyError('Invalid policy sections')
        if not isinstance(policy['version'], str) or not policy['version']:
            raise PolicyError('Policy version required')
        for name in ('required', 'deny', 'allow', 'pii'):
            if not isinstance(policy[name], list):
                raise PolicyError('Policy sections must be lists')
        if not policy['required'] or not policy['allow'] or not policy['pii']:
            raise PolicyError('Empty access or PII policy')
        tests = list(policy['required']) + list(policy['pii'])
        ids = []
        for rule in policy['required']:
            ids.append(rule['id'])
        for kind in ('allow', 'deny'):
            for rule in policy[kind]:
                if set(rule) != {'id', 'all'} or not isinstance(rule['all'], list) or not rule['all']:
                    raise PolicyError('Invalid rule')
                ids.append(rule['id'])
                tests.extend(rule['all'])
        if any(not isinstance(x, str) or not x for x in ids) or len(ids) != len(set(ids)):
            raise PolicyError('Rule IDs must be nonempty and unique')
        for test in tests:
            if set(test) - {'id', 'left', 'op', 'right', 'value'}:
                raise PolicyError('Unexpected condition key')
            if test.get('op') not in ('eq', 'gte', 'in', 'contains'):
                raise PolicyError('Unknown operator')
            if ('right' in test) == ('value' in test):
                raise PolicyError('One comparison target required')
            for path in [test.get('left')] + ([test['right']] if 'right' in test else []):
                if not isinstance(path, str) or len(path.split('.')) != 2 or path.split('.')[0] not in ('user', 'resource', 'action', 'environment'):
                    raise PolicyError('Invalid attribute path')

    def evaluate(self, context):
        def result(allowed, reason, matched=(), pii=False):
            return Decision(allowed, reason, self.version, self.digest, tuple(matched), pii)
        try:
            # Evaluate every condition, even in unmatched rules: missing attributes fail closed.
            guards = [(r['id'], condition(r, context)) for r in self.policy['required']]
            denies = [(r['id'], all([condition(t, context) for t in r['all']])) for r in self.policy['deny']]
            allows = [(r['id'], all([condition(t, context) for t in r['all']])) for r in self.policy['allow']]
            pii = all([condition(t, context) for t in self.policy['pii']])
            failures = [name for name, passed in guards if not passed]
            if failures:
                return result(False, 'Required conditions failed', failures)
            matched = [name for name, passed in denies if passed]
            if matched:
                return result(False, 'Explicit deny', matched)
            matched = [name for name, passed in allows if passed]
            if not matched:
                return result(False, 'Default deny: no allow policy matched')
            return result(True, 'Allowed by attribute policy', matched, pii)
        except (PolicyError, KeyError, TypeError, ValueError) as exc:
            return result(False, 'Invalid or missing attributes: ' + str(exc))
