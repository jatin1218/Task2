"""Policy enforcement point; no SQL or attribute bags accepted from callers."""
import json
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from .data import CATALOG, COLUMNS, PII
from .pdp import Decision


class AuditUnavailable(RuntimeError):
    pass


class AccessLayer:
    def __init__(self, db, pdp, users):
        self.db, self.pdp, self.users = db, pdp, users

    def request(self, principal, resource_id, action, environment, limit=20):
        request_id = str(uuid.uuid4())
        # In a service, principal must come from verified authentication; this CLI simulates it.
        user = self.users.get(principal)
        resource = CATALOG.get(resource_id)
        context = {'user': user, 'resource': resource, 'action': {'name': action},
                   'environment': environment}
        def denied(reason):
            return Decision(False, reason, self.pdp.version, self.pdp.digest)
        if user is None or resource is None:
            decision = denied('Unknown principal or resource')
        elif action != 'read':
            decision = denied('Unsupported action')
        elif type(limit) is not int or not 1 <= limit <= 100:
            decision = denied('Limit must be 1 through 100')
        elif user.get('tenant') != resource['tenant']:
            # Defense in depth: policy edits cannot remove row isolation.
            decision = denied('Tenant boundary violation')
        else:
            decision = self.pdp.evaluate(context)
        rows, outcome = [], 'denied'
        if decision.allowed:
            dataset = resource['dataset']
            projection = ', '.join(
                f'NULL AS {column}' if column in PII and not decision.reveal_pii else column
                for column in COLUMNS[dataset]
            )
            try:
                # All identifiers are from the trusted catalog; values are bound parameters.
                cursor = self.db.execute(
                    f'SELECT {projection} FROM {dataset} WHERE tenant = ? ORDER BY id LIMIT ?',
                    (user['tenant'], limit))
                rows = [dict(row) for row in cursor]
                outcome = 'served'
            except Exception:
                outcome = 'query_error'
        entry = (request_id, datetime.now(timezone.utc).isoformat(), principal, resource_id,
                 action, 'ALLOW' if decision.allowed else 'DENY', decision.reason,
                 decision.policy_version, decision.policy_hash, json.dumps(decision.matched),
                 json.dumps(context, sort_keys=True), len(rows), outcome)
        try:
            with self.db:
                self.db.execute('INSERT INTO audit VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)', entry)
        except Exception as exc:
            # Nothing is returned unless its audit record commits successfully.
            raise AuditUnavailable('Audit write failed; no data released') from exc
        return {'request_id': request_id, **asdict(decision), 'outcome': outcome, 'rows': rows}
