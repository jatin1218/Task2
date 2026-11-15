"""Run with python -m abac demo, query, personas or audit."""
import argparse
import json
from pathlib import Path
from .data import connect
from .pdp import PDP
from .service import AccessLayer, AuditUnavailable

ROOT = Path(__file__).resolve().parent.parent


def trusted_demo_environment(**changes):
    return {'mfa': True, 'network': 'office', 'region': 'IN', 'lockdown': False, **changes}


def show(result):
    print(f"{'ALLOW' if result['allowed'] else 'DENY '} | {result['reason']} | {result['outcome']}")
    print('Rules:', ', '.join(result['matched']) or '(none)', '| Request:', result['request_id'])
    if result['rows']:
        print(json.dumps(result['rows'], indent=2))


def main():
    parser = argparse.ArgumentParser(description='ABAC demonstration (simulated identity/environment)')
    parser.add_argument('--db', default=str(ROOT / 'data' / 'analytics.db'))
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('demo')
    sub.add_parser('personas')
    sub.add_parser('audit')
    query = sub.add_parser('query')
    query.add_argument('--user', required=True)
    query.add_argument('--resource', required=True)
    query.add_argument('--action', default='read')
    query.add_argument('--network', default='office', choices=['office', 'vpn', 'public'])
    query.add_argument('--region', default='IN')
    query.add_argument('--no-mfa', action='store_true')
    query.add_argument('--lockdown', action='store_true')
    query.add_argument('--limit', type=int, default=20)
    args = parser.parse_args()
    users = json.loads((ROOT / 'config/users.json').read_text())
    if args.command == 'personas':
        print(json.dumps(users, indent=2))
        return 0
    Path(args.db).parent.mkdir(parents=True, exist_ok=True)
    db = connect(args.db)
    try:
        service = AccessLayer(db, PDP(ROOT / 'config/policies.json'), users)
        if args.command == 'audit':
            # Local operator view, not a user-facing analytics endpoint.
            for row in db.execute('SELECT request_id, principal,resource,decision,reason,outcome FROM audit ORDER BY rowid DESC LIMIT 30'):
                print(json.dumps(dict(row)))
        elif args.command == 'query':
            result = service.request(args.user, args.resource, args.action,
                trusted_demo_environment(mfa=not args.no_mfa, network=args.network,
                                         region=args.region, lockdown=args.lockdown), args.limit)
            show(result)
            return 0 if result['outcome'] == 'served' else 1
        else:
            cases = [
                ('Alice sees masked customers', 'alice', 'acme.customers', {}),
                ('Bob sees customer PII', 'bob', 'acme.customers', {}),
                ('Carol reads own tenant orders', 'carol', 'beta.orders', {}),
                ('Carol cannot cross tenants', 'carol', 'acme.orders', {}),
                ('Alice lacks finance clearance', 'alice', 'acme.finance', {}),
                ('Bob can read finance', 'bob', 'acme.finance', {}),
                ('Bob denied without MFA', 'bob', 'acme.finance', {'mfa': False}),
                ('Alice denied on public network', 'alice', 'acme.orders', {'network': 'public'}),
                ('Incident deny overrides allow', 'bob', 'acme.orders', {'lockdown': True}),
            ]
            for label, user, resource, env in cases:
                print('\n' + label)
                show(service.request(user, resource, 'read', trusted_demo_environment(**env)))
        return 0
    except AuditUnavailable as exc:
        print(str(exc))
        return 2
    finally:
        db.close()


if __name__ == '__main__':
    raise SystemExit(main())
