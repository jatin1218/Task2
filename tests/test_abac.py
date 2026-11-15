import copy
import json
import tempfile
import unittest
from pathlib import Path
from abac.data import connect, CATALOG
from abac.pdp import PDP, PolicyError
from abac.service import AccessLayer, AuditUnavailable
from abac.__main__ import ROOT, trusted_demo_environment


class AccessTests(unittest.TestCase):
    def setUp(self):
        self.db = connect(':memory:')
        self.users = json.loads((ROOT / 'config/users.json').read_text())
        self.pdp = PDP(ROOT / 'config/policies.json')
        self.service = AccessLayer(self.db, self.pdp, self.users)

    def tearDown(self):
        self.db.close()

    def request(self, user='alice', resource='acme.orders', action='read', **env):
        return self.service.request(user, resource, action, trusted_demo_environment(**env))

    def test_analyst_allowed(self):
        self.assertEqual(len(self.request()['rows']), 2)

    def test_masking(self):
        row = self.request(resource='acme.customers')['rows'][0]
        self.assertIsNone(row['email'])
        self.assertIsNone(row['customer_name'])

    def test_pii_grant(self):
        row = self.request(user='bob', resource='acme.customers')['rows'][0]
        self.assertEqual(row['email'], 'a@example.invalid')

    def test_partner_own_tenant(self):
        result = self.request(user='carol', resource='beta.orders')
        self.assertTrue(result['allowed'])
        self.assertEqual([r['tenant'] for r in result['rows']], ['beta'])

    def test_cross_tenant(self):
        result = self.request(user='bob', resource='beta.orders')
        self.assertFalse(result['allowed'])
        self.assertEqual(result['rows'], [])

    def test_clearance(self):
        self.assertFalse(self.request(resource='acme.finance')['allowed'])
        self.assertTrue(self.request(user='bob', resource='acme.finance')['allowed'])

    def test_mfa(self):
        self.assertFalse(self.request(mfa=False)['allowed'])

    def test_boolean_not_integer(self):
        self.assertFalse(self.request(mfa=1)['allowed'])

    def test_public_network(self):
        self.assertFalse(self.request(network='public')['allowed'])

    def test_region(self):
        self.assertFalse(self.request(region='US')['allowed'])

    def test_deny_overrides(self):
        result = self.request(lockdown=True)
        self.assertEqual(result['matched'], ('incident-lockdown',))
        self.assertFalse(result['allowed'])

    def test_missing_environment(self):
        result = self.service.request('alice', 'acme.orders', 'read', {})
        self.assertFalse(result['allowed'])

    def test_missing_subject_attribute(self):
        del self.users['alice']['clearance']
        self.assertFalse(self.request()['allowed'])

    def test_inactive(self):
        self.users['alice']['active'] = False
        self.assertFalse(self.request()['allowed'])

    def test_dataset_entitlement(self):
        self.users['alice']['datasets'] = []
        self.assertFalse(self.request()['allowed'])

    def test_purpose(self):
        self.users['alice']['purposes'] = ['research']
        self.assertFalse(self.request()['allowed'])

    def test_unknown_principal(self):
        self.assertFalse(self.request(user='unknown')['allowed'])

    def test_injection_resource(self):
        self.assertFalse(self.request(resource='orders; DROP TABLE orders;')['allowed'])
        self.assertEqual(self.db.execute('SELECT count(*) FROM orders').fetchone()[0], 3)

    def test_unsupported_action(self):
        self.assertFalse(self.request(action='delete')['allowed'])

    def test_limit(self):
        result = self.service.request('alice', 'acme.orders', 'read', trusted_demo_environment(), 1)
        self.assertEqual(len(result['rows']), 1)
        result = self.service.request('alice', 'acme.orders', 'read', trusted_demo_environment(), 1000)
        self.assertFalse(result['allowed'])

    def test_audit_both_outcomes(self):
        self.request()
        self.request(mfa=False)
        rows = self.db.execute('SELECT * FROM audit ORDER BY rowid').fetchall()
        self.assertEqual([r['decision'] for r in rows], ['ALLOW', 'DENY'])
        self.assertEqual([r['row_count'] for r in rows], [2, 0])
        self.assertEqual(len(rows[0]['policy_hash']), 64)
        self.assertNotIn('example.invalid', rows[0]['attributes'])

    def test_audit_failure_blocks_response(self):
        self.db.execute('DROP TABLE audit')
        with self.assertRaises(AuditUnavailable):
            self.request()

    def test_query_failure_audited(self):
        self.db.execute('DROP TABLE orders')
        result = self.request()
        self.assertEqual(result['outcome'], 'query_error')
        self.assertEqual(result['rows'], [])
        self.assertEqual(self.db.execute('SELECT outcome FROM audit').fetchone()[0], 'query_error')

    def test_tenant_guard_survives_policy_edit(self):
        self.pdp.policy['required'] = []
        self.assertFalse(self.request(resource='beta.orders')['allowed'])

    def test_external_pii_restricted(self):
        self.users['bob']['employment'] = 'external'
        self.assertIsNone(self.request(user='bob', resource='acme.customers')['rows'][0]['email'])

    def test_no_role_name_dependency(self):
        self.users['dave'] = copy.deepcopy(self.users['alice'])
        self.users['dave']['name'] = 'A different persona'
        self.assertTrue(self.request(user='dave')['allowed'])

    def test_default_deny_pdp(self):
        context = {'user': self.users['bob'], 'resource': CATALOG['acme.orders'],
                   'action': {'name': 'export'}, 'environment': trusted_demo_environment()}
        self.assertFalse(self.pdp.evaluate(context).allowed)

    def test_invalid_policy_rejected(self):
        policy = copy.deepcopy(self.pdp.policy)
        policy['required'][0]['op'] = 'execute'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy.json'
            path.write_text(json.dumps(policy))
            with self.assertRaises(PolicyError):
                PDP(path)


if __name__ == '__main__':
    unittest.main()
