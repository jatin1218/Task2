"""Static trusted resource catalog and synthetic two-tenant data."""
import sqlite3

COLUMNS = {
    'orders': ('id', 'tenant', 'product', 'amount'),
    'customers': ('id', 'tenant', 'customer_name', 'email'),
    'finance': ('id', 'tenant', 'quarter', 'revenue'),
}
PII = {'customer_name', 'email'}
CATALOG = {
    f'{tenant}.{dataset}': {
        'tenant': tenant, 'dataset': dataset, 'classification': level,
        'purpose': 'finance' if dataset == 'finance' else 'sales', 'region': 'IN',
    }
    for tenant in ('acme', 'beta')
    for dataset, level in (('orders', 1), ('customers', 2), ('finance', 3))
}


def connect(path):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.executescript('''
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER, tenant TEXT, product TEXT, amount REAL, PRIMARY KEY (tenant,id));
    CREATE TABLE IF NOT EXISTS customers (
      id INTEGER, tenant TEXT, customer_name TEXT, email TEXT, PRIMARY KEY (tenant,id));
    CREATE TABLE IF NOT EXISTS finance (
      id INTEGER, tenant TEXT, quarter TEXT, revenue REAL, PRIMARY KEY (tenant,id));
    CREATE INDEX IF NOT EXISTS orders_tenant ON orders(tenant);
    CREATE INDEX IF NOT EXISTS customers_tenant ON customers(tenant);
    CREATE INDEX IF NOT EXISTS finance_tenant ON finance(tenant);
    CREATE TABLE IF NOT EXISTS audit (
      request_id TEXT PRIMARY KEY, timestamp_utc TEXT NOT NULL,
      principal TEXT, resource TEXT, action TEXT, decision TEXT,
      reason TEXT, policy_version TEXT, policy_hash TEXT,
      matched_rules TEXT, attributes TEXT, row_count INTEGER, outcome TEXT);
    ''')
    with db:
        db.executemany('INSERT OR IGNORE INTO orders VALUES (?,?,?,?)', [
            (1, 'acme', 'Sensor kit', 2400), (2, 'acme', 'Gateway', 5200),
            (1, 'beta', 'Sensor kit', 1800)])
        db.executemany('INSERT OR IGNORE INTO customers VALUES (?,?,?,?)', [
            (1, 'acme', 'Demo Customer A', 'a@example.invalid'),
            (1, 'beta', 'Demo Customer B', 'b@example.invalid')])
        db.executemany('INSERT OR IGNORE INTO finance VALUES (?,?,?,?)', [
            (1, 'acme', '2026-Q3', 150000), (1, 'beta', '2026-Q3', 90000)])
    return db
