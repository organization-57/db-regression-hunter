-- Local demo only. Use a separate password and TLS for an external target.
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
CREATE ROLE hunter LOGIN PASSWORD 'hunter';
GRANT CONNECT ON DATABASE demo TO hunter;
GRANT pg_monitor TO hunter;
ALTER ROLE hunter SET default_transaction_read_only = on;
ALTER ROLE hunter SET statement_timeout = '5s';
