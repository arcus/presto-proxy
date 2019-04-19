# Presto Proxy

An HTTP proxy that understands the [Presto HTTP protocol](https://github.com/prestodb/presto/wiki/HTTP-Protocol) and adds additional features such as:

- [Fire-and-forget](#fire-and-forget) async execution of queries

## Features

### Fire-and-forget

The first use case this proxy solved was the ability for a client to execute a query without blocking. The proxy handles this by running the query on behalf of the client in a subroutine. The Presto protocol requires polling in order to transition between states of the query such as QUEUED, PLANNING, RUNNING, etc.

A client tag is used to signal that the query should be run asynchronously. Using the standard [presto-cli](https://prestosql.io/docs/current/installation/cli.html) simply add a `--client-tags async=1` to tell the proxy to run it in the background.

```bash
$ presto-cli \
  --client-tags async=1 \
  --server https://presto.example.com \
  --execute 'select ...'

"20190418_195641_00103_cf5ds","https://presto.example.com/ui/query.html?20190418_195641_00103_cf5ds"
```

The output is the Job ID and the URL to the UI for the job. This allows you to view the state and progress of the query without need to wait for it locally.

**Caveats**

**Async query requests are not queued or persisted in any way.** If the proxy goes down or is restarted, all running queries will also be interrupted and will not restart.

**The output of queries are discarded.** This feature was designed for running `CREATE TABLE .. AS` statements which run a `SELECT` but write the results out to a new table (e.g. a Hive table).

**Multi-statement queries are not run in order.** This is side-effect of the fact that the client is doing the work of parsing the multi-statement queries (delimited by semicolons) and executing them in order (waiting for the result of the previous statement). Since each statement is fire-and-forget and therefore the result returns immediately, the next statement will be executed before the previous one actually finishes.

See [feature ideas](#feature-ideas) that address the above caveats.

## Feature ideas

- Support for restarting failed queries due to interruptions
- Support for ordered execution of queries in the same batch
- Support for scheduling a query to run at a later time
- Support for scheduling a query for recurring execution (e.g. cron)
- Support for writing the output of a query to a storage location
