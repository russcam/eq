# Elasticsearch Query CLI (eq)

A command line interface to perform queries on
[Elasticsearch](https://github.com/elastic/elasticsearch).

This project is under development, no guarantees of version compatibility or
breaking changes at this point.

This uses the Official Elasticsearch Rust Client
[elasticsearch-rs](https://github.com/elastic/elasticsearch-rs), which is in an
*alpha* state.

# Usage

`eq` queries Elasticsearch for results and uses the [Search
After](https://www.elastic.co/guide/en/elasticsearch/reference/7.6/search-request-body.html#request-body-search-search-after)
API for retrieving multiple batches of results. This can be handy for
interacting with documents such as logs in a terminal.

```
eq 0.1.0
A simple command line interface for Elasticsearch queries.

USAGE:
    eq [FLAGS] [OPTIONS]

FLAGS:
    -d, --debug                        Activate debug mode
    -f, --follow                       Follow logs, this polls for new results until canceled
    -h, --help                         Prints help information
    -j, --json                         Print hits as newline delimited json objects, including all fields
    -n, --no-certificate-validation    Do not validate SSL/TLS certificate of server
    -V, --version                      Prints version information

OPTIONS:
    -a, --address <address>          The address of the Elasticsearch server to query [env: ES_ADDRESS=]  [default:
                                     http://localhost:9200]
    -b, --batch-size <batch-size>    The number of results to return per batch [default: 100]
    -i, --index <index>              The index to query [default: filebeat-*]
    -l, --limit <limit>              The limit of results to return, 0 means no limit [default: 10000]
    -p, --password <password>        The Elasticsearch password to use [env: ES_PASSWORD=]
    -q, --query <query>              The query json as a string to search with [default: {}]
    -s, --sort <sort>                key:value pairs separated by commas to set sorting parameters for query [default:
                                     @timestamp:asc,_id:asc]
    -u, --username <username>        The Elasticsearch username to authenticate as [env: ES_USERNAME=]
```

By default only `_source.message` fields of results are logged to stdout.

```sh
$ eq --index eq-testing
log entry 0
log entry 1
log entry 2
```

`--json` can be used to output search result hits as json objects and retrieve
all fields. A tool like [jq](https://stedolan.github.io/jq/) or
[gron](https://github.com/tomnomnom/gron) can be used to format or filter
fields for display as desired.

```sh
$ eq --index eq-testing --follow --json | jq --compact-output '._source | {"@timestamp","message"}'
{"@timestamp":"2020-03-10T18:11:38.988Z","message":"log entry 0"}
{"@timestamp":"2020-03-11T18:11:38.988Z","message":"log entry 1"}
{"@timestamp":"2020-03-12T18:11:38.988Z","message":"log entry 2"}
^C

$ eq --index eq-testing --follow --json | gron --stream | grep '_source.message'
json[0]._source.message = "log entry 0";
json[1]._source.message = "log entry 1";
json[2]._source.message = "log entry 2";
^C
```

`--query` allows [Elasticsearch Query
DSL](https://www.elastic.co/guide/en/elasticsearch/reference/7.6/query-dsl.html)
to be used.

```sh
$ eq --query '
{
  "query": {
    "term": {
      "agent.hostname": {
        "value": "my-server"
      }
    }
  }
}' > my-server.log
```

# Development

Get [rustup](https://rustup.rs) and install the nightly compiler builds:

```sh
rustup toolchain install nightly
```

Run [cargo](https://doc.rust-lang.org/cargo/) commands for different tasks:

To build:

```sh
cargo build
```

To run like the executable will run:

```sh
cargo run
```

Create a release build:

```sh
cargo build --release
```

Auto format:

```sh
cargo fmt
```

Linting can be done with [clippy](https://github.com/rust-lang/rust-clippy)
which is installable via:

```sh
rustup component add clippy
```

Then run linting with:

```sh
cargo clippy
```

Generate documentation for **all** crates locally:

```sh
cargo doc
```

Then explore `./target/doc` to find documentation for crates.

# Testing

To run unit tests:

```sh
cargo test
```

To run tests with a real Elasticsearch instance, start one up accessible via
`http://localhost:9200` (for example by following [getting-started][] in the
Elasticsearch documentation) and run:

```sh
cargo test -- --ignored
```

An index named `eq-testing` will be used for testing.

[getting-started]: https://www.elastic.co/guide/en/elasticsearch/reference/current/getting-started-install.html#run-elasticsearch-local

# License

This is free software, licensed under [The Apache License Version 2.0.](LICENSE).
