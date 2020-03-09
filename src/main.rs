use elasticsearch::auth::Credentials;
use elasticsearch::cert::CertificateValidation;
use elasticsearch::http::response::Response;
use elasticsearch::http::transport::SingleNodeConnectionPool;
use elasticsearch::http::transport::TransportBuilder;
use elasticsearch::{Elasticsearch, Error, SearchParts};
use serde_json::json;
use serde_json::to_string_pretty;
use serde_json::Value;
use std::convert::TryInto;
use std::process::exit;
use std::thread::sleep;
use std::time::Duration;
use structopt::StructOpt;
use url::Url;

#[derive(StructOpt)]
#[structopt(about)]
struct Opt {
    /// The address of the Elasticsearch server to query
    #[structopt(
        short,
        long,
        default_value = "http://localhost:9200",
        env = "ES_ADDRESS"
    )]
    address: String,

    /// The number of results to return per batch
    #[structopt(short, long, default_value = "100")]
    batch_size: usize,

    /// Activate debug mode
    #[structopt(short, long)]
    debug: bool,

    /// Follow logs, this polls for new results until canceled
    #[structopt(short, long)]
    follow: bool,

    /// The index to query
    #[structopt(short, long, default_value = "filebeat-*")]
    index: String,

    /// Print hits as newline delimited json objects, including all fields
    #[structopt(short, long)]
    json: bool,

    // 10,000 is arbitrarily chosen to try and have a safe-ish out of the box experience
    /// The limit of results to return, 0 means no limit
    #[structopt(short, long, default_value = "10000")]
    limit: usize,

    /// Do not validate SSL/TLS certificate of server
    #[structopt(short, long)]
    no_certificate_validation: bool,

    /// The Elasticsearch password to use
    #[structopt(short, long, env = "ES_PASSWORD")]
    password: Option<String>,

    /// The query json as a string to search with
    #[structopt(short, long, default_value = "{}")]
    query: Value,

    /// key:value pairs separated by commas to set sorting parameters for query
    #[structopt(short, long, default_value = "@timestamp:asc,_id:asc")]
    sort: String,

    /// The Elasticsearch username to authenticate as
    #[structopt(short, long, env = "ES_USERNAME")]
    username: Option<String>,
}

#[derive(Clone, Debug)]
struct QueryOptions {
    // elasticsearch-rs api options
    index: String,
    json_body: Value,
    size: usize,
    sort: String,

    // eq specific options
    debug: bool,
    follow: bool,
    limit: usize,
    print_json: bool,
}

struct SearchResult {
    search_response_body: Value,
}

impl SearchResult {
    pub fn new(search_response_body: Value) -> SearchResult {
        SearchResult {
            search_response_body,
        }
    }

    fn hits(&mut self) -> Vec<Hit> {
        match self.search_response_body["hits"]["hits"].as_array() {
            Some(hits) => {
                let mut hit_objects = Vec::new();
                for hit in hits {
                    hit_objects.push(Hit::new(hit.clone()));
                }
                hit_objects
            }
            None => vec![],
        }
    }

    fn last_sort_field(&mut self) -> Vec<Value> {
        match self.hits().last() {
            Some(hit) => hit.sort(),
            None => vec![],
        }
    }
}

struct Hit {
    value: Value,
}

impl Hit {
    pub fn new(value: Value) -> Hit {
        Hit { value }
    }

    pub fn message(&self) -> String {
        self.value["_source"]["message"]
            .as_str()
            .unwrap()
            .to_string()
    }

    pub fn json(&self) -> String {
        self.value.to_string()
    }

    pub fn sort(&self) -> Vec<Value> {
        self.value["sort"].as_array().unwrap().to_vec()
    }
}

#[tokio::main]
async fn main() {
    let opt = Opt::from_args();

    let server = match Url::parse(&opt.address) {
        Ok(url) => url,
        Err(error) => {
            eprintln!("Could not parse url '{}'.", opt.address);
            if opt.debug {
                eprintln!("Error: {:?}", error);
            }
            exit(1)
        }
    };

    if opt.debug {
        eprintln!("Using Elasticsearch url '{}'.", server);
    }

    let connection_pool = SingleNodeConnectionPool::new(server);
    let mut transport_builder = TransportBuilder::new(connection_pool);
    match opt.username {
        None => (),
        Some(username) => {
            transport_builder =
                transport_builder.auth(Credentials::Basic(username, opt.password.unwrap()));
        }
    }
    if opt.no_certificate_validation {
        transport_builder = transport_builder.cert_validation(CertificateValidation::None);
    }
    let transport = match transport_builder.build() {
        Ok(transport) => transport,
        Err(error) => {
            eprintln!("Could not build transport for Elasticsearch.");
            eprintln!("Error: {:?}", error);
            exit(1)
        }
    };

    let client = Elasticsearch::new(transport);

    let options = QueryOptions {
        index: opt.index.to_string(),
        debug: opt.debug,
        size: opt.batch_size,
        json_body: json!(opt.query),
        sort: opt.sort.to_string(),
        print_json: opt.json,
        follow: opt.follow,
        limit: opt.limit,
    };

    // query some logs
    logs(&client, options)
        .await
        .expect("Unable to get logs from Elasticsearch.");
}

async fn logs(client: &Elasticsearch, options: QueryOptions) -> Result<usize, Error> {
    // do the first search
    let response = search(&client, &options).await;

    // get the result and hit count, print the logs
    let body = response.read_body::<Value>().await.unwrap();
    let mut result = SearchResult::new(body);
    let hits = result.hits();
    print_logs(options.print_json, &hits);

    // set up the things we'll be modifying as we search
    let mut total_hits = hits.len();
    let mut sort_values = result.last_sort_field();

    // repeat searches until there are no more hits unless we're following
    while !result.hits().is_empty() || options.follow {
        let mut size = options.size;

        // if we have a limit
        if options.limit != 0 {
            // break if we have reached the limit
            if options.limit <= total_hits {
                eprintln!("Limit '{}' reached.", options.limit);
                break;
            }

            // slim down the request size if our next search will hit the limit
            if options.limit <= total_hits + options.size {
                size = options.limit - total_hits
            }
        }

        result = search_after(&client, size, options.clone(), sort_values.clone()).await;
        total_hits += result.hits().len();
        print_logs(options.print_json, &result.hits());

        // update the sort values if they are not empty, otherwise keep the
        // previous sort values
        if !result.last_sort_field().is_empty() {
            sort_values = result.last_sort_field();
        }

        // sleep if following and did not find new results
        if options.follow && result.hits().is_empty() {
            sleep(Duration::from_secs(5));
        }
    }

    Ok(total_hits)
}

async fn search(client: &Elasticsearch, options: &QueryOptions) -> Response {
    if options.debug {
        eprintln!("Search options: {:?}", options);
    }

    // if our limit is smaller than the batch size, use the limit
    let size = if options.size > options.limit {
        options.limit
    } else {
        options.size
    };

    let response_result = client
        .search(SearchParts::Index(&[&options.index]))
        .size(size.try_into().unwrap())
        .body(&options.json_body)
        .sort(&[&options.sort])
        .send()
        .await;

    verify_response(response_result).await
}

fn print_logs(print_json: bool, hits: &[Hit]) {
    for hit in hits {
        if print_json {
            println!("{}", hit.json())
        } else {
            println!("{}", hit.message())
        }
    }
}

async fn search_after(
    client: &Elasticsearch,
    size: usize,
    mut options: QueryOptions,
    sort_values: Vec<Value>,
) -> SearchResult {
    // if we have sort values, add them to the query body
    let mut new_options = if sort_values.is_empty() {
        options
    } else {
        // modify the query body to include the "search_after" argument
        // https://www.elastic.co/guide/en/elasticsearch/reference/7.6/search-request-body.html#request-body-search-search-after
        let new_body = add_to_serde_value(
            options.json_body.clone(),
            "search_after".to_string(),
            json!(sort_values),
        );
        options.json_body = new_body;
        options
    };

    // set the search size to what we were given
    new_options.size = size;

    let response = search(&client, &new_options).await;
    let body = response.read_body::<Value>().await.unwrap();

    SearchResult::new(body)
}

async fn verify_response(response_result: Result<Response, Error>) -> Response {
    match response_result {
        Ok(response) => {
            if response.status_code().is_success() {
                response
            } else {
                eprintln!("A query was unsuccessful.");
                eprintln!("response code: {:?}", response.status_code().as_str());
                eprintln!(
                    "response body:\n{}",
                    to_string_pretty(
                        &response
                            .read_body::<Value>()
                            .await
                            .expect("Could not get response body for failed search.")
                    )
                    .unwrap()
                );
                exit(1)
            }
        }
        Err(error) => {
            eprintln!("A request encountered an error.");
            eprintln!("{:?}", error);
            exit(1)
        }
    }
}

// this seems waay too complicated to add to some existing Value, there is probably a way better
// way to go about this
fn add_to_serde_value(existing_value: Value, key_to_add: String, value_to_add: Value) -> Value {
    let mut map: serde_json::Map<String, Value> = existing_value.as_object().unwrap().clone();
    map.insert(key_to_add, value_to_add);
    map.into()
}

#[test]
fn add_to_existing_json_test() {
    let json: Value = json!({"a": 1});
    assert_eq!(
        add_to_serde_value(json, "b".to_string(), json!(2)),
        json!({"a": 1, "b": 2})
    );
}

#[tokio::test]
#[ignore]
async fn elasticsearch_pagination_test() {
    use elasticsearch::{
        indices::IndicesCreateParts, indices::IndicesDeleteParts, params::Refresh, IndexParts,
    };

    let client = Elasticsearch::default();
    let test_index = "eq-testing";
    let test_record_count = 3;

    // delete the testing index in case it already exists
    client
        .indices()
        .delete(IndicesDeleteParts::Index(&[test_index]))
        .send()
        .await
        .expect("Could not delete testing index.");

    // create the testing index
    let index_creation_result = client
        .indices()
        .create(IndicesCreateParts::Index(test_index))
        .send()
        .await;

    // verify we got a successful response
    verify_response(index_creation_result).await;

    // create some testing records
    for i in 0..test_record_count {
        let index_result = client
            .index(IndexParts::Index(test_index))
            .body(json!({
                "@timestamp": format!("2020-03-1{}T18:11:38.988Z", i),
                "message": format!("log entry {}", i),
            }))
            // trigger a refresh on the latest record so we can immediately
            // query for the tests
            .refresh(if i == test_record_count - 1 {
                Refresh::True
            } else {
                Refresh::False
            })
            .send()
            .await;

        verify_response(index_result).await;
    }

    // set up our query options
    let options = QueryOptions {
        index: test_index.to_string(),
        size: 1,
        json_body: json!({}),
        sort: "@timestamp:asc,_id:asc".to_string(),
        print_json: false,
        debug: true,
        follow: false,
        limit: 10,
    };

    // query our test index and see that we saw the full count of records, even with the restricted
    // batch size
    assert_eq!(logs(&client, options).await.unwrap(), test_record_count);
}
