import json
import re
import time
from urllib.parse import urljoin

from scanner.core import Finding, Severity, ScanSession
from scanner.log import logger

GRAPHQL_ENDPOINTS = [
    "/graphql",
    "/graphiql",
    "/v1/graphql",
    "/v2/graphql",
    "/api/graphql",
    "/api/v1/graphql",
    "/graphql/console",
    "/graphql/v1",
    "/query",
    "/gql",
]

INTROSPECTION_QUERY = """{
  __schema {
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
        }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}"""

INTROSPECTION_FULL = """query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args { ...InputValue }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated
    deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes { ...TypeRef }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
      }
    }
  }
}"""


def _build_curl(url, query, method="POST"):
    payload = json.dumps({"query": query})
    return f"curl -k -X {method} '{url}' -H 'Content-Type: application/json' -d '{payload}'"


def _send_query(session, method, url, query):
    if method == "POST":
        return session.post(
            url, data=json.dumps({"query": query}),
            headers={"Content-Type": "application/json"})
    return session.get(url, params={"query": query})


def _build_depth_query(depth):
    inner = "id"
    field_name = "node"
    for _ in range(depth):
        inner = f"{field_name} {{ {inner} }}"
    return f"{{ {inner} }}"


def _is_graphql_response(resp):
    if not resp:
        return False
    try:
        body = resp.json()
        return "data" in body or "errors" in body or "__schema" in str(body)
    except (json.JSONDecodeError, ValueError):
        return False


def _discover_endpoints(session, base_url):
    found = []
    test_query = '{"query": "{ __typename }"}'

    for path in GRAPHQL_ENDPOINTS:
        url = urljoin(base_url, path)

        resp = session.post(url, data=test_query, headers={"Content-Type": "application/json"})
        if resp and resp.status_code in (200, 400, 405) and _is_graphql_response(resp):
            found.append(("POST", url, resp))
            continue

        resp = session.get(url, params={"query": "{ __typename }"})
        if resp and resp.status_code in (200, 400) and _is_graphql_response(resp):
            found.append(("GET", url, resp))
            continue

        resp = session.get(url)
        if resp and resp.status_code == 200:
            body = resp.text.lower()
            if any(s in body for s in ("graphiql", "graphql playground", "graphql-playground")):
                found.append(("GRAPHIQL", url, resp))

    return found


def _test_introspection(session, method, url):
    resp = _send_query(session, method, url, INTROSPECTION_QUERY)
    if not resp:
        return False

    try:
        body = resp.json()
    except (json.JSONDecodeError, ValueError):
        return False

    if "data" in body and body["data"] and "__schema" in body.get("data", {}):
        schema_data = body["data"]["__schema"]
        type_names = [t.get("name", "") for t in schema_data.get("types", [])]
        custom_types = [t for t in type_names if not t.startswith("__") and t not in (
            "String", "Int", "Float", "Boolean", "ID",
        )]
        query_type = schema_data.get("queryType", {})
        mutation_type = schema_data.get("mutationType", {})

        curl_cmd = _build_curl(url, INTROSPECTION_QUERY, method)
        session.add_finding(Finding(
            title="GraphQL Introspection Enabled",
            severity=Severity.MEDIUM,
            description=(
                f"The GraphQL endpoint at '{url}' has introspection enabled, allowing anyone to "
                f"query the full API schema. This exposes all types, fields, queries, mutations, "
                f"and their arguments -- providing a complete blueprint of the API to attackers."
            ),
            evidence=(
                f"Endpoint: {url}\n"
                f"Method: {method}\n"
                f"Response Status: {resp.status_code}\n"
                f"Total Types Exposed: {len(type_names)}\n"
                f"Custom Types: {', '.join(custom_types[:15])}"
                f"{'... and more' if len(custom_types) > 15 else ''}\n"
                f"Query Type: {query_type.get('name', 'N/A')}\n"
                f"Mutation Type: {mutation_type.get('name', 'N/A') if mutation_type else 'None'}"
            ),
            remediation=(
                "1. Disable introspection in production:\n"
                "   - Apollo Server: new ApolloServer({ introspection: false })\n"
                "   - Hasura: Set HASURA_GRAPHQL_ENABLE_INTROSPECTION=false\n"
                "   - graphql-yoga: useDisableIntrospection plugin\n"
                "2. If introspection is needed for tooling, restrict it by IP or auth.\n"
                "3. Implement field-level authorization on all resolvers."
            ),
            url=url,
            module="graphql",
            cwe="CWE-200",
            confirmed=True,
            location=f"GraphQL endpoint at {url}",
            parameter="query (introspection)",
            payload=INTROSPECTION_QUERY[:200] + "...",
            request_method=method,
            response_status=resp.status_code,
            curl_command=curl_cmd,
            reproduction_steps=(
                f"1. Send the introspection query to {url}\n"
                f"2. Run: {curl_cmd}\n"
                f"3. The response contains the full API schema with all types and fields.\n"
                f"4. Use a tool like GraphQL Voyager to visualize the schema."
            ),
            developer_fix=(
                "Disable introspection in your GraphQL server configuration:\n\n"
                "Apollo Server:\n"
                "  const server = new ApolloServer({\n"
                "    typeDefs,\n"
                "    resolvers,\n"
                "    introspection: process.env.NODE_ENV !== 'production',\n"
                "  });\n\n"
                "Express-GraphQL:\n"
                "  app.use('/graphql', graphqlHTTP({\n"
                "    schema,\n"
                "    graphiql: process.env.NODE_ENV !== 'production',\n"
                "  }));\n\n"
                "Hasura: HASURA_GRAPHQL_ENABLE_INTROSPECTION=false"
            ),
            affected_component=f"GraphQL API at {url}",
            references="https://graphql.org/learn/introspection/ | https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html | https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL",
            detection_method="Sent a standard GraphQL introspection query (__schema) and received a complete schema definition in the response, confirming introspection is enabled.",
        ))
        return True

    return False


def _test_depth_attack(session, method, url):
    resp = _send_query(session, method, url, "{ __typename }")

    if not resp or resp.status_code not in (200, 400):
        return

    for depth in [10, 15, 20]:
        deep_query = _build_depth_query(depth)
        start = time.time()
        resp = _send_query(session, method, url, deep_query)
        elapsed = time.time() - start

        if not resp:
            continue

        try:
            body = resp.json()
        except (json.JSONDecodeError, ValueError):
            continue

        has_data = "data" in body and body["data"] is not None
        has_depth_error = False
        if "errors" in body:
            error_text = json.dumps(body["errors"]).lower()
            has_depth_error = any(kw in error_text for kw in [
                "depth", "too complex", "complexity", "max depth", "nested",
            ])

        if has_depth_error:
            return

        if has_data or elapsed > 5:
            curl_cmd = _build_curl(url, deep_query, method)
            session.add_finding(Finding(
                title="GraphQL Missing Query Depth Limit",
                severity=Severity.MEDIUM,
                description=(
                    f"The GraphQL endpoint at '{url}' does not enforce query depth limits. "
                    f"A query with {depth} levels of nesting was accepted and processed. "
                    f"Attackers can craft deeply nested queries to cause denial-of-service "
                    f"by exhausting server resources."
                ),
                evidence=(
                    f"Endpoint: {url}\n"
                    f"Method: {method}\n"
                    f"Query Depth Tested: {depth} levels\n"
                    f"Response Time: {elapsed:.2f}s\n"
                    f"Response Status: {resp.status_code}\n"
                    f"Had Data: {has_data}\n"
                    f"No depth-related error returned"
                ),
                remediation=(
                    "1. Implement query depth limiting (recommended max: 7-10 levels):\n"
                    "   - graphql-depth-limit: depthLimit(10)\n"
                    "   - Apollo Server: validationRules with depthLimit\n"
                    "2. Add query complexity analysis to reject expensive queries.\n"
                    "3. Set query timeouts to prevent long-running operations.\n"
                    "4. Implement rate limiting on the GraphQL endpoint."
                ),
                url=url,
                module="graphql",
                cwe="CWE-770",
                confirmed=True,
                location=f"GraphQL endpoint at {url}",
                parameter="query (depth)",
                payload=f"Nested query at depth {depth}",
                request_method=method,
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Send a deeply nested GraphQL query ({depth} levels) to {url}\n"
                    f"2. Run: {curl_cmd}\n"
                    f"3. Observe the query is processed without a depth-limit error.\n"
                    f"4. Increase depth to cause server resource exhaustion."
                ),
                developer_fix=(
                    "Install and configure graphql-depth-limit:\n\n"
                    "  npm install graphql-depth-limit\n\n"
                    "Apollo Server:\n"
                    "  const depthLimit = require('graphql-depth-limit');\n"
                    "  const server = new ApolloServer({\n"
                    "    typeDefs, resolvers,\n"
                    "    validationRules: [depthLimit(10)],\n"
                    "  });\n\n"
                    "Also add query complexity analysis:\n"
                    "  npm install graphql-query-complexity\n"
                    "  // Assign cost per field and set a max complexity threshold"
                ),
                affected_component=f"GraphQL query parser/executor at {url}",
                references="https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#query-limiting-depth-and-amount | https://www.apollographql.com/blog/securing-your-graphql-api-from-malicious-queries",
                detection_method=f"Sent a GraphQL query nested {depth} levels deep and received a successful response without any depth-limit validation error.",
            ))
            return


def _test_batching(session, url):
    batch_payload = [
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
    ]

    resp = session.post(
        url,
        data=json.dumps(batch_payload),
        headers={"Content-Type": "application/json"}
    )
    if not resp:
        return

    try:
        body = resp.json()
    except (json.JSONDecodeError, ValueError):
        return

    if isinstance(body, list) and len(body) >= 3:
        curl_cmd = f"curl -k -X POST '{url}' -H 'Content-Type: application/json' -d '{json.dumps(batch_payload)}'"
        session.add_finding(Finding(
            title="GraphQL Query Batching Enabled",
            severity=Severity.LOW,
            description=(
                f"The GraphQL endpoint at '{url}' accepts batched queries. An attacker can "
                f"send multiple queries in a single HTTP request, potentially bypassing rate "
                f"limiting and amplifying the impact of expensive queries or brute-force attacks."
            ),
            evidence=(
                f"Endpoint: {url}\n"
                f"Batch Size Sent: {len(batch_payload)}\n"
                f"Responses Received: {len(body)}\n"
                f"Response Status: {resp.status_code}\n"
                f"All queries in the batch were processed independently."
            ),
            remediation=(
                "1. Disable query batching if not needed:\n"
                "   - Apollo Server: new ApolloServer({ allowBatchedHttpRequests: false })\n"
                "2. If batching is required, limit the maximum batch size (e.g., 5).\n"
                "3. Apply rate limiting per query, not per HTTP request.\n"
                "4. Implement query cost analysis across the entire batch."
            ),
            url=url,
            module="graphql",
            cwe="CWE-770",
            confirmed=True,
            location=f"GraphQL endpoint at {url}",
            parameter="query (batch)",
            payload=f"Array of {len(batch_payload)} queries",
            request_method="POST",
            response_status=resp.status_code,
            curl_command=curl_cmd,
            reproduction_steps=(
                f"1. Send an array of {len(batch_payload)} queries to {url}\n"
                f"2. Run: {curl_cmd}\n"
                f"3. Observe that all queries are executed and returned as an array.\n"
                f"4. An attacker can batch hundreds of queries to bypass rate limiting."
            ),
            developer_fix=(
                "Apollo Server v4:\n"
                "  const server = new ApolloServer({\n"
                "    typeDefs, resolvers,\n"
                "    allowBatchedHttpRequests: false,\n"
                "  });\n\n"
                "Express-GraphQL does not support batching by default (safe).\n\n"
                "If batching is needed, enforce a max batch size:\n"
                "  app.use('/graphql', (req, res, next) => {\n"
                "    if (Array.isArray(req.body) && req.body.length > 5) {\n"
                "      return res.status(400).json({ error: 'Batch size limit exceeded' });\n"
                "    }\n"
                "    next();\n"
                "  });"
            ),
            affected_component=f"GraphQL HTTP handler at {url}",
            references="https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#batching-attacks | https://lab.wallarm.com/graphql-batching-attack/",
            detection_method="Sent an array of 5 GraphQL queries in a single POST request and received an array of 5 independent responses, confirming batching is enabled.",
        ))


def _test_graphiql_exposure(session, method, url, resp):
    if method == "GRAPHIQL" or (resp and resp.status_code == 200):
        body = resp.text.lower() if resp else ""
        indicators = [
            "graphiql" in body,
            "graphql playground" in body,
            "graphql-playground" in body,
            "explorer" in body and "graphql" in body,
            "react" in body and "graphql" in body and ("editor" in body or "query" in body),
        ]
        if any(indicators):
            curl_cmd = f"curl -k '{url}'"
            session.add_finding(Finding(
                title="GraphiQL / GraphQL Playground Exposed",
                severity=Severity.LOW,
                description=(
                    f"A GraphQL interactive IDE (GraphiQL or Playground) is publicly accessible "
                    f"at '{url}'. This tool provides a full query editor with auto-completion, "
                    f"documentation explorer, and schema browsing -- making it trivial for "
                    f"attackers to explore and exploit the API."
                ),
                evidence=(
                    f"URL: {url}\n"
                    f"Response Status: {resp.status_code}\n"
                    f"GraphiQL indicators found in response body\n"
                    f"Content-Type: {resp.headers.get('Content-Type', 'N/A')}"
                ),
                remediation=(
                    "1. Disable GraphiQL/Playground in production:\n"
                    "   - Apollo: new ApolloServer({ plugins: [ApolloServerPluginLandingPageDisabled()] })\n"
                    "   - Express-GraphQL: graphqlHTTP({ graphiql: false })\n"
                    "2. If needed for development, restrict access by IP or authentication.\n"
                    "3. Use environment checks: graphiql: process.env.NODE_ENV !== 'production'"
                ),
                url=url,
                module="graphql",
                cwe="CWE-200",
                confirmed=True,
                location=f"GraphQL IDE at {url}",
                request_method="GET",
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Navigate to {url} in a browser.\n"
                    f"2. Observe the GraphiQL/Playground interface.\n"
                    f"3. Use the documentation explorer to browse the full schema.\n"
                    f"4. Run: {curl_cmd}"
                ),
                developer_fix=(
                    "Disable the IDE in production:\n\n"
                    "Express-GraphQL:\n"
                    "  app.use('/graphql', graphqlHTTP({\n"
                    "    schema,\n"
                    "    graphiql: process.env.NODE_ENV === 'development',\n"
                    "  }));\n\n"
                    "Apollo Server v4:\n"
                    "  import { ApolloServerPluginLandingPageDisabled } from '@apollo/server/plugin/disabled';\n"
                    "  const server = new ApolloServer({\n"
                    "    plugins: [ApolloServerPluginLandingPageDisabled()],\n"
                    "  });"
                ),
                affected_component=f"GraphQL IDE at {url}",
                references="https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html | https://graphql.org/learn/serving-over-http/",
                detection_method="Sent a GET request to the endpoint and detected GraphiQL/Playground HTML indicators in the response body.",
            ))


def _test_no_auth(session, method, url):
    sensitive_queries = [
        ("{ users { id email } }", "users"),
        ("{ user(id: 1) { id email role } }", "user by id"),
        ("mutation { __typename }", "mutation access"),
    ]

    for query, label in sensitive_queries:
        resp = _send_query(session, method, url, query)

        if not resp:
            continue

        try:
            body = resp.json()
        except (json.JSONDecodeError, ValueError):
            continue

        has_data = "data" in body and body["data"] is not None
        has_auth_error = False
        if "errors" in body:
            error_text = json.dumps(body["errors"]).lower()
            has_auth_error = any(kw in error_text for kw in [
                "unauthorized", "forbidden", "authentication", "not authenticated",
                "access denied", "login required", "permission",
            ])

        if has_data and not has_auth_error:
            data = body.get("data", {})
            data_str = json.dumps(data)
            if len(data_str) > 20 and data_str != '{"__typename":null}':
                curl_cmd = _build_curl(url, query, method)
                session.add_finding(Finding(
                    title=f"GraphQL Query Accessible Without Authentication ({label})",
                    severity=Severity.HIGH,
                    description=(
                        f"The GraphQL endpoint at '{url}' returned data for a '{label}' query "
                        f"without requiring authentication. Sensitive data may be accessible to "
                        f"unauthenticated users."
                    ),
                    evidence=(
                        f"Endpoint: {url}\n"
                        f"Query: {query}\n"
                        f"Response Status: {resp.status_code}\n"
                        f"Data Returned: {data_str[:500]}"
                    ),
                    remediation=(
                        "1. Implement authentication middleware on the GraphQL endpoint.\n"
                        "2. Add field-level authorization in resolvers.\n"
                        "3. Use schema directives for declarative auth: @auth(requires: ADMIN).\n"
                        "4. Never rely on obscurity -- all queries should check auth."
                    ),
                    url=url,
                    module="graphql",
                    cwe="CWE-306",
                    confirmed=True,
                    location=f"GraphQL endpoint at {url}",
                    parameter=f"query ({label})",
                    payload=query,
                    request_method=method,
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Send the query without any auth headers: {query}\n"
                        f"2. Run: {curl_cmd}\n"
                        f"3. Observe that data is returned without authentication."
                    ),
                    developer_fix=(
                        "Add authentication to your GraphQL resolvers:\n\n"
                        "Apollo Server context-based auth:\n"
                        "  const resolvers = {\n"
                        "    Query: {\n"
                        "      users: (_, args, context) => {\n"
                        "        if (!context.user) throw new AuthenticationError('Not authenticated');\n"
                        "        return db.users.findAll();\n"
                        "      }\n"
                        "    }\n"
                        "  };\n\n"
                        "Or use middleware: graphql-shield, graphql-auth-directives"
                    ),
                    affected_component=f"GraphQL resolver for '{label}' at {url}",
                    references="https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#access-control | https://www.apollographql.com/docs/apollo-server/security/authentication/",
                    detection_method=f"Sent a '{label}' GraphQL query without authentication credentials and received actual data in the response.",
                ))
                break


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing GraphQL endpoints...")

    base_url = session.config.target
    endpoints = _discover_endpoints(session, base_url)

    if not endpoints:
        return

    for method, url, resp in endpoints:
        logger.info(f" [+] Found GraphQL endpoint: {url} ({method})")

        if method == "GRAPHIQL":
            _test_graphiql_exposure(session, method, url, resp)
            test_resp = session.post(
                url,
                data=json.dumps({"query": "{ __typename }"}),
                headers={"Content-Type": "application/json"}
            )
            if test_resp and _is_graphql_response(test_resp):
                method = "POST"
            else:
                continue
        else:
            _test_graphiql_exposure(session, method, url, resp)

        _test_introspection(session, method, url)
        _test_depth_attack(session, method, url)
        _test_batching(session, url)
        _test_no_auth(session, method, url)
