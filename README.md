# PumpWood Communication

This package facilitates communication with PumpWood-pattern endpoints
and helps with authentication. It was developed by Murabei Data Science
and is under the BSD-3-Clause license.

<p align="center" width="60%">
  <img src="static_doc/sitelogo-horizontal.png" /> <br>

  <a href="https://en.wikipedia.org/wiki/Cecropia">
    Pumpwood is a native Brazilian tree
  </a> which has a symbiotic relation with ants (Murabei)
</p>

## Objective and motivation

Python client library for PumpWood-style REST backends: login, CRUD,
actions, batch and parallel calls, disk cache, and typed exceptions.

### Why this exists

PumpWood services share a common endpoint layout (`rest/<model>/…`).
This package centralizes HTTP calls, auth token handling, error
rehydration, and parallel chunking so workers and scripts do not
reimplement that wiring.

### How it is used

Import `PumpWoodMicroService`, configure `server_url` and credentials,
call `login()`, then use list, save, retrieve, delete, and action
helpers from workers, ETL jobs, notebooks, or other Murabei services.

### Scope

Owns the HTTP client, serializers, cache, exception mapping, and shared
dataclass types for ETL payloads and view configuration. Backend
business rules, models, and deploy live in PumpWood API services. See
the generated docs for the full method list.

## Documentation

Check the documentation page
[here](https://murabei-opensource-codes.github.io/pumpwood-communication/pumpwood_communication.html).

## Install

Requires Python 3.6 or newer (`requires-python` in `pyproject.toml`).

```bash
pip install pumpwood-communication
```

For local development, install from the repository root with Poetry or
pip in editable mode.

## Quick start

The main class in the package is `PumpWoodMicroService`. It abstracts
all endpoint communication using helper methods. Set credentials when
initializing the object or afterward with `init`.

```python
from pumpwood_communication.microservices import PumpWoodMicroService

microservice = PumpWoodMicroService(
    server_url="http://0.0.0.0:8080/",
    username="pumpwood", password="pumpwood")
microservice.login()
```

Sometimes it is easier to create the object first and set credentials
later with `init`:

```python
from pumpwood_communication.microservices import PumpWoodMicroService

microservice = PumpWoodMicroService()

# After many validations or other functions
[...]

microservice.init(
    server_url="http://0.0.0.0:8080/",
    username="pumpwood", password="pumpwood")
microservice.login()
```

`PumpWoodMicroService` constructor and `init` accept these parameters:

- **name:** Microservice name for debug purposes only; does not affect
  usage.
- **server_url:** Server URL using the PumpWood pattern.
- **username:** Username for the connection.
- **password:** Password for the connection.
- **verify_ssl:** In some test environments the endpoint may use a
  self-assigned certificate.

## Basic definition

These concepts help understand the general structure of PumpWood-based
endpoints.

PumpWood endpoints are organized by `model_class`, the class exposed
through the PumpWood API. Every object has its own primary key,
returned as `pk` in JSON responses regardless of the database column
name (`pk` may map to `id` or `identification_id` in the DB).

All endpoints for a given `model_class` follow
`rest/[model_class]/[endpoint]/[?pk]&[query parameters]`. Examples:

- [POST] `rest/user/list/`
- [POST] `rest/user/list-without-pag/`
- [POST] `rest/user/save/`
- [GET] `rest/user/retrieve/5/`
- [POST] `rest/company/save/`
- [POST] `rest/company/actions/duplicate/5/`
- [GET] `rest/company/actions/`

## Raise and error treatment

When a PumpWood exception is identified in the request response, the
microservice re-raises it using the same exception type. This helps
debugging and propagating errors across endpoints.

Exceptions defined in the package can be raised directly:

```python
from pumpwood_communication.exceptions import PumpWoodException

raise PumpWoodException(
  message="Error to be mapped using the APIs",
  payload={
      "payload": "payload-data"
  })
```

## Base query filters and superuser

Many endpoints accept ``base_filter_skip`` to skip backend base query
filters (row-level restrictions). When the argument is omitted:

- **Superusers** (after ``login``) default to ``['ALL']``.
- **Other users** default to ``[]`` (no filters skipped).

Superuser status comes from the ``user`` object returned at login and
stored on the microservice instance. Explicit values are always passed
through unchanged.

``logout`` and ``logout_all`` clear the cached user, token, and auth
header so ``is_superuser()`` and ``base_filter_skip`` defaults reset
correctly.

## Cloning the microservice client

Use ``clone()`` on ``PumpWoodMicroService`` to build a second client with
the same ``server_url``, credentials, and timeout settings. When
``copy_session=True`` (default) and the instance is logged in, the clone
receives a copy of the auth header and user so background threads can
call the API without sharing mutable token state with the original
client.

```python
worker_ms = microservice.clone()
# use worker_ms in a thread or async worker
```

Pass ``copy_session=False`` to get a fresh client that must ``login()``
on its first request.

## Environment variables

Correct spelling is ``PUMPWOOD_COMMUNICATION__*``. Legacy typo spelling
``PUMPWOOD_COMUNICATION__*`` is still supported as fallback when the
correct name is not set.

### Parallel and requests

- **PUMPWOOD_COMMUNICATION__N_PARALLEL:** Number of parallel requests.
  Default ``4``.
- **PUMPWOOD_COMMUNICATION__PARALLEL_CHUNK_SIZE:** Chunk size for
  parallel bulk save. Default ``10000``.
- **PUMPWOOD_COMMUNICATION__DEFAULT_TIMEOUT:** Default HTTP request
  timeout in seconds. Default ``60``.
- **PUMPWOOD_COMMUNICATION__DEBUG:** Refresh token on each request when
  ``TRUE``. Default ``FALSE``.
- **PUMPWOOD_COMMUNICATION__VERIFY_SSL:** Validate server certificates
  when ``TRUE``. Default ``TRUE``.

### Cache

- **PUMPWOOD_COMMUNICATION__CACHE_ENABLE:** Enable disk cache. Default
  ``TRUE``.
- **PUMPWOOD_COMMUNICATION__CACHE_BASE_PATH:** Sub-path under
  ``/tmp/pumpwood_cache/``. Default empty string.
- **PUMPWOOD_COMMUNICATION__CACHE_LIMIT_MB:** Disk cache size limit in
  megabytes. Default ``250``.
- **PUMPWOOD_COMMUNICATION__CACHE_DEFAULT_EXPIRE:** Default cache entry
  TTL in seconds. Default ``60``.
- **PUMPWOOD_COMMUNICATION__CACHE_TRANSACTION_TIMEOUT:** SQLite
  transaction timeout in seconds. Default ``0.1``. Use ``5`` or higher
  under heavy parallel load.
- **PUMPWOOD_COMMUNICATION__CACHE_N_SHARDS:** Number of FanoutCache
  shards. Default ``8``.
- **PUMPWOOD_COMMUNICATION__CACHE_RETRY_ATTEMPTS:** Retries on SQLite
  lock contention. Default ``5``.
- **PUMPWOOD_COMMUNICATION__CACHE_RETRY_DELAY:** Base delay in seconds
  between cache retries. Default ``0.05``.
- **PUMPWOOD_COMMUNICATION__AUTHORIZATION_CACHE_TIMEOUT:** TTL for
  authorization and row-permission cache. Default ``60``.

### Encryption

- **PUMPWOOD_COMMUNICATION__CRYPTO_FERNET_KEY:** Fernet key for
  ``PumpwoodCryptography``. No default; encrypt/decrypt raise when unset.

## Basic usage

The sections below cover common operations. For the full API, see the
generated documentation.

### List and list without pagination

Both methods list objects using dictionaries passed as payload on a
POST request.

```python
from pumpwood_communication.microservices import PumpWoodMicroService

microservice = PumpWoodMicroService(
    server_url="http://0.0.0.0:8080/",
    username="pumpwood", password="pumpwood")
microservice.login()

list_results = microservice.list(
    model_class="Company",
    filter_dict={
      "name__icontains": "Acme",
    }, exclude_dict={
      "status__in": ["deprected", "inactive"],
    },
    order_by=["holding_name", "-name"]
)
```

Use `filter_dict` and `exclude_dict` to adjust the query. Order results
with a list of fields; names starting with `-` sort in descending order.

`list` paginates results according to the backend page size.
`list_without_pag` does not paginate and must be used with caution for
large result sets. Manual pagination using received primary keys is
also possible:

```python
microservice = PumpWoodMicroService(
    server_url="http://0.0.0.0:8080/",
    username="pumpwood", password="pumpwood")
microservice.login()

# Get the first page results using the filters and the order
pag_1 = microservice.list(
    model_class="Company",
    filter_dict={
      "name__icontains": "Acme",
    }, exclude_dict={
      "status__in": ["deprected", "inactive"],
    },
    order_by=["holding_name", "-name"]
)

# Get the list of the pks received
pag_1_pks = [obj["pk"] for obj in pag_1]

# Use in the next page query
pag_2 = microservice.list(
    model_class="Company",
    filter_dict={
      "name__icontains": "Acme",
    }, exclude_dict={
      "status__in": ["deprected", "inactive"],
      "pk__in": pag_1_pks
    },
    order_by=["holding_name", "-name"]
)
```

Restrict fields returned by the endpoint with the `fields` parameter.
When `fields` is `None`, default columns are returned.

Use `__` to access related fields and apply operators (similar to the
Django ORM). Some examples:

#### Time, date, and numeric

- **gt:** Greater than.
- **lt:** Less than.
- **gte:** Greater than or equal.
- **lte:** Less than or equal.

#### List of values

- **in:** Check if a value is present in a list.

#### Text field

- **contains:** Check if a value contains another.
- **icontains:** Case-insensitive contains.
- **unaccent_icontains:** Contains, case and accent insensitive.
- **startswith:** Starts with the given text.
- **istartswith:** Starts with, case insensitive.
- **unaccent_istartswith:** Starts with, case and accent insensitive.
- **endswith:** Ends with the given text.
- **iendswith:** Ends with, case insensitive.
- **unaccent_iendswith:** Ends with, case and accent insensitive.

#### Date and time fields

- **year:** Date is in the specified year.
- **month:** Date is in the specified month.
- **day:** Date is on the specified day.

#### JSON fields

Access JSON key/value pairs with the `->` operator.

```python
list_results = microservice.list(
    model_class="Company",
    filter_dict={
      "json_dimensions->dim1__icontains": "test_dimention",
    }, exclude_dict={
      "json_extra_info->parameter__in": [
        1, "1", None],
    },
    order_by=[
      "json_extra_info->company-cat", "-name"]
)
```

### Saving and updating objects

Use the `save` method with a dictionary that includes `model_class` to
select the endpoint.

If `pk` is present, the object is updated. `pk=None` creates a new row.

```python
# Creating a new object
microservice.save(obj_dict={
  "model_class": "Company",
  "name": "New Company",
  "json_extra_info": {
      "cat": "joe"
  },
  "json_dimensions": {
      "dim1": "test_save"
  }
})

# Updating an object in the database
microservice.save(obj_dict={
  "pk": 5,
  "model_class": "Company",
  "name": "New Company",
  "json_extra_info": {
      "cat": "joe"
  },
  "json_dimensions": {
      "dim1": "test_save"
  }
})
```

### Deleting objects

Use `delete` to remove a single object by primary key. Some model
classes soft-delete (`deleted=True`) instead of removing the row.

Pass ``force_delete=True`` to request a hard delete when the backend
supports it (default ``False``).

```python
microservice.delete(model_class="Company", pk=5)

microservice.delete(
    model_class="Company", pk=5, force_delete=True)
```

Use `delete_many` with `filter_dict` and `exclude_dict` to remove
multiple rows. ``force_delete`` is accepted on the simple endpoint but
raises ``NotImplementedError`` when set to ``True`` until backend
support is complete.

### Actions: listing and executing

Each `model_class` can expose actions, regular or static (not tied to
an object). List available actions with `list_actions`:

```python
resp_list_actions = microservice.list_actions(
    model_class="Company")
# [
#   {
#     "action_name": "duplicate",
#     "doc_string": "Doc string of the function",
#     "info": "Duplicate the company at the database.",
#     "is_static_function": false,
#     "parameters": {
#       "suffix": {
#         "default_value": "new ",
#         "required": false,
#         "type": "bool"
#       },
#       "clone_id": {
#         "default_value": None,
#         "required": true,
#         "type": "bool"
#       }
#     }
#   },
#   {
#     "action_name": "create_company_from_holding",
#     "doc_string": "Doc string of the function",
#     "info": "Create a company associated to a holding.",
#     "is_static_function": true,
#     "parameters": {
#       "holding_name": {
#         "default_value": None,
#         "required": true,
#         "type": "str"
#       },
#       "parameters": {
#         "default_value": {},
#         "required": false,
#         "type": "dict"
#       }
#     }
#   }
# ]
```

Execute an action with `execute_action`:

```python
microservice.execute_action(
    model_class="Company", pk=1, action="duplicate", parameters={
        "clone_id": True})

microservice.execute_action(
    model_class="Company", action="create_company_from_holding", parameters={
        "holding_name": "Holding one",
        "parameters": {"parm1": 1, "param2": 2}})
```

## Disabling ETL triggers

``save``, ``delete``, and ``execute_action`` accept an optional
``disable_etl_trigger`` query parameter (default ``False``). Set it to
``True`` to skip backend ETL triggers on that request.

Parallel helpers ``parallel_save``, ``parallel_delete``, and
``parallel_execute_action`` forward the same flag as a single ``bool``
or a per-request ``list[bool]``.

```python
microservice.save(obj_dict={...}, disable_etl_trigger=True)

microservice.delete(
    model_class="Company", pk=5, disable_etl_trigger=True)

microservice.parallel_save(
    list_obj_dict=objects, disable_etl_trigger=True)
```

### Other functions
Other methods are documented in their docstrings. Some of the helpers
on `PumpWoodMicroService`:

- clone
- error_handler
- request_post
- request_get
- request_delete
- list_registered_routes
- list_registered_endpoints
- list
- list_without_pag
- list_dimentions
- list_dimention_values
- list_one
- retrieve
- retrieve_file
- retrieve_streaming_file
- save
- save_streaming_file
- delete
- remove_file_field
- delete_many
- list_actions
- execute_action
- search_options
- fill_options
- pivot
- bulk_save
- parallel_request_get
- parallel_request_post
- parallel_request_delete
- parallel_retrieve
- parallel_list
- parallel_list_without_pag
- parallel_list_one
- parallel_save
- parallel_delete
- parallel_delete_many
- parallel_execute_action
- parallel_bulk_save
- parallel_pivot
