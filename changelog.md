# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.4.33] - 2026-05-19

### Added
- No adds.

### Changed
- **Docstring Refactoring**: Updated and standardized `parallel_pivot`
  docstrings to follow Google Style guidelines with a strict 80-character
  maximum width limit.

### Fixed
- **Parallel Pivot Replication Bug**: Added `force_replicate=True` to the
  `columns` argument in `parallel_pivot` to prevent incorrect unpacking
  across parallel tasks when the number of columns matched the number of
  arguments.

## [2.4.32] - 2026-05-08
### Added
- No adds.

### Changed
- **Exception Handling Refactor**:
  - Standardized `PumpWoodException`, `PumpWoodOtherException`, and the
    `raise_pumpwood_exception` factory to follow Google Style docstrings.
  - Eliminated mutable default argument anti-patterns by replacing
    `payload: dict = {}` with `None` and internal initialization across
    the exception hierarchy.
  - Enhanced type hinting and documentation for exception parameters
    (`status_code`, `translate`, `parallel`).
- **Improved Exception Factory**: Refactored `raise_pumpwood_exception` to
  include robust validation, error logging via `loguru`, and a safe fallback
  to `PumpWoodOtherException` for unregistered exception names.

### Fixed
- Resolved potential state-leakage bugs caused by shared mutable dictionaries
  in exception constructors.
- Corrected typos and PEP-8 formatting issues within `exceptions.py`.


## [2.4.31] - 2026-05-06
### Added
- No adds.

### Changed

- Standardized `list_by_chunks` docstrings to Google Format for better
  readability and tool compatibility.
- Updated `list_by_chunks` return type hints to include `pd.DataFrame` and
  `List[dict]` using `Union`.
- Refactored `list_by_chunks` return logic to remove unreachable code and
  improve structure.
- Corrected typos in comments and documentation within `list.py`.
- Fixed the pagination on `list_by_chunks` when the id__gt was passed
  as argument on filter_dict parameter.

### Removed

- No removes.

## [2.4.30] - 2026-05-05

### Added

- No adds.

### Changed

- **Fixed `list_by_chunks` logic**: Improved the pagination mechanism to correctly handle base64 encoded primary keys. It now extracts the `id` from composite keys to ensure seamless fetching of data chunks.
- **Documentation Standardization**: Completed the migration to Google Style docstrings and added comprehensive type hints across `ABCSimpleListMicroservice`, `ABCSimpleBatchMicroservice`, and the base classes.
- **Enhanced Serializers**:
  - Updated `pumpJsonDump` to support the `indent` argument, allowing for human-readable JSON output.
  - Improved `CompositePkBase64Converter.dump` to return the raw value instead of a base64 string when a single-field primary key (e.g., `{"id": value}`) is used.
- **Deprecation**: Added a deprecation warning for the `variables` argument in the `pivot` method, encouraging the use of `fields` for consistency.

### Removed

- No removes.

## [2.4.29] - 2026-05-02

### Added

- No adds.

### Changed

- Set `use_disk_cache=True` as the default behavior in `fill_options` for optimized schema retrieval.
- Fixed a bug in `fill_options` where substituting the request's `auth_header` caused conflicts with the microservice login. Introduced a localized `temp_auth_header` specifically for securely generating the cache hash without side-effects.

### Removed

- No removes.

## [2.4.28] - 2026-05-02

### Added

- Implemented `use_disk_cache` parameter in `fill_options` alongside the `FillOptionsNoDataCacheHash` to optimize schema retrieval.
- Introduced `authorization` to the cache hash to ensure strict cross-tenant data isolation and prevent metadata leakage.

### Changed

- Fixed mutable default argument bug in `fill_validation` endpoint.
- Standardized docstrings across `ABCSimpleInfoMicroservice` to comply with the Google Style format.
- Resolved typo issues and improved overall PEP-8 compliance in the module.

### Removed

- No removes.

## [2.4.27] - 2026-04-30

### Added

- `use_app_cache` parameter to `retrieve`, `list_one`, and their parallel
  counterparts. This enables application-level caching for individual object
  retrieval.
- `upsert` parameter to `save` and `parallel_save` methods. This allows
  creating  objects when a primary key is provided but doesn't exist on the
  database.

### Changed

- Improved type hints across `retrieve.py`, `save.py`, and parallel
  implementation modules.
- Replicated `use_app_cache` and `upsert` arguments in `parallel_retrieve`, `parallel_list_one`, and `parallel_save` to maintain consistency across the API.
- Updated `PumpWoodException.to_dict()` with a more specific return type hint.

### Removed

- No removes.

## [2.4.25] - 2026-04-28

### Added

- New `validate_primary_key_dict` method in `CompositePkBase64Converter` to enforce
  data integrity on composite keys (ensures flat dictionaries with no nesting).
- Support for `numpy` numeric types and `decimal.Decimal` in the `retrieve` method
  type validation.

### Changed

- Refactored `retrieve()` method:
  - Automatically handles dictionary-based primary keys (composite or unique
    constraints) by serializing them to base64.
  - Improved robustness of type checking using `numbers.Number` and `np.number`.
  - Significantly enhanced docstrings with detailed implementation examples.
- Updated `dump_dict()` to use centralized validation logic and fixed a keyword
  argument mismatch (`primary_key_dict`).

### Fixed

- Corrected potential "ghost" variable issues by using `serialized_pk` during
  URL construction in the retrieval pipeline.

## [2.4.19] - 2026-04-16

### Added

- No adds.

### Changed

- Fixed the fields argument on pivot that was not working.

### Removed

- No removes

## [2.4.18] - 2026-04-16

### Added

- No adds.

### Changed

- Fixed the `CompositePkBase64Converter` to convert dictionary with only
  `{"id": value}` to return just the `value` without base64 conversion.

### Removed

- No removes

## [2.4.17] - 2026-03-30

### Added

- Add types for return of action parameters and information.

### Changed

- No changes.

### Removed

- No removes

## [2.4.15] - 2026-03-30

### Added

- Sentinel class for autofill fields.

### Changed

- No changes.

### Removed

- No removes

## [2.4.12] - 2026-03-25

### Added

- No adds.

### Changed

- Fix cripto object not correct error raise.

### Removed

- No removes

## [2.4.11] - 2026-03-24

### Added

- Add `as_dataframe` argument to list and pivot function to return
  results as dataframe and set the columns according to the fields
  if passed as argument.

### Changed

- No changes.

### Removed

- No removes

## [2.4.8] - 2026-03-17

### Added

- No adds.

### Changed

- Set `PUMPWOOD_COMUNICATION__PARALLEL_CHUNK_SIZE` enviroment variable
  to set the chunk size of parallel bulk save operations.

### Removed

- No removes

## [2.4.2] - 2026-03-07

### Added

- No adds.

### Changed

- Refactor parallel implementation to use threads.

### Removed

- No removes

## [2.3.5] - 2026-03-05

### Added

- No adds.

### Changed

- Pivot function breaking with new fill_options return, it was made compatible
  with both actual and legacy.

### Removed

- No removes

## [2.3.2] - 2026-02-17

### Added

- No adds.

### Changed

- Migrate some enviroment variables get to config to centralize.
- Add new types to cover Primary Keys, now and today defauls.

### Removed

- No removes

## [2.3.1] - 2026-02-17

### Added

- Add Pumpwood types to allow consistency between Flask, Django, etc...

### Changed

- Refactor part of the batch calls.

### Removed

- No removes

## [2.2.49] - 2026-02-06

### Added

- No adds.

### Changed

- Add storage path to cache, in deployments with more than one service
  doming it is possible that cache might colide between services. I might
  not be a problem, but is better be safe than sorry.

### Removed

- No removes

## [2.2.48] - 2026-02-04

### Added

- Add base skip filter in save endpoint.

### Changed

- No changes.

### Removed

- No removes

## [2.2.47] - 2026-01-14

### Added

- No Adds.

### Changed

- Fix stream upload.

### Removed

- No removes

## [2.2.40] - 2025-12-30

### Added

- Add `base_filter_skip` parameter for end-points, this will send a
  list at URL parameters that can be used by super user to skip application
  of base_filter.

### Changed

- Refactor system end-points calls.

### Removed

- No removes

## [2.2.39] - 2025-11-28

### Added

- Add clear cache and heath check for each server pointing to new
  service general API paths.

### Changed

- Refactor system end-points calls.

### Removed

- No removes

## [2.2.32] - 2025-10-31

### Added

- No adds.

### Changed

- Fix JSON Decimal object conversion.
- Remove default dictionary and list to avoid default update mess.

### Removed

- No removes

## [2.2.26] - 2025-09-23

### Added

- No adds.

### Changed

- Fix composite primary key creation.

### Removed

- No removes

## [2.2.25] - 2025-09-16

### Added

- Allow clear and evicting (using a tag dictionary) cache .

### Changed

- No changes.

### Removed

- No removes

## [2.2.23] - 2025-09-09

### Added

- No adds.

### Changed

- Refactor pivot to batch class.

### Removed

- No removes

## [2.2.19, 2.2.20] - 2025-09-09

### Added

- No adds.

### Changed

- Add numpy to orjson serialization.
- Fix cache `expire` argument that was not been used.

### Removed

- No removes

## [2.2.15] - 2025-09-09

### Added

- No adds.

### Changed

- Set cache to a specific location for all workers to use the same
  disk cache database.

### Removed

- No removes

## [2.2.14] - 2025-09-09

### Added

- Add disk cache for get requests.

### Changed

- Refactor codes.

### Removed

- No removes

## [2.2.11] - 2025-03-08

### Added

- Add exception for unique errors on database `PumpWoodUniqueDatabaseError`.

### Changed

- No changes.

### Removed

- No removes

## [2.2.9] - 2025-03-08

### Added

- No adds.

### Changed

- Update `CompositePkBase64Converter.dump` to be able to pass a dictionary to
  `obj` (it just worked with objects before).

### Removed

- No removes

## [2.2.8] - 2025-03-08

### Added

- Add `add_pk_column` parameter to `pivot` function in order to return primary
  key column on pivot.

### Changed

- Changed behavior of `CompositePkBase64Converter.dump` to accept
  dictionary and list at `primary_keys` argument. It now permits to
  pass map dictionary to create composite primary converting fields
  to other keys. This can be used at related fields when the target
  object has different names. List argument will keep same behavior
  of the past implementation, and string will return the field without
  converting to base64 dictionary.

## [2.2.7] - 2025-03-08

### Added

- No adds

### Changed

- Changed behavior of `CompositePkBase64Converter.dump` to accept
  dictionary and list at `primary_keys` argument. It now permits to
  pass map dictionary to create composite primary converting fields
  to other keys. This can be used at related fields when the target
  object has different names. List argument will keep same behavior
  of the past implementation, and string will return the field without
  converting to base64 dictionary.

### Removed

- No removes.

## [2.2.4] - 2025-03-08

### Added

- No adds

### Changed

- Change env variable for debug from `DEBUG` to `PUMPWOOD_COMUNICATION__DEBUG`
  to reduce collision with Django and Flask debug env variables.

### Removed

- No removes.

## [2.2.4] - 2025-02-22

### Added

- Add indent argument to `serializers.pumpJsonDump` to make human readable
  JSON.

### Changed

- No changes

### Removed

- No removes.

## [2.2.3] - 2025-02-11

### Added

- No adds.

### Changed

- No changes

### Removed

- Remove debug prints
