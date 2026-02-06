# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
