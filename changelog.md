# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
