# php-src threat model

Repository: `mkrishna793/php-src` (fork of php/php-src, master = 8.7.0-dev). No infrastructure repository: the user confirmed there isn't one, so deployment facts below are assumptions.

Scan scope (user's choice): attacker-reachable input parsing only. That is `main/`, `sapi/fpm`, `sapi/cgi`, `sapi/cli`, `sapi/apache2handler`, `ext/standard`, and the parser extensions `ext/json`, `ext/xml`, `ext/dom`, `ext/mbstring`, `ext/pcre`, `ext/zip`, `ext/phar`, `ext/exif`, `ext/gd`, `ext/intl`. The Zend engine, opcache and other extensions are not scanned.

Source of truth for classification: the repository's `SECURITY.md`, which links the full policy (php/policies `security-classification.rst`). `AGENTS.md` asks scanners to respect it.

## System overview and trust boundaries

PHP runs as an interpreter inside a server process. The trusted side is the PHP script and its configuration (php.ini, FPM pool config), which the deployer writes. The untrusted side is everything the script receives as data. The boundaries:

1. **Network → SAPI.** An HTTP request reaches PHP through a web server (nginx/Apache) speaking FastCGI to php-fpm or php-cgi, or in-process through mod_php. The SAPI turns the request into `$_SERVER`, `$_GET`, `$_POST`, `$_COOKIE` and `$_FILES` before any script code runs.
2. **Request data → script.** A trusted script passes untrusted strings and files to library functions: parsers, string functions, stream wrappers.
3. **FPM master → workers.** The php-fpm master often runs as root and forks unprivileged pool workers. They share a scoreboard in shared memory (`sapi/fpm/fpm/fpm_scoreboard.c`, `fpm_shm.c`), and the master manages sockets and logs.
4. **PHP → outbound network/filesystem.** Stream wrappers (`http://`, `ftp://`, `phar://`, `zip://`, `php://`) fetch or open resources that an attacker may control.

## Components

| Component | Code | Notes |
|---|---|---|
| **Request parsing** | `main/SAPI.c`, `main/rfc1867.c`, `main/php_variables.c`, `main/php_content_types.c`, `main/main.c` | Pre-script parsing of query strings, cookies, url-encoded and multipart bodies, uploads. Limits: `max_input_vars`, `max_multipart_body_parts`, `post_max_size`, `upload_max_filesize`. |
| **SAPIs & FastCGI** | `main/fastcgi.c`, `sapi/fpm`, `sapi/cgi`, `sapi/apache2handler`, `sapi/cli` | FastCGI record/param parsing (`fcgi_read_request`, `fcgi_get_params`), FPM `fpm_main.c` path handling (`cgi.fix_pathinfo`, `security.limit_extensions`), FPM status page (`fpm_status.c`), master/worker processes, CLI built-in server (`sapi/cli/php_cli_server.c`). |
| **Streams & wrappers** | `main/streams/*`, `main/network.c`, `ext/standard/http_fopen_wrapper.c`, `ext/standard/ftp_fopen_wrapper.c`, `ext/standard/php_fopen_wrapper.c`, `ext/standard/filters.c` | Response parsing from servers the attacker may control (HTTP headers, redirects, chunked encoding, FTP replies) and stream filters. |
| **Standard library** | rest of `ext/standard` | String and format functions, `parse_url`, `escapeshellarg`/`escapeshellcmd` (policy says these must be hardened), `mail()` headers, `base64`/`quoted_printable`, `var_unserializer.re` (malicious input is out of scope, see below). |
| **Archive & image parsers** | `ext/phar`, `ext/zip`, `ext/exif`, `ext/gd` (bundled libgd), `ext/standard/image.c` (`getimagesize`) | Parse uploaded or fetched binary files: phar/tar/zip manifests, EXIF/TIFF IFDs, image headers. Classic memory-safety surface. |
| **Text & markup parsers** | `ext/json`, `ext/xml`, `ext/dom` (libxml2 + bundled lexbor HTML5), `ext/mbstring` (libmbfl), `ext/pcre` (bundled pcre2, JIT), `ext/intl` (ICU) | Parse untrusted JSON, XML/HTML, multibyte text and regex subjects. |

## Entry points and who reaches them

- **Remote, unauthenticated HTTP client:** any byte of the request line, headers, cookies and body through Request parsing and SAPIs & FastCGI, before the script runs. This is the highest-exposure surface.
- **Remote content supplier:** files uploaded to, or URLs fetched by, a typical script, through Archive & image parsers, Text & markup parsers, Streams & wrappers and Standard library functions that normal apps commonly pass user data to (`json_decode`, `getimagesize`, `exif_read_data`, `DOMDocument::loadHTML`, `mb_*`, `preg_*`, `htmlspecialchars`, `parse_url`).
- **Malicious upstream server:** HTTP/FTP responses read through Streams & wrappers.
- **Local unprivileged user / co-tenant pool:** the FPM master/worker boundary, shared memory, sockets and log files (SAPIs & FastCGI).

## Assets

- Integrity of the PHP worker process: code execution through memory corruption.
- Data in the worker's memory and files readable by its uid: other requests' data, session files, secrets in env/config. Information leaks such as uninitialized memory in output.
- Availability: a worker crash or CPU/memory exhaustion triggered by a small request.
- On FPM: the root master process and isolation between pools.

## Attacker profiles

1. Remote unauthenticated attacker sending HTTP requests to a typical PHP app (primary).
2. Attacker supplying files or text that the app parses with standard functions (primary).
3. Malicious remote server answering PHP's outbound requests (secondary).
4. Local user or another FPM pool on the same host (secondary).

Not attackers in this model: anyone who can write or run PHP code, or edit php.ini or FPM config. PHP has no sandbox.

## Existing controls

- Input limits: `max_input_vars`, `max_input_nesting_level`, `max_multipart_body_parts`, `post_max_size`, `upload_max_filesize`, `memory_limit`, `max_execution_time`, `pcre.backtrack_limit`/`pcre.recursion_limit`.
- Overflow-checked allocators (`safe_emalloc`, `zend_safe_address`) and the Zend memory manager with heap protection.
- FPM: `security.limit_extensions` (default `.php`), per-pool user/group, `listen.owner`/`listen.mode`, status page off unless `pm.status_path` is set.
- Upload temp files are tracked so that `move_uploaded_file` only moves real uploads.
- Phar: `phar.readonly`, `phar_path_check.c`.

## Out of scope / accepted risk (from SECURITY.md)

Not security issues:
- Crafted malicious PHP code (error handlers, destructors, `__toString()`) causing memory violations.
- Malicious arguments to functions not intended to receive unsanitized values (for example `mysqli_query()`). `escapeshellarg()` and similar functions *are* expected to be hardened.
- Legacy or documented-insecure APIs and settings.
- FFI.
- `open_basedir` / `disable_functions` bypasses.
- Malicious `unserialize()` input.
- Memory exhaustion from a size the input declares, when `memory_limit` refuses the allocation and only the current request dies.

The full policy linked from SECURITY.md also excludes debugging facilities, non-production settings, non-standard environment variables or builds, actions that need more than PHP's uid, and the built-in web server. It rates issues present only in an unstable branch as Low.

### User decisions (2026-11-09)

- **Purpose:** the fork exists to contribute fixes and reports upstream, so findings are judged by what php/php-src would accept.
- **Priorities are not moved by policy:** the user chose to keep every finding at its scanner severity. That includes findings in the categories above (built-in web server, unstable-branch-only, FFI, `open_basedir`, `unserialize`, malicious code). The policy is recorded only in each finding's `PHP policy class` tag, so findings can be filtered by upstream classification without dismissing anything.
- **Primary deployment:** PHP-FPM behind nginx/Apache handling untrusted HTTP requests and uploads. This is the reference deployment when filling in the `PHP policy class` tag (it decides "typical installation"). It does not change priorities.

## Open questions

- None outstanding. The user can change any decision above, for example to let the policy lower findings it does not consider security issues.
