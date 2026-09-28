# ngx_http_mupdf_module

An nginx module that converts documents with the [MuPDF](https://mupdf.com/) library. A location takes its input document (HTML by default) from an nginx complex value, converts the selected pages to another format (PDF by default) and returns the result as the response.

## Building

```sh
./configure --add-dynamic-module=/path/to/ngx_http_mupdf_module
make modules
```

`config` first tries to link a static MuPDF build (`-lmupdf -lmupdfthird -lfreetype -lharfbuzz -ljpeg -ljbig2dec -lopenjp2`), then falls back to `pkg-config mupdf`, and stops `configure` with an error if neither works. The module needs MuPDF 1.24 or newer.

The `mupdf_thread_pool` directive requires nginx built `--with-threads`.

## Directives

### mupdf

- **syntax:** `mupdf <text>;`
- **context:** `location`
- Sets the input document and makes this module the location's content handler. The value is an [nginx complex value](https://nginx.org/en/docs/dev/development_guide.html#http_variables), so it can reference variables.
- Only `GET` and `HEAD` requests are accepted, others get `405`. A `HEAD` request still runs the conversion to get `Content-Length`.

### mupdf_input_type

- **syntax:** `mupdf_input_type <type>;`
- **default:** `html`
- **context:** `http`, `server`, `location`
- The input format, as a file extension or MIME type that MuPDF recognises, e.g. `html`, `xhtml`, `pdf`, `xps`, `epub`, `svg`, `png`.

### mupdf_output_type

- **syntax:** `mupdf_output_type <type>;`
- **default:** `pdf`
- **context:** `http`, `server`, `location`
- The output format passed to the MuPDF document writer, e.g. `pdf`, `png`, `svg`, `ps`, `text`, `html`, `docx`, `odt`, `cbz`.
- The response `Content-Type` is looked up from this value in the location's `types` map (`mime.types`), the same way nginx does it for file extensions. Formats missing from the standard `mime.types` get a built-in type: `text` is `text/plain`, `stext` is `text/xml`, `stext.json` is `application/json`, `csv` is `text/csv`, `cbz` is `application/vnd.comicbook+zip`, `pam`, `pbm`, `pgm`, `pnm` and `ppm` are `image/x-portable-*`, `pcl` is `application/vnd.hp-pcl`, `pwg` is `image/pwg-raster` and `ocr` is `application/pdf`. Other formats fall back to `default_type`.
- Image formats such as `png` write each page as a separate image into the same response, so use `mupdf_range` to select a single page.

### mupdf_options

- **syntax:** `mupdf_options <options>;`
- **default:** empty
- **context:** `http`, `server`, `location`
- Comma-separated MuPDF document writer options, e.g. `compress` for PDF or `resolution=150` for images.

### mupdf_range

- **syntax:** `mupdf_range <range>;`
- **default:** `1-N`
- **context:** `http`, `server`, `location`
- The pages to convert, in MuPDF page range syntax: comma-separated page numbers and ranges, where `N` is the last page. A range may run backwards, e.g. `N-1` outputs the pages in reverse order.

### mupdf_timeout

- **syntax:** `mupdf_timeout <time>;`
- **default:** `0` (no limit)
- **context:** `http`, `server`, `location`
- Limits the conversion time, counted from the start of the request handling (with a thread pool this includes the time spent in the queue). When the limit is exceeded, the request fails with `500` and `mupdf_timeout ... exceeded` is logged, instead of returning a truncated document.
- The deadline is checked before each page and after the last one. With `mupdf_thread_pool`, a timer also asks MuPDF to stop rendering the current page, which only works for formats that support it, such as PDF input. MuPDF cannot interrupt HTML layout or the rendering of an HTML page, so a single very large page still runs to completion.

### mupdf_thread_pool

- **syntax:** `mupdf_thread_pool <name> | off;`
- **default:** `off`
- **context:** `http`, `server`, `location`
- Runs conversions in the named nginx [thread pool](https://nginx.org/en/docs/ngx_core_module.html#thread_pool) instead of the worker process, so that a long conversion does not block other requests. The pool named `default` exists without a `thread_pool` directive (32 threads), other names must be defined with one.
- Without it, the conversion runs inside the worker and blocks it until it finishes.
- Messages from MuPDF during a conversion in a thread pool are logged when the conversion is done, at most 64 of them per request.

### mupdf_store_size

- **syntax:** `mupdf_store_size <size>;`
- **default:** `256m`
- **context:** `http`
- The size of the MuPDF resource cache (fonts, images, ...). Each worker process has its own cache, shared by all its requests and threads. `0` means unlimited.

## Examples

### HTML to PDF

```nginx
location /hello {
    mupdf "<html><body><h1>Hello, world!</h1></body></html>";
}
```

### First page of a PDF as a PNG image, in a thread pool

```nginx
thread_pool mupdf threads=4;

http {
    server {
        location /preview {
            mupdf_thread_pool mupdf;
            mupdf_timeout     10s;
            mupdf_input_type  pdf;
            mupdf_output_type png;
            mupdf_options     resolution=96;
            mupdf_range       1;
            mupdf             $document; # a variable holding the PDF, set by another module
        }
    }
}
```

## Tests

The tests use [Test::Nginx](https://metacpan.org/pod/Test::Nginx::Socket) and the `nginx` binary found in `PATH`. They load the module from `/etc/nginx/modules/ngx_http_mupdf_module.so`, or from the path in `TEST_NGINX_MUPDF_MODULE`:

```sh
TEST_NGINX_MUPDF_MODULE=/path/to/objs/ngx_http_mupdf_module.so prove -r t/
```

## Security

The input document is whatever the `mupdf` value expands to. If it includes request data, e.g. `mupdf "<h1>Hello, $arg_name</h1>";`, a client can inject its own markup into the document. Escape such values or do not use them.

MuPDF opens the document from memory, so HTML input cannot load local files through `<img>`, `<link>` or `file://` URLs.

The whole input and output documents are held in memory for the duration of the request.
