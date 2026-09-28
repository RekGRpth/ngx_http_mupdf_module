# vi:filetype=
#
# Coverage for the request path without a thread pool: conversion to
# several output formats, Content-Type from mupdf_output_type, allowed
# methods, page ranges, empty output, subrequests and mupdf errors.
#
# The module is loaded from /etc/nginx/modules unless
# TEST_NGINX_MUPDF_MODULE points to another build.

use lib 'lib';
use Test::Nginx::Socket;

my $module = $ENV{TEST_NGINX_MUPDF_MODULE} || '/etc/nginx/modules/ngx_http_mupdf_module.so';

add_block_preprocessor(sub {
    my $block = shift;
    # Test::Nginx does not include mime.types
    $block->set_value('http_config', "types { application/pdf pdf; image/png png; }\n" . ($block->http_config // ''));
    $block->set_value('main_config', "load_module $module;\n" . ($block->main_config // ''));
});

plan tests => repeat_each() * 41;

no_shuffle();
run_tests();

__DATA__

=== TEST 1: html is converted to pdf by default
--- config
    location /test {
        mupdf "<h1>Hello, world!</h1>";
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: application/pdf
--- response_body_like: ^%PDF-
--- no_error_log
[error]
[alert]


=== TEST 2: the input is a complex value
--- config
    location /test {
        mupdf_output_type text;
        mupdf "<p>Hello, $arg_name!</p>";
    }
--- request
GET /test?name=world
--- error_code: 200
--- response_body_like eval
qr/\AHello, world!\s*\z/
--- no_error_log
[error]


=== TEST 3: HEAD sends the headers of the converted document without a body
--- config
    location /test {
        mupdf "<h1>Hello, world!</h1>";
    }
--- request
HEAD /test
--- error_code: 200
--- response_headers
Content-Type: application/pdf
--- response_headers_like
Content-Length: [1-9][0-9]*
--- response_body
--- no_error_log
[error]


=== TEST 4: other methods are not allowed
--- config
    location /test {
        mupdf "<h1>Hello, world!</h1>";
    }
--- request
POST /test
body
--- error_code: 405
--- no_error_log
[error]


=== TEST 5: png output gets the image/png content type
--- config
    location /test {
        mupdf_output_type png;
        mupdf_options resolution=48;
        mupdf "<h1>Hello, world!</h1>";
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: image/png
--- response_body_like eval
qr/^\x89PNG\r\n/
--- no_error_log
[error]


=== TEST 6: an output type missing from mime.types gets a built-in type
--- config
    location /test {
        mupdf_output_type text;
        mupdf "<p>Hello</p>";
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: text/plain


=== TEST 7: types takes precedence over the built-in type
--- config
    location /test {
        types { text/x-test text; }
        mupdf_output_type text;
        mupdf "<p>Hello</p>";
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: text/x-test


=== TEST 8: an output type without a known type falls back to default_type
--- config
    location /test {
        default_type application/x-test;
        mupdf_output_type pkm;
        mupdf "<p>Hello</p>";
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: application/x-test


=== TEST 9: mupdf_range selects and orders pages
--- config
    location /test {
        mupdf_output_type text;
        mupdf_range "3,1";
        mupdf "<p style='page-break-after:always'>one</p><p style='page-break-after:always'>two</p><p>three</p>";
    }
--- request
GET /test
--- error_code: 200
--- response_body_like eval
qr/\A\s*three\s+one\s*\z/
--- no_error_log
[error]


=== TEST 10: empty output of a successful conversion is an empty 200 response
--- config
    location /test {
        mupdf_output_type text;
        mupdf "<div></div>";
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Length: 0
--- response_body
--- no_error_log
[error]
[alert]


=== TEST 11: subrequests, including an empty one
--- config
    location /empty {
        mupdf_output_type text;
        mupdf "<div></div>";
    }
    location /text {
        mupdf_output_type text;
        mupdf "<p>hi</p>";
    }
    location /test {
        ssi on;
        ssi_types *;
        default_type text/plain;
        return 200 'A<!--# include virtual="/empty" -->B<!--# include virtual="/text" -->C';
    }
--- request
GET /test
--- error_code: 200
--- response_body_like eval
qr/\AAB\s*hi\s*C\z/
--- no_error_log
[error]
[alert]


=== TEST 12: an unknown input type is a request error
--- config
    location /test {
        mupdf_input_type nosuch;
        mupdf "<p>Hello</p>";
    }
--- request
GET /test
--- error_code: 500
--- error_log
cannot find document handler for file type: 'nosuch'


=== TEST 13: mupdf messages are not used as a format string
--- config
    location /test {
        mupdf_input_type "%s%s%s%V%n";
        mupdf "<p>Hello</p>";
    }
--- request
GET /test
--- error_code: 500
--- error_log
cannot find document handler for file type: '%s%s%s%V%n'
--- no_error_log
[alert]
