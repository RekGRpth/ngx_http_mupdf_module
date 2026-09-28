# vi:filetype=
#
# Coverage for mupdf_thread_pool and mupdf_timeout: conversions in a
# thread pool (named, default and switched off), errors and empty output
# from a thread, and the timeout with and without a thread pool.
#
# The timeout tests use a document of a few thousand pages, built from a
# variable because a single configuration token is limited in size, so
# that the conversion cannot finish within 1ms.
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
    $block->set_value('main_config', "load_module $module;\nthread_pool mupdf threads=2;\n" . ($block->main_config // ''));
});

our $pages = "<p style='page-break-after:always'>page</p>" x 90;
our $document = '$pages' x 30;

plan tests => repeat_each() * 28;

no_shuffle();
run_tests();

__DATA__

=== TEST 1: conversion in a named thread pool
--- config
    location /test {
        mupdf_thread_pool mupdf;
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


=== TEST 2: the default thread pool needs no thread_pool directive
--- config
    location /test {
        mupdf_thread_pool default;
        mupdf "<h1>Hello, world!</h1>";
    }
--- request
GET /test
--- error_code: 200
--- response_body_like: ^%PDF-
--- no_error_log
[error]


=== TEST 3: mupdf_thread_pool is inherited and can be switched off
--- config
    mupdf_thread_pool mupdf;
    location /test {
        mupdf_thread_pool off;
        mupdf "<h1>Hello, world!</h1>";
    }
--- request
GET /test
--- error_code: 200
--- response_body_like: ^%PDF-
--- no_error_log
[error]


=== TEST 4: HEAD in a thread pool
--- config
    location /test {
        mupdf_thread_pool mupdf;
        mupdf "<h1>Hello, world!</h1>";
    }
--- request
HEAD /test
--- error_code: 200
--- response_headers_like
Content-Length: [1-9][0-9]*
--- response_body


=== TEST 5: empty output in a thread pool
--- config
    location /test {
        mupdf_thread_pool mupdf;
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
[alert]


=== TEST 6: a conversion error in a thread pool
--- config
    location /test {
        mupdf_thread_pool mupdf;
        mupdf_output_type nosuch;
        mupdf "<p>Hello</p>";
    }
--- request
GET /test
--- error_code: 500
--- error_log
unknown output document format: nosuch


=== TEST 7: mupdf_timeout without a thread pool
--- config eval
"location /test {
    set \$pages \"$::pages\";
    mupdf_timeout 1ms;
    mupdf \"$::document\";
}"
--- request
GET /test
--- error_code: 500
--- error_log
mupdf_timeout 1 ms exceeded


=== TEST 8: mupdf_timeout in a thread pool
--- config eval
"location /test {
    set \$pages \"$::pages\";
    mupdf_thread_pool mupdf;
    mupdf_timeout 1ms;
    mupdf \"$::document\";
}"
--- request
GET /test
--- error_code: 500
--- error_log
mupdf_timeout 1 ms exceeded
--- no_error_log
[alert]


=== TEST 9: a conversion within mupdf_timeout succeeds
--- config eval
"location /test {
    set \$pages \"$::pages\";
    mupdf_thread_pool mupdf;
    mupdf_timeout 60s;
    mupdf \"$::document\";
}"
--- request
GET /test
--- error_code: 200
--- response_body_like: ^%PDF-
--- no_error_log
[error]
--- timeout: 60
