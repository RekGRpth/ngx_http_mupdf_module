# vi:filetype=
#
# Coverage for filter mode (mupdf; without arguments): converting static
# files, return and proxy_pass responses, with and without a thread
# pool, a body that arrives in many buffers, responses that are passed
# through unchanged, conversion errors, HEAD and subrequests.
#
# The module is loaded from /etc/nginx/modules unless
# TEST_NGINX_MUPDF_MODULE points to another build.

use lib 'lib';
use Test::Nginx::Socket;

my $module = $ENV{TEST_NGINX_MUPDF_MODULE} || '/etc/nginx/modules/ngx_http_mupdf_module.so';

add_block_preprocessor(sub {
    my $block = shift;
    # Test::Nginx does not include mime.types
    $block->set_value('http_config', "types { application/pdf pdf; text/html html; text/css css; }\n" . ($block->http_config // ''));
    $block->set_value('main_config', "load_module $module;\nthread_pool mupdf threads=2;\n" . ($block->main_config // ''));
});

our $big = join '', map { "<p>line $_</p>\n" } 1 .. 20000;

plan tests => repeat_each() * 57;

no_shuffle();
run_tests();

__DATA__

=== TEST 1: a static html file is converted to pdf
--- config
    location /doc/ {
        mupdf;
    }
--- user_files
>>> doc/a.html
<h1>Hello, world!</h1>
--- request
GET /doc/a.html
--- error_code: 200
--- response_headers
Content-Type: application/pdf
--- response_body_like: ^%PDF-
--- no_error_log
[error]
[alert]


=== TEST 2: a return response is converted
--- config
    location /test {
        default_type text/html;
        mupdf_output_type text;
        mupdf;
        return 200 "<p>Hello, world!</p>";
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body_like eval
qr/\AHello, world!\s*\z/
--- no_error_log
[error]


=== TEST 3: a proxied response is converted
--- config
    location /backend {
        default_type text/html;
        return 200 "<p>Hello from backend</p>";
    }
    location /test {
        mupdf_output_type text;
        mupdf;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend;
    }
--- request
GET /test
--- error_code: 200
--- response_body_like eval
qr/\AHello from backend\s*\z/
--- no_error_log
[error]
[alert]


=== TEST 4: a proxied response is converted in a thread pool
--- config
    location /backend {
        default_type text/html;
        return 200 "<p>Hello from backend</p>";
    }
    location /test {
        mupdf_thread_pool mupdf;
        mupdf_output_type text;
        mupdf;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend;
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body_like eval
qr/\AHello from backend\s*\z/
--- no_error_log
[error]
[alert]


=== TEST 5: a static file is converted in a thread pool
--- config
    location /doc/ {
        mupdf_thread_pool mupdf;
        mupdf;
    }
--- user_files
>>> doc/a.html
<h1>Hello, world!</h1>
--- request
GET /doc/a.html
--- error_code: 200
--- response_headers
Content-Type: application/pdf
--- response_body_like: ^%PDF-
--- no_error_log
[error]
[alert]


=== TEST 6: a large file arriving in many buffers is converted as a whole
--- config
    location /doc/ {
        output_buffers 1 4k;
        mupdf_output_type text;
        mupdf;
    }
--- user_files eval
">>> doc/big.html\n$::big"
--- request
GET /doc/big.html
--- error_code: 200
--- response_body_like eval
qr/\Aline 1\n.*\nline 10000\n.*\nline 20000\s*\z/s
--- no_error_log
[error]
--- timeout: 60


=== TEST 7: a large proxied response in a thread pool
--- config
    location /backend {
        output_buffers 1 4k;
    }
    location /test {
        mupdf_thread_pool mupdf;
        mupdf_output_type text;
        mupdf;
        proxy_buffer_size 4k;
        proxy_buffers 4 4k;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/big.html;
    }
--- user_files eval
">>> backend/big.html\n$::big"
--- request
GET /test
--- error_code: 200
--- response_body_like eval
qr/\Aline 1\n.*\nline 20000\s*\z/s
--- no_error_log
[error]
[alert]
--- timeout: 60


=== TEST 8: a response that mupdf cannot read is passed through
--- config
    location /doc/ {
        mupdf;
    }
--- user_files
>>> doc/a.css
body { color: red; }
--- request
GET /doc/a.css
--- error_code: 200
--- response_headers
Content-Type: text/css
--- response_body
body { color: red; }
--- no_error_log
[error]


=== TEST 9: an error response is passed through
--- config
    location /doc/ {
        mupdf;
    }
--- request
GET /doc/nosuch.html
--- error_code: 404
--- response_headers
Content-Type: text/html
--- response_body_like: 404 Not Found


=== TEST 10: mupdf_input_type converts a response of any type
--- config
    location /test {
        default_type application/octet-stream;
        mupdf_input_type html;
        mupdf_output_type text;
        mupdf;
        return 200 "<p>Hello, world!</p>";
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body_like eval
qr/\AHello, world!\s*\z/


=== TEST 11: a conversion error is a 500 response
--- config
    location /test {
        default_type text/html;
        mupdf_input_type pdf;
        mupdf;
        return 200 "<p>not a pdf</p>";
    }
--- request
GET /test
--- error_code: 500
--- response_body_like: 500 Internal Server Error
--- error_log
[error]
--- no_error_log
[alert]


=== TEST 12: a conversion error in a thread pool is a 500 response
--- config
    location /backend {
        default_type text/html;
        return 200 "<p>not a pdf</p>";
    }
    location /test {
        mupdf_thread_pool mupdf;
        mupdf_input_type pdf;
        mupdf;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend;
    }
--- request
GET /test
--- error_code: 500
--- response_body_like: 500 Internal Server Error
--- no_error_log
[alert]


=== TEST 13: HEAD gets the converted type without a length
--- config
    location /doc/ {
        mupdf;
    }
--- user_files
>>> doc/a.html
<h1>Hello, world!</h1>
--- request
HEAD /doc/a.html
--- error_code: 200
--- response_headers
Content-Type: application/pdf
Content-Length:
--- response_body


=== TEST 14: a subrequest response is converted
--- config
    location /sub {
        default_type text/html;
        mupdf_output_type text;
        mupdf;
        return 200 "<p>hi</p>";
    }
    location /test {
        ssi on;
        ssi_types *;
        default_type text/plain;
        return 200 'A<!--# include virtual="/sub" -->B';
    }
--- request
GET /test
--- error_code: 200
--- response_body_like eval
qr/\AA\s*hi\s*B\z/
--- no_error_log
[error]
[alert]


=== TEST 15: mupdf with and without text in the same location is a duplicate
--- config
    location /test {
        mupdf;
        mupdf "<p>Hello</p>";
    }
--- request
GET /test
--- must_die
--- error_log
is duplicate
