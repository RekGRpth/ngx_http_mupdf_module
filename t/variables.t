# vi:filetype=
#
# Coverage for variables in mupdf_input_type, mupdf_output_type,
# mupdf_options and mupdf_range: a constant output type is resolved and
# checked when loading the configuration, one with variables per
# request, including the Content-Type.
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

plan tests => repeat_each() * 24;

no_shuffle();
run_tests();

__DATA__

=== TEST 1: mupdf_range from a variable
--- config
    location /test {
        mupdf_output_type text;
        mupdf_range $arg_page;
        mupdf "<p style='page-break-after:always'>one</p><p style='page-break-after:always'>two</p><p>three</p>";
    }
--- request
GET /test?page=2
--- error_code: 200
--- response_body_like eval
qr/\A\s*two\s*\z/
--- no_error_log
[error]


=== TEST 2: mupdf_output_type from a variable found in types
--- config
    location /test {
        mupdf_output_type $arg_format;
        mupdf "<h1>Hello, world!</h1>";
    }
--- request
GET /test?format=png
--- error_code: 200
--- response_headers
Content-Type: image/png
--- response_body_like eval
qr/^\x89PNG\r\n/


=== TEST 3: mupdf_output_type from a variable with a built-in type
--- config
    location /test {
        mupdf_output_type $arg_format;
        mupdf "<p>Hello</p>";
    }
--- request
GET /test?format=text
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body_like: Hello


=== TEST 4: mupdf_output_type from a variable is looked up in lowercase
--- config
    location /test {
        mupdf_output_type $arg_format;
        mupdf "<p>Hello</p>";
    }
--- request
GET /test?format=TEXT
--- error_code: 200
--- response_headers
Content-Type: text/plain


=== TEST 5: an unknown output type from a variable is not rejected at startup but fails the request
--- config
    location /test {
        mupdf_output_type $arg_format;
        mupdf "<p>Hello</p>";
    }
--- request
GET /test?format=nosuch
--- error_code: 500
--- error_log
unknown output document format: nosuch


=== TEST 6: mupdf_options from a variable
--- config
    location /test {
        mupdf_output_type png;
        mupdf_options $arg_options;
        mupdf "<h1>Hello, world!</h1>";
    }
--- request
GET /test?options=resolution=24
--- error_code: 200
--- response_body_like eval
qr/^\x89PNG\r\n/
--- no_error_log
[error]


=== TEST 7: mupdf_input_type from a variable
--- config
    location /test {
        mupdf_input_type $arg_type;
        mupdf_output_type text;
        mupdf "<p>Hello</p>";
    }
--- request
GET /test?type=xhtml
--- error_code: 200
--- response_body_like: Hello
--- no_error_log
[error]


=== TEST 8: a variable is inherited from the server level
--- config
    mupdf_output_type $arg_format;
    location /test {
        mupdf "<p>Hello</p>";
    }
--- request
GET /test?format=text
--- error_code: 200
--- response_headers
Content-Type: text/plain


=== TEST 9: mupdf_output_type from a variable in a thread pool
--- config
    location /test {
        mupdf_thread_pool mupdf;
        mupdf_output_type $arg_format;
        mupdf "<h1>Hello, world!</h1>";
    }
--- request
GET /test?format=png
--- error_code: 200
--- response_headers
Content-Type: image/png
--- no_error_log
[error]
