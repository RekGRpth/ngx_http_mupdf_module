# vi:filetype=
#
# Coverage for config-time behavior: directive contexts, duplicate and
# unknown thread pools, mupdf_store_size values, and a loaded module
# that no location uses.
#
# The module is loaded from /etc/nginx/modules unless
# TEST_NGINX_MUPDF_MODULE points to another build.

use lib 'lib';
use Test::Nginx::Socket;

my $module = $ENV{TEST_NGINX_MUPDF_MODULE} || '/etc/nginx/modules/ngx_http_mupdf_module.so';

add_block_preprocessor(sub {
    my $block = shift;
    $block->set_value('main_config', "load_module $module;\n" . ($block->main_config // ''));
});

plan tests => repeat_each() * 18;

no_shuffle();
run_tests();

__DATA__

=== TEST 1: mupdf is only allowed in a location
--- http_config
    mupdf "<p>Hello</p>";
--- config
--- request
GET /
--- must_die
--- error_log
"mupdf" directive is not allowed here


=== TEST 2: mupdf_store_size is only allowed in http
--- config
    location /test {
        mupdf_store_size 1m;
        mupdf "<p>Hello</p>";
    }
--- request
GET /test
--- must_die
--- error_log
"mupdf_store_size" directive is not allowed here


=== TEST 3: a second mupdf_thread_pool in the same location is rejected as a duplicate
--- config
    location /test {
        mupdf_thread_pool default;
        mupdf_thread_pool default;
        mupdf "<p>Hello</p>";
    }
--- request
GET /test
--- must_die
--- error_log
is duplicate


=== TEST 4: an undefined thread pool is rejected
--- config
    location /test {
        mupdf_thread_pool nosuch;
        mupdf "<p>Hello</p>";
    }
--- request
GET /test
--- must_die
--- error_log
unknown thread pool "nosuch"


=== TEST 5: a limited store
--- http_config
    mupdf_store_size 1m;
--- config
    location /test {
        mupdf "<h1>Hello, world!</h1>";
    }
--- request
GET /test
--- error_code: 200
--- response_body_like: ^%PDF-
--- no_error_log
[error]


=== TEST 6: an unlimited store
--- http_config
    mupdf_store_size 0;
--- config
    location /test {
        mupdf "<h1>Hello, world!</h1>";
    }
--- request
GET /test
--- error_code: 200
--- response_body_like: ^%PDF-
--- no_error_log
[error]


=== TEST 7: a loaded module that no location uses does not get in the way
--- config
    location /test {
        return 200 "ok";
    }
--- request
GET /test
--- error_code: 200
--- response_body chomp
ok
--- no_error_log
[error]
[alert]
