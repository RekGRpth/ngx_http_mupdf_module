#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <mupdf/fitz.h>

typedef struct {
    fz_context *ctx;
    ngx_flag_t enable;
    ngx_flag_t filter;
    size_t store_size;
} ngx_http_mupdf_main_conf_t;

typedef struct {
    ngx_http_complex_value_t *input_data;
    ngx_http_complex_value_t *input_type;
    ngx_http_complex_value_t *output_type;
    ngx_http_complex_value_t *options;
    ngx_http_complex_value_t *range;
    // precomputed for a constant output type
    ngx_str_t exten;
    ngx_uint_t exten_hash;
    ngx_str_t content_type;
    ngx_msec_t timeout;
    ngx_uint_t filter;
#if (NGX_THREADS)
    ngx_thread_pool_t *thread_pool;
#endif
} ngx_http_mupdf_loc_conf_t;

#define NGX_HTTP_MUPDF_MESSAGES 64

typedef struct ngx_http_mupdf_message_s ngx_http_mupdf_message_t;

struct ngx_http_mupdf_message_s {
    ngx_http_mupdf_message_t *next;
    ngx_uint_t level;
    size_t len;
    u_char data[];
};

typedef struct {
    fz_context *ctx;
    ngx_log_t *log;
    char *input_type;
    char *output_type;
    char *options;
    char *range;
    ngx_str_t input_data;
    u_char *output_data;
    size_t output_len;
    unsigned done:1;
    fz_cookie cookie;
    ngx_msec_t start;
    ngx_msec_t timeout;
#if (NGX_THREADS)
    ngx_event_t timer;
    unsigned thread:1;
    ngx_http_mupdf_message_t *messages;
    ngx_http_mupdf_message_t **last;
    ngx_uint_t nmessages;
#endif
} ngx_http_mupdf_task_t;

// the image filter uses the same bit, both filters cannot convert the same response
#define NGX_HTTP_MUPDF_BUFFERED 0x08

enum {
    NGX_HTTP_MUPDF_READ = 0,
    NGX_HTTP_MUPDF_CONVERT,
    NGX_HTTP_MUPDF_PASS
};

typedef struct {
    ngx_http_mupdf_task_t *t;
#if (NGX_THREADS)
    ngx_thread_task_t *task;
#endif
    // filter mode: the response body and the input type from its Content-Type
    u_char *data;
    size_t len;
    size_t size;
    char *input_type;
    ngx_uint_t state;
    unsigned filter:1;
} ngx_http_mupdf_ctx_t;

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

typedef struct {
    ngx_str_t format;
    ngx_str_t type;
} ngx_http_mupdf_type_t;

// mupdf output formats missing from the standard mime.types
static ngx_http_mupdf_type_t ngx_http_mupdf_types[] = {
    { ngx_string("cbz"), ngx_string("application/vnd.comicbook+zip") },
    { ngx_string("csv"), ngx_string("text/csv") },
    { ngx_string("ocr"), ngx_string("application/pdf") },
    { ngx_string("pam"), ngx_string("image/x-portable-arbitrarymap") },
    { ngx_string("pbm"), ngx_string("image/x-portable-bitmap") },
    { ngx_string("pcl"), ngx_string("application/vnd.hp-pcl") },
    { ngx_string("pgm"), ngx_string("image/x-portable-graymap") },
    { ngx_string("pnm"), ngx_string("image/x-portable-anymap") },
    { ngx_string("ppm"), ngx_string("image/x-portable-pixmap") },
    { ngx_string("pwg"), ngx_string("image/pwg-raster") },
    { ngx_string("stext"), ngx_string("text/xml") },
    { ngx_string("stext.json"), ngx_string("application/json") },
    { ngx_string("text"), ngx_string("text/plain") },
    { ngx_null_string, ngx_null_string }
};

static ngx_http_complex_value_t ngx_http_mupdf_default_input_type = { .value = ngx_string("html") };
static ngx_http_complex_value_t ngx_http_mupdf_default_output_type = { .value = ngx_string("pdf") };
static ngx_http_complex_value_t ngx_http_mupdf_default_options = { .value = ngx_string("") };
static ngx_http_complex_value_t ngx_http_mupdf_default_range = { .value = ngx_string("1-N") };

// lowercase the output type into exten and find its built-in content type
static ngx_uint_t ngx_http_mupdf_exten(ngx_str_t *output_type, ngx_str_t *exten, ngx_str_t *content_type) {
    exten->len = output_type->len;
    ngx_uint_t hash = ngx_hash_strlow(exten->data, output_type->data, output_type->len);
    ngx_str_null(content_type);
    for (ngx_http_mupdf_type_t *type = ngx_http_mupdf_types; type->format.len; type++) if (type->format.len == exten->len && !ngx_strncmp(type->format.data, exten->data, exten->len)) { *content_type = type->type; break; }
    return hash;
}

ngx_module_t ngx_http_mupdf_module;

#if (NGX_THREADS)
static ngx_thread_mutex_t ngx_http_mupdf_mutex[FZ_LOCK_MAX];

static void ngx_http_mupdf_lock(void *user, int lock) {
    ngx_thread_mutex_lock(&ngx_http_mupdf_mutex[lock], ngx_cycle->log);
}

static void ngx_http_mupdf_unlock(void *user, int lock) {
    ngx_thread_mutex_unlock(&ngx_http_mupdf_mutex[lock], ngx_cycle->log);
}
#else
// fz_clone_context() refuses a context without lock functions, a worker without threads needs no real locking
static void ngx_http_mupdf_lock(void *user, int lock) { }

static void ngx_http_mupdf_unlock(void *user, int lock) { }
#endif

static void pg_mupdf_error_callback(void *user, const char *message) {
    ngx_log_t *log = user;
    ngx_log_error(NGX_LOG_ERR, log, 0, "%s", message);
}

static void pg_mupdf_warning_callback(void *user, const char *message) {
    ngx_log_t *log = user;
    ngx_log_error(NGX_LOG_WARN, log, 0, "%s", message);
}

static void ngx_http_mupdf_message(ngx_http_mupdf_task_t *t, ngx_uint_t level, const char *message) {
#if (NGX_THREADS)
    // a thread must not use the request log: keep the messages and log them when the conversion is done
    if (t->thread) {
        if (t->nmessages++ >= NGX_HTTP_MUPDF_MESSAGES) return;
        size_t len = ngx_strlen(message);
        ngx_http_mupdf_message_t *m = ngx_alloc(sizeof(*m) + len, t->log);
        if (!m) return;
        m->next = NULL;
        m->level = level;
        m->len = len;
        ngx_memcpy(m->data, message, len);
        *t->last = m;
        t->last = &m->next;
        return;
    }
#endif
    ngx_log_error(level, t->log, 0, "%s", message);
}

static void ngx_http_mupdf_error_callback(void *user, const char *message) {
    ngx_http_mupdf_message(user, NGX_LOG_ERR, message);
}

static void ngx_http_mupdf_warning_callback(void *user, const char *message) {
    ngx_http_mupdf_message(user, NGX_LOG_WARN, message);
}

// monotonic and callable from a thread, unlike ngx_current_msec
static ngx_msec_t ngx_http_mupdf_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ngx_msec_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// mupdf can only be interrupted between pages, and inside a page only for formats that honour cookie->abort (e.g. pdf, not html)
static void ngx_http_mupdf_check_timeout(fz_context *ctx, ngx_http_mupdf_task_t *t) {
    if (!t->timeout) return;
    if (!t->cookie.abort && ngx_http_mupdf_now() - t->start < t->timeout) return;
    t->cookie.abort = 1;
    fz_throw(ctx, FZ_ERROR_LIMIT, "mupdf_timeout %lu ms exceeded", (unsigned long) t->timeout);
}

static void runpage(fz_context *ctx, fz_document *doc, int number, fz_document_writer *wri, fz_cookie *cookie) {
    fz_page *page = fz_load_page(ctx, doc, number - 1);
    fz_try(ctx) {
        fz_rect mediabox = fz_bound_page(ctx, page);
        fz_device *dev = fz_begin_page(ctx, wri, mediabox);
        fz_run_page(ctx, page, dev, fz_identity, cookie);
        fz_end_page(ctx, wri);
    } fz_always(ctx) {
        fz_drop_page(ctx, page);
    } fz_catch(ctx) {
        fz_rethrow(ctx);
    }
}

static void runrange(fz_context *ctx, fz_document *doc, const char *range, fz_document_writer *wri, ngx_http_mupdf_task_t *t) {
    int start, end, count = fz_count_pages(ctx, doc);
    while ((range = fz_parse_page_range(ctx, range, &start, &end, count))) {
        if (start < end) {
            for (int i = start; i <= end; i++) {
                ngx_http_mupdf_check_timeout(ctx, t);
                runpage(ctx, doc, i, wri, &t->cookie);
            }
        } else {
            for (int i = start; i >= end; i--) {
                ngx_http_mupdf_check_timeout(ctx, t);
                runpage(ctx, doc, i, wri, &t->cookie);
            }
        }
    }
    // an aborted page is silently cut short: fail instead of returning a truncated document
    ngx_http_mupdf_check_timeout(ctx, t);
}

// runs in a thread pool thread when mupdf_thread_pool is set: must not touch the request or its pool
static void ngx_http_mupdf_convert(ngx_http_mupdf_task_t *t, ngx_log_t *log) {
    t->log = log;
    fz_context *ctx = fz_clone_context(t->ctx);
    if (!ctx) { ngx_log_error(NGX_LOG_ERR, log, 0, "!fz_clone_context"); return; }
    fz_set_error_callback(ctx, ngx_http_mupdf_error_callback, t);
    fz_set_warning_callback(ctx, ngx_http_mupdf_warning_callback, t);
    fz_stream *stm = NULL; fz_var(stm);
    fz_buffer *obuf = NULL; fz_var(obuf);
    fz_document *doc = NULL; fz_var(doc);
    fz_document_writer *wri = NULL; fz_var(wri);
    fz_try(ctx) {
        obuf = fz_new_buffer(ctx, 0);
        stm = fz_open_memory(ctx, (unsigned char *)t->input_data.data, t->input_data.len);
        doc = fz_open_document_with_stream(ctx, t->input_type, stm);
        wri = fz_new_document_writer_with_buffer(ctx, obuf, t->output_type, t->options);
        runrange(ctx, doc, t->range, wri, t);
        fz_close_document_writer(ctx, wri);
    } fz_always(ctx) {
        if (wri) fz_drop_document_writer(ctx, wri);
        if (doc) fz_drop_document(ctx, doc);
        if (stm) fz_drop_stream(ctx, stm);
    } fz_catch(ctx) {
        fz_report_error(ctx);
        goto fz_drop_context;
    }
    // take the data without a copy, it is freed with fz_free() in the request pool cleanup; empty output is valid, e.g. text of a document without text
    t->output_len = fz_buffer_extract(ctx, obuf, &t->output_data);
    t->done = 1;
fz_drop_context:
    if (obuf) fz_drop_buffer(ctx, obuf);
    fz_drop_context(ctx);
}

static void ngx_http_mupdf_cleanup(void *data) {
    ngx_http_mupdf_task_t *t = data;
#if (NGX_THREADS)
    if (t->timer.timer_set) ngx_del_timer(&t->timer);
    for (ngx_http_mupdf_message_t *m = t->messages, *next; m; m = next) { next = m->next; ngx_free(m); }
#endif
    // the clone that allocated it shares the allocator with the worker context
    fz_free(t->ctx, t->output_data);
}

#if (NGX_THREADS)
static void ngx_http_mupdf_thread_handler(void *data, ngx_log_t *log) {
    ngx_http_mupdf_convert(data, log);
}

static void ngx_http_mupdf_log_messages(ngx_http_mupdf_task_t *t, ngx_log_t *log) {
    for (ngx_http_mupdf_message_t *m = t->messages, *next; m; m = next) {
        next = m->next;
        ngx_log_error(m->level, log, 0, "%*s", m->len, m->data);
        ngx_free(m);
    }
    t->messages = NULL;
    t->last = &t->messages;
    if (t->nmessages > NGX_HTTP_MUPDF_MESSAGES) ngx_log_error(NGX_LOG_WARN, log, 0, "%ui more mupdf messages dropped", t->nmessages - NGX_HTTP_MUPDF_MESSAGES);
}

static void ngx_http_mupdf_timer_handler(ngx_event_t *ev) {
    ngx_http_mupdf_task_t *t = ev->data;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "ngx_http_mupdf_timer_handler");
    t->cookie.abort = 1;
}

#endif

// like ngx_http_set_content_type() for the output type as an extension, with the mupdf formats missing from mime.types before default_type
static ngx_int_t ngx_http_mupdf_set_content_type(ngx_http_request_t *r, char *output_type) {
    ngx_http_mupdf_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_mupdf_module);
    ngx_http_core_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    ngx_str_t exten = conf->exten, content_type = conf->content_type;
    ngx_uint_t hash = conf->exten_hash;
    if (conf->output_type->lengths) {
        ngx_str_t value = { ngx_strlen(output_type), (u_char *) output_type };
        if (!(exten.data = ngx_pnalloc(r->pool, value.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        hash = ngx_http_mupdf_exten(&value, &exten, &content_type);
    }
    ngx_str_t *type = ngx_hash_find(&clcf->types_hash, hash, exten.data, exten.len);
    if (!type) type = content_type.len ? &content_type : &clcf->default_type;
    // in filter mode this replaces the type of the converted response
    r->headers_out.content_type_len = type->len;
    r->headers_out.content_type = *type;
    r->headers_out.content_type_lowcase = NULL;
    ngx_str_null(&r->headers_out.charset);
    return NGX_OK;
}

static ngx_int_t ngx_http_mupdf_set_headers(ngx_http_request_t *r, ngx_http_mupdf_task_t *t) {
    r->headers_out.content_length_n = t->output_len;
    return ngx_http_mupdf_set_content_type(r, t->output_type);
}

static ngx_int_t ngx_http_mupdf_body(ngx_http_request_t *r, ngx_http_mupdf_task_t *t, ngx_chain_t *cl) {
    ngx_buf_t *buf = ngx_calloc_buf(r->pool);
    if (!buf) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!buf"); return NGX_ERROR; }
    if (t->output_len) {
        buf->pos = t->output_data;
        buf->last = t->output_data + t->output_len;
        buf->memory = 1;
    }
    buf->last_buf = (r == r->main) ? 1 : 0;
    buf->last_in_chain = 1;
    // an empty buffer must be special
    if (!t->output_len && r != r->main) buf->sync = 1;
    cl->buf = buf;
    cl->next = NULL;
    return NGX_OK;
}

static ngx_int_t ngx_http_mupdf_send(ngx_http_request_t *r, ngx_http_mupdf_task_t *t) {
    if (!t->done) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    r->headers_out.status = NGX_HTTP_OK;
    if (ngx_http_mupdf_set_headers(r, t) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    ngx_int_t rc = ngx_http_send_header(r);
//    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rc = %i", rc);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) return rc;
    ngx_chain_t cl;
    if (ngx_http_mupdf_body(r, t, &cl) != NGX_OK) return NGX_ERROR;
    return ngx_http_output_filter(r, &cl);
}

// filter mode: send the headers held back by the header filter and the converted response
static ngx_int_t ngx_http_mupdf_filter_send(ngx_http_request_t *r, ngx_http_mupdf_ctx_t *ctx) {
    ngx_http_mupdf_task_t *t = ctx->t;
    ctx->state = NGX_HTTP_MUPDF_PASS;
    r->buffered &= ~NGX_HTTP_MUPDF_BUFFERED;
    if (!t->done || ngx_http_mupdf_set_headers(r, t) != NGX_OK) return ngx_http_filter_finalize_request(r, &ngx_http_mupdf_module, NGX_HTTP_INTERNAL_SERVER_ERROR);
    ngx_int_t rc = ngx_http_next_header_filter(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) return rc;
    ngx_chain_t cl;
    if (ngx_http_mupdf_body(r, t, &cl) != NGX_OK) return NGX_ERROR;
    return ngx_http_next_body_filter(r, &cl);
}

static char *ngx_http_mupdf_str(ngx_pool_t *pool, ngx_str_t *str) {
    char *s = ngx_pcalloc(pool, str->len + 1);
    if (s) ngx_memcpy(s, str->data, str->len);
    return s;
}

static char *ngx_http_mupdf_value(ngx_http_request_t *r, ngx_http_complex_value_t *cv) {
    ngx_str_t value;
    if (ngx_http_complex_value(r, cv, &value) != NGX_OK) return NULL;
    return ngx_http_mupdf_str(r->pool, &value);
}

// the conversion settings of the location, the caller sets the input
static ngx_http_mupdf_ctx_t *ngx_http_mupdf_ctx(ngx_http_request_t *r) {
    ngx_http_mupdf_main_conf_t *mcf = ngx_http_get_module_main_conf(r, ngx_http_mupdf_module);
    if (!mcf->ctx) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!mcf->ctx"); return NULL; }
    ngx_http_mupdf_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_mupdf_module);
    ngx_http_mupdf_ctx_t *ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
    if (!ctx) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NULL; }
    ngx_http_mupdf_task_t *t;
#if (NGX_THREADS)
    if (conf->thread_pool) {
        if (!(ctx->task = ngx_thread_task_alloc(r->pool, sizeof(*t)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_thread_task_alloc"); return NULL; }
        t = ctx->task->ctx;
    } else
#endif
    if (!(t = ngx_pcalloc(r->pool, sizeof(*t)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NULL; }
    ctx->t = t;
    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(r->pool, 0);
    if (!cln) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pool_cleanup_add"); return NULL; }
    cln->handler = ngx_http_mupdf_cleanup;
    cln->data = t;
    t->ctx = mcf->ctx;
    t->start = ngx_http_mupdf_now();
    t->timeout = conf->timeout;
    if (!(t->output_type = ngx_http_mupdf_value(r, conf->output_type))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!output_type"); return NULL; }
    if (!(t->options = ngx_http_mupdf_value(r, conf->options))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!options"); return NULL; }
    if (!(t->range = ngx_http_mupdf_value(r, conf->range))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!range"); return NULL; }
    ngx_http_set_ctx(r, ctx, ngx_http_mupdf_module);
    return ctx;
}

// convert in the worker, or post the conversion to the thread pool and return NGX_AGAIN
static ngx_int_t ngx_http_mupdf_run(ngx_http_request_t *r, ngx_http_mupdf_ctx_t *ctx, ngx_event_handler_pt handler) {
    ngx_http_mupdf_task_t *t = ctx->t;
    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "input_data = %V, input_type = %s, output_type = %s, range = %s, options = %s", &t->input_data, t->input_type, t->output_type, t->range, t->options);
#if (NGX_THREADS)
    ngx_thread_task_t *task = ctx->task;
    if (task) {
        ngx_http_mupdf_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_mupdf_module);
        t->thread = 1;
        t->last = &t->messages;
        task->handler = ngx_http_mupdf_thread_handler;
        task->event.data = r;
        task->event.handler = handler;
        if (ngx_thread_task_post(conf->thread_pool, task) != NGX_OK) return NGX_ERROR;
        if (t->timeout) {
            t->timer.handler = ngx_http_mupdf_timer_handler;
            t->timer.data = t;
            t->timer.log = r->connection->log;
            ngx_add_timer(&t->timer, t->timeout);
        }
        r->main->blocked++;
        r->aio = 1;
        return NGX_AGAIN;
    }
#endif
    ngx_http_mupdf_convert(t, r->connection->log);
    return NGX_OK;
}

#if (NGX_THREADS)
// back in the worker after a conversion in the thread pool
static ngx_http_mupdf_ctx_t *ngx_http_mupdf_thread_done(ngx_event_t *ev) {
    ngx_http_request_t *r = ev->data;
    ngx_connection_t *c = r->connection;
    ngx_http_set_log_request(c->log, r);
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "ngx_http_mupdf_thread_done");
    ngx_http_mupdf_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_mupdf_module);
    ngx_http_mupdf_task_t *t = ctx->t;
    if (t->timer.timer_set) ngx_del_timer(&t->timer);
    r->main->blocked--;
    r->aio = 0;
    ngx_http_mupdf_log_messages(t, c->log);
    // the request was terminated while converting: let the connection write handler close it
    if (r->main->terminated) { c->write->handler(c->write); return NULL; }
    return ctx;
}

static void ngx_http_mupdf_thread_event_handler(ngx_event_t *ev) {
    ngx_http_mupdf_ctx_t *ctx = ngx_http_mupdf_thread_done(ev);
    if (!ctx) return;
    ngx_http_request_t *r = ev->data;
    ngx_connection_t *c = r->connection;
    ngx_http_finalize_request(r, ngx_http_mupdf_send(r, ctx->t));
    ngx_http_run_posted_requests(c);
}

static void ngx_http_mupdf_filter_event_handler(ngx_event_t *ev) {
    ngx_http_request_t *r = ev->data;
    ngx_connection_t *c = r->connection;
#if (NGX_HTTP_V2)
    // like the copy filter: make sure the write reaches the main connection
    if (r->stream) {
        c->write->ready = 1;
        c->write->active = 0;
    }
#endif
    ngx_http_mupdf_ctx_t *ctx = ngx_http_mupdf_thread_done(ev);
    if (!ctx) return;
    // send the result here: the write event handler of the request does not necessarily call the body filter again
    if (ngx_http_mupdf_filter_send(r, ctx) == NGX_ERROR) {
        ngx_http_finalize_request(r, NGX_ERROR);
        ngx_http_run_posted_requests(c);
        return;
    }
    r->write_event_handler(r);
    ngx_http_run_posted_requests(c);
}
#endif

static ngx_int_t ngx_http_mupdf_handler(ngx_http_request_t *r) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_mupdf_handler");
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) return NGX_HTTP_NOT_ALLOWED;
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK && rc != NGX_AGAIN) return rc;
    ngx_http_mupdf_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_mupdf_module);
    ngx_http_mupdf_ctx_t *ctx = ngx_http_mupdf_ctx(r);
    if (!ctx) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    ngx_http_mupdf_task_t *t = ctx->t;
    if (!(t->input_type = ngx_http_mupdf_value(r, conf->input_type))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!input_type"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    if (ngx_http_complex_value(r, conf->input_data, &t->input_data) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
#if (NGX_THREADS)
    rc = ngx_http_mupdf_run(r, ctx, ngx_http_mupdf_thread_event_handler);
#else
    rc = ngx_http_mupdf_run(r, ctx, NULL);
#endif
    if (rc == NGX_ERROR) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (rc == NGX_AGAIN) {
        r->main->count++;
        return NGX_DONE;
    }
    return ngx_http_mupdf_send(r, t);
}

// the Content-Type of the response without parameters, if mupdf can read it
static char *ngx_http_mupdf_response_type(ngx_http_request_t *r, fz_context *ctx) {
    ngx_str_t type = r->headers_out.content_type;
    u_char *p = ngx_strlchr(type.data, type.data + type.len, ';');
    if (p) type.len = p - type.data;
    while (type.len && type.data[type.len - 1] == ' ') type.len--;
    if (!type.len) return NULL;
    char *input_type = ngx_http_mupdf_str(r->pool, &type);
    if (!input_type) return NULL;
    const fz_document_handler *handler = NULL; fz_var(handler);
    fz_try(ctx) {
        handler = fz_recognize_document(ctx, input_type);
    } fz_catch(ctx) {
        fz_report_error(ctx);
    }
    return handler ? input_type : NULL;
}

static ngx_int_t ngx_http_mupdf_header_filter(ngx_http_request_t *r) {
    ngx_http_mupdf_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_mupdf_module);
    // a request with a context is converted already, e.g. this is its error page
    if (!conf->filter || r->headers_out.status != NGX_HTTP_OK || ngx_http_get_module_ctx(r, ngx_http_mupdf_module)) return ngx_http_next_header_filter(r);
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_mupdf_header_filter");
    ngx_http_mupdf_main_conf_t *mcf = ngx_http_get_module_main_conf(r, ngx_http_mupdf_module);
    if (!mcf->ctx) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!mcf->ctx"); return ngx_http_filter_finalize_request(r, &ngx_http_mupdf_module, NGX_HTTP_INTERNAL_SERVER_ERROR); }
    char *input_type = NULL;
    // without mupdf_input_type only responses that mupdf can read are converted
    if (conf->input_type == &ngx_http_mupdf_default_input_type && !(input_type = ngx_http_mupdf_response_type(r, mcf->ctx))) return ngx_http_next_header_filter(r);
    off_t length = r->headers_out.content_length_n;
    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);
    ngx_http_clear_etag(r);
    // header_only is only set for HEAD by the last header filter
    if (r->header_only || r->method == NGX_HTTP_HEAD) {
        // there is no body to convert: send the type of the converted response
        char *output_type = ngx_http_mupdf_value(r, conf->output_type);
        if (!output_type) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!output_type"); return NGX_ERROR; }
        if (ngx_http_mupdf_set_content_type(r, output_type) != NGX_OK) return NGX_ERROR;
        return ngx_http_next_header_filter(r);
    }
    ngx_http_mupdf_ctx_t *ctx = ngx_http_mupdf_ctx(r);
    if (!ctx) return NGX_ERROR;
    ctx->filter = 1;
    ctx->input_type = input_type;
    if (length > 0) {
        if (!(ctx->data = ngx_pnalloc(r->pool, length))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        ctx->size = length;
    }
    // the headers are sent with the converted response
    r->filter_need_in_memory = 1;
    return NGX_OK;
}

static ngx_int_t ngx_http_mupdf_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
    ngx_http_mupdf_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_mupdf_module);
    if (!ctx || !ctx->filter || ctx->state == NGX_HTTP_MUPDF_PASS) return ngx_http_next_body_filter(r, in);
    if (ctx->state == NGX_HTTP_MUPDF_CONVERT) return NGX_AGAIN;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_mupdf_body_filter");
    ngx_uint_t last = 0;
    for (ngx_chain_t *cl = in; cl; cl = cl->next) {
        ngx_buf_t *b = cl->buf;
        if (b->last_buf || (r != r->main && b->last_in_chain)) last = 1;
        size_t size = ngx_buf_in_memory(b) ? (size_t) (b->last - b->pos) : 0;
        if (size) {
            if (ctx->len + size > ctx->size) {
                size_t n = ngx_max(ctx->size * 2, ctx->len + size);
                u_char *data = ngx_pnalloc(r->pool, n);
                if (!data) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                if (ctx->len) ngx_memcpy(data, ctx->data, ctx->len);
                if (ctx->data) ngx_pfree(r->pool, ctx->data);
                ctx->data = data;
                ctx->size = n;
            }
            ngx_memcpy(ctx->data + ctx->len, b->pos, size);
            ctx->len += size;
        }
        b->pos = b->last;
        if (b->in_file) b->file_pos = b->file_last;
    }
    if (!last) return NGX_OK;
    ngx_http_mupdf_task_t *t = ctx->t;
    t->input_data.data = ctx->data;
    t->input_data.len = ctx->len;
    if (!(t->input_type = ctx->input_type)) {
        ngx_http_mupdf_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_mupdf_module);
        if (!(t->input_type = ngx_http_mupdf_value(r, conf->input_type))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!input_type"); ctx->state = NGX_HTTP_MUPDF_PASS; return ngx_http_filter_finalize_request(r, &ngx_http_mupdf_module, NGX_HTTP_INTERNAL_SERVER_ERROR); }
    }
    ctx->state = NGX_HTTP_MUPDF_CONVERT;
#if (NGX_THREADS)
    ngx_int_t rc = ngx_http_mupdf_run(r, ctx, ngx_http_mupdf_filter_event_handler);
#else
    ngx_int_t rc = ngx_http_mupdf_run(r, ctx, NULL);
#endif
    if (rc == NGX_ERROR) { ctx->state = NGX_HTTP_MUPDF_PASS; return ngx_http_filter_finalize_request(r, &ngx_http_mupdf_module, NGX_HTTP_INTERNAL_SERVER_ERROR); }
    if (rc == NGX_AGAIN) {
        r->buffered |= NGX_HTTP_MUPDF_BUFFERED;
        return NGX_AGAIN;
    }
    return ngx_http_mupdf_filter_send(r, ctx);
}

// mupdf <text>; converts the text as the content handler, mupdf; converts the response of the location as a filter
static char *ngx_http_mupdf_convert_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_mupdf_loc_conf_t *mlcf = conf;
    if (mlcf->filter != NGX_CONF_UNSET_UINT) return "is duplicate";
    ngx_http_mupdf_main_conf_t *mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mupdf_module);
    mcf->enable = 1;
    if (cf->args->nelts == 1) {
        mlcf->filter = 1;
        mcf->filter = 1;
        return NGX_CONF_OK;
    }
    mlcf->filter = 0;
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_mupdf_handler;
    return ngx_http_set_complex_value_slot(cf, cmd, conf);
}

static char *ngx_http_mupdf_thread_pool_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
#if (NGX_THREADS)
    ngx_http_mupdf_loc_conf_t *mlcf = conf;
    if (mlcf->thread_pool != NGX_CONF_UNSET_PTR) return "is duplicate";
    ngx_str_t *value = cf->args->elts;
    if (value[1].len == sizeof("off") - 1 && !ngx_strncmp(value[1].data, "off", sizeof("off") - 1)) { mlcf->thread_pool = NULL; return NGX_CONF_OK; }
    if (!(mlcf->thread_pool = ngx_thread_pool_add(cf, &value[1]))) return NGX_CONF_ERROR;
    return NGX_CONF_OK;
#else
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" requires nginx built --with-threads", &cmd->name);
    return NGX_CONF_ERROR;
#endif
}

static ngx_command_t ngx_http_mupdf_commands[] = {
  { .name = ngx_string("mupdf_input_type"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_set_complex_value_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_mupdf_loc_conf_t, input_type),
    .post = NULL },
  { .name = ngx_string("mupdf_output_type"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_set_complex_value_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_mupdf_loc_conf_t, output_type),
    .post = NULL },
  { .name = ngx_string("mupdf_options"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_set_complex_value_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_mupdf_loc_conf_t, options),
    .post = NULL },
  { .name = ngx_string("mupdf_range"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_set_complex_value_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_mupdf_loc_conf_t, range),
    .post = NULL },
  { .name = ngx_string("mupdf_timeout"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_msec_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_mupdf_loc_conf_t, timeout),
    .post = NULL },
  { .name = ngx_string("mupdf_store_size"),
    .type = NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_size_slot,
    .conf = NGX_HTTP_MAIN_CONF_OFFSET,
    .offset = offsetof(ngx_http_mupdf_main_conf_t, store_size),
    .post = NULL },
  { .name = ngx_string("mupdf_thread_pool"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_mupdf_thread_pool_set,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("mupdf"),
    .type = NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
    .set = ngx_http_mupdf_convert_set,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_mupdf_loc_conf_t, input_data),
    .post = NULL },
    ngx_null_command
};

static void *ngx_http_mupdf_create_main_conf(ngx_conf_t *cf) {
    ngx_http_mupdf_main_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mupdf_main_conf_t));
    if (!conf) return NULL;
    conf->store_size = NGX_CONF_UNSET_SIZE;
    return conf;
}

static char *ngx_http_mupdf_init_main_conf(ngx_conf_t *cf, void *conf) {
    ngx_http_mupdf_main_conf_t *mcf = conf;
    ngx_conf_init_size_value(mcf->store_size, FZ_STORE_DEFAULT);
    return NGX_CONF_OK;
}

static void *ngx_http_mupdf_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_mupdf_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mupdf_loc_conf_t));
    if (!conf) return NULL;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->filter = NGX_CONF_UNSET_UINT;
#if (NGX_THREADS)
    conf->thread_pool = NGX_CONF_UNSET_PTR;
#endif
    return conf;
}

static void ngx_http_mupdf_quiet_callback(void *user, const char *message) { }

// reject an unknown output type or bad options when loading the configuration instead of failing every request
static char *ngx_http_mupdf_check_output(ngx_conf_t *cf, ngx_http_mupdf_loc_conf_t *conf) {
    char *output_type = ngx_http_mupdf_str(cf->temp_pool, &conf->output_type->value);
    char *options = ngx_http_mupdf_str(cf->temp_pool, &conf->options->value);
    if (!output_type || !options) return NGX_CONF_ERROR;
    fz_context *ctx = fz_new_context(NULL, NULL, FZ_STORE_DEFAULT);
    if (!ctx) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!fz_new_context"); return NGX_CONF_ERROR; }
    fz_set_error_callback(ctx, ngx_http_mupdf_quiet_callback, NULL);
    fz_set_warning_callback(ctx, ngx_http_mupdf_quiet_callback, NULL);
    char *rv = NGX_CONF_OK;
    fz_buffer *buf = NULL; fz_var(buf);
    fz_document_writer *wri = NULL; fz_var(wri);
    fz_try(ctx) {
        buf = fz_new_buffer(ctx, 0);
        wri = fz_new_document_writer_with_buffer(ctx, buf, output_type, options);
    } fz_always(ctx) {
        if (wri) fz_drop_document_writer(ctx, wri);
        if (buf) fz_drop_buffer(ctx, buf);
    } fz_catch(ctx) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mupdf: %s", fz_caught_message(ctx));
        fz_report_error(ctx);
        rv = NGX_CONF_ERROR;
    }
    fz_drop_context(ctx);
    return rv;
}

static char *ngx_http_mupdf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_mupdf_loc_conf_t *prev = parent;
    ngx_http_mupdf_loc_conf_t *conf = child;
    if (!conf->input_type) conf->input_type = prev->input_type ? prev->input_type : &ngx_http_mupdf_default_input_type;
    if (!conf->output_type) conf->output_type = prev->output_type ? prev->output_type : &ngx_http_mupdf_default_output_type;
    if (!conf->options) conf->options = prev->options ? prev->options : &ngx_http_mupdf_default_options;
    if (!conf->range) conf->range = prev->range ? prev->range : &ngx_http_mupdf_default_range;
    if (!conf->output_type->lengths) {
        if (!(conf->exten.data = ngx_pnalloc(cf->pool, conf->output_type->value.len))) return NGX_CONF_ERROR;
        conf->exten_hash = ngx_http_mupdf_exten(&conf->output_type->value, &conf->exten, &conf->content_type);
    }
    if (!conf->input_data) conf->input_data = prev->input_data;
    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 0);
    // a location with mupdf <text>; sets 0 and does not inherit the filter
    ngx_conf_merge_uint_value(conf->filter, prev->filter, 0);
#if (NGX_THREADS)
    ngx_conf_merge_ptr_value(conf->thread_pool, prev->thread_pool, NULL);
#endif
    // with variables the output type and options are only known per request
    if ((conf->input_data || conf->filter) && !conf->output_type->lengths && !conf->options->lengths) return ngx_http_mupdf_check_output(cf, conf);
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_mupdf_init_process(ngx_cycle_t *cycle) {
    ngx_http_mupdf_main_conf_t *mcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_mupdf_module);
    if (!mcf || !mcf->enable) return NGX_OK;
#if (NGX_THREADS)
    for (ngx_uint_t i = 0; i < FZ_LOCK_MAX; i++) if (ngx_thread_mutex_create(&ngx_http_mupdf_mutex[i], cycle->log) != NGX_OK) return NGX_ERROR;
#endif
    fz_locks_context locks = {.user = NULL, .lock = ngx_http_mupdf_lock, .unlock = ngx_http_mupdf_unlock};
    // shared by all requests of the worker: document handlers are registered and the store is limited once
    fz_context *ctx = fz_new_context(NULL, &locks, mcf->store_size);
    if (!ctx) { ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "!fz_new_context"); return NGX_OK; }
    fz_set_error_callback(ctx, pg_mupdf_error_callback, cycle->log);
    fz_set_warning_callback(ctx, pg_mupdf_warning_callback, cycle->log);
    int error = 0;
    fz_try(ctx) {
        fz_register_document_handlers(ctx);
        fz_set_use_document_css(ctx, 1);
    } fz_catch(ctx) {
        fz_report_error(ctx);
        error = 1;
    }
    if (error) { fz_drop_context(ctx); return NGX_OK; }
    mcf->ctx = ctx;
    return NGX_OK;
}

static void ngx_http_mupdf_exit_process(ngx_cycle_t *cycle) {
    ngx_http_mupdf_main_conf_t *mcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_mupdf_module);
    if (!mcf || !mcf->enable) return;
    if (mcf->ctx) fz_drop_context(mcf->ctx);
    mcf->ctx = NULL;
#if (NGX_THREADS)
    for (ngx_uint_t i = 0; i < FZ_LOCK_MAX; i++) ngx_thread_mutex_destroy(&ngx_http_mupdf_mutex[i], cycle->log);
#endif
}

static ngx_int_t ngx_http_mupdf_postconfiguration(ngx_conf_t *cf) {
    ngx_http_mupdf_main_conf_t *mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mupdf_module);
    if (!mcf->filter) return NGX_OK;
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_mupdf_header_filter;
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_mupdf_body_filter;
    return NGX_OK;
}

static ngx_http_module_t ngx_http_mupdf_module_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = ngx_http_mupdf_postconfiguration,
    .create_main_conf = ngx_http_mupdf_create_main_conf,
    .init_main_conf = ngx_http_mupdf_init_main_conf,
    .create_srv_conf = NULL,
    .merge_srv_conf = NULL,
    .create_loc_conf = ngx_http_mupdf_create_loc_conf,
    .merge_loc_conf = ngx_http_mupdf_merge_loc_conf
};

ngx_module_t ngx_http_mupdf_module = {
    NGX_MODULE_V1,
    .ctx = &ngx_http_mupdf_module_ctx,
    .commands = ngx_http_mupdf_commands,
    .type = NGX_HTTP_MODULE,
    .init_master = NULL,
    .init_module = NULL,
    .init_process = ngx_http_mupdf_init_process,
    .init_thread = NULL,
    .exit_thread = NULL,
    .exit_process = ngx_http_mupdf_exit_process,
    .exit_master = NULL,
    NGX_MODULE_V1_PADDING
};
