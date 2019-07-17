#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <mupdf/fitz.h>

typedef struct {
    ngx_http_complex_value_t *input_data;
    ngx_str_t input_type;
    ngx_str_t output_type;
    ngx_str_t options;
    ngx_str_t range;
} ngx_http_mupdf_loc_conf_t;

ngx_module_t ngx_http_mupdf_module;

/*struct fz_buffer_s {
    int refs;
    unsigned char *data;
    size_t cap, len;
    int unused_bits;
    int shared;
};*/

static void runpage(fz_context *ctx, fz_document *doc, int number, fz_document_writer *wri) {
    fz_page *page = fz_load_page(ctx, doc, number - 1);
    fz_try(ctx) {
        fz_rect mediabox = fz_bound_page(ctx, page);
        fz_device *dev = fz_begin_page(ctx, wri, mediabox);
        fz_run_page(ctx, page, dev, fz_identity, NULL);
        fz_end_page(ctx, wri);
    } fz_always(ctx) {
        fz_drop_page(ctx, page);
    } fz_catch(ctx) {
        fz_rethrow(ctx);
    }
}

static void runrange(fz_context *ctx, fz_document *doc, const char *range, fz_document_writer *wri) {
    int start, end, count;
    count = fz_count_pages(ctx, doc);
    while ((range = fz_parse_page_range(ctx, range, &start, &end, count))) {
        if (start < end) {
            for (int i = start; i <= end; i++) {
                runpage(ctx, doc, i, wri);
            }
        } else {
            for (int i = start; i >= end; i--) {
                runpage(ctx, doc, i, wri);
            }
        }
    }
}

static ngx_int_t ngx_http_mupdf_handler(ngx_http_request_t *r) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_mupdf_handler");
    if (!(r->method & NGX_HTTP_GET)) return NGX_HTTP_NOT_ALLOWED;
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK && rc != NGX_AGAIN) return rc;
    ngx_http_mupdf_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_mupdf_module);
    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    char *input_type = ngx_pcalloc(r->pool, conf->input_type.len + 1);
    if (!input_type) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!input_type"); goto ret; }
    ngx_memcpy(input_type, conf->input_type.data, conf->input_type.len);
    char *output_type = ngx_pcalloc(r->pool, conf->output_type.len + 1);
    if (!output_type) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!output_type"); goto ret; }
    ngx_memcpy(output_type, conf->output_type.data, conf->output_type.len);
    char *options = ngx_pcalloc(r->pool, conf->options.len + 1);
    if (!options) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!options"); goto ret; }
    ngx_memcpy(options, conf->options.data, conf->options.len);
    char *range = ngx_pcalloc(r->pool, conf->range.len + 1);
    if (!range) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!range"); goto ret; }
    ngx_memcpy(range, conf->range.data, conf->range.len);
    ngx_str_t input_data, out = {0, NULL};
    if (ngx_http_complex_value(r, conf->input_data, &input_data) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); goto ret; }
    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "input_data = %V, input_type = %s, output_type = %s, range = %s, options = %s", &input_data, input_type, output_type, range, options);
    fz_context *ctx = fz_new_context(NULL, NULL, FZ_STORE_UNLIMITED);
    if (!ctx) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!fz_new_context"); goto ret; }
    fz_buffer *output_buffer; fz_var(output_buffer);
    fz_buffer *input_buffer; fz_var(input_buffer);
    fz_document *doc; fz_var(doc);
    fz_document_writer *wri; fz_var(wri);
    fz_try(ctx) {
        fz_register_document_handlers(ctx);
        fz_set_use_document_css(ctx, 1);
        output_buffer = fz_new_buffer(ctx, 0);
        fz_set_user_context(ctx, output_buffer);
        input_buffer = fz_new_buffer_from_data(ctx, (unsigned char *)input_data.data, input_data.len);
        fz_stream *input_stream = fz_open_buffer(ctx, input_buffer);
        doc = fz_open_document_with_stream(ctx, input_type, input_stream);
        wri = fz_new_document_writer(ctx, "buf:", output_type, options);
        runrange(ctx, doc, range, wri);
    } fz_always(ctx) {
        fz_close_document_writer(ctx, wri);
        fz_drop_document_writer(ctx, wri);
        fz_drop_document(ctx, doc);
        fz_drop_buffer(ctx, input_buffer);
    } fz_catch(ctx) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "fz_caught_message: %s", fz_caught_message(ctx));
        goto fz_drop_context;
    }
//    const char *output_data = fz_string_from_buffer(ctx, output_buffer);
//    out.len = ngx_strlen(output_data);
    unsigned char *output_data = NULL;
    out.len = fz_buffer_storage(ctx, output_buffer, &output_data);
//    unsigned char *output_data = output_buffer->data;
//    out.len = output_buffer->len;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "out.len = %ul", out.len);
    if (out.len) out.data = ngx_palloc(r->pool, out.len);
    if (out.data) ngx_memcpy(out.data, output_data, out.len);
    fz_buffer *output_buffer1 = fz_new_buffer_from_data(ctx, (unsigned char *)out.data, out.len);
    fz_save_buffer(ctx, output_buffer1, "output_buffer1.pdf");
    fz_save_buffer(ctx, output_buffer, "output_buffer.pdf");
fz_drop_context:
    fz_drop_context(ctx);
    if (out.data) {
        ngx_chain_t ch = {.buf = &(ngx_buf_t){.pos = out.data, .last = out.data + out.len, .memory = 1, .last_buf = 1}, .next = NULL};
//        ngx_str_set(&r->headers_out.content_type, "application/pdf");
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = out.len;
        rc = ngx_http_send_header(r);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rc = %i", rc);
        ngx_http_weak_etag(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only); else rc = ngx_http_output_filter(r, &ch);
    }
ret:
    return rc;
}

static char *ngx_http_mupdf_convert_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_mupdf_handler;
    return ngx_http_set_complex_value_slot(cf, cmd, conf);
}

static ngx_command_t ngx_http_mupdf_commands[] = {
  { .name = ngx_string("mupdf_input_type"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_mupdf_loc_conf_t, input_type),
    .post = NULL },
  { .name = ngx_string("mupdf_output_type"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_mupdf_loc_conf_t, output_type),
    .post = NULL },
  { .name = ngx_string("mupdf_options"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_mupdf_loc_conf_t, options),
    .post = NULL },
  { .name = ngx_string("mupdf_range"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_mupdf_loc_conf_t, range),
    .post = NULL },
  { .name = ngx_string("mupdf"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_mupdf_convert_set,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_mupdf_loc_conf_t, input_data),
    .post = NULL },
    ngx_null_command
};

static void *ngx_http_mupdf_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_mupdf_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mupdf_loc_conf_t));
    if (!conf) return NGX_CONF_ERROR;
    return conf;
}

static char *ngx_http_mupdf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_mupdf_loc_conf_t *prev = parent;
    ngx_http_mupdf_loc_conf_t *conf = child;
    ngx_conf_merge_str_value(conf->input_type, prev->input_type, "html");
    ngx_conf_merge_str_value(conf->output_type, prev->output_type, "pdf");
    ngx_conf_merge_str_value(conf->options, prev->options, "");
    ngx_conf_merge_str_value(conf->range, prev->range, "1-N");
    if (!conf->input_data) conf->input_data = prev->input_data;
    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_mupdf_module_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = NULL,
    .create_main_conf = NULL,
    .init_main_conf = NULL,
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
    .init_process = NULL,
    .init_thread = NULL,
    .exit_thread = NULL,
    .exit_process = NULL,
    .exit_master = NULL,
    NGX_MODULE_V1_PADDING
};
