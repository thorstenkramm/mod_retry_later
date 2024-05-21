/*
mod_evasive for Apache 2
Copyright (c) by Jonathan A. Zdziarski

LICENSE
                                                                                
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.
                                                                                
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
                                                                                
You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <syslog.h>
#include <errno.h>
#include <apr_file_io.h>
#include <apr_time.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <apr_strings.h>

#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "ap_regex.h"

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(retry_later);
#endif

module AP_MODULE_DECLARE_DATA
retry_later_module;

#if AP_SERVER_MAJORVERSION_NUMBER > 2 || \
    (AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER >= 4)
#define CLIENT_IP(conn) ((conn)->client_ip)
#else
#define CLIENT_IP(conn) ((conn)->remote_ip)
#endif

/* BEGIN DoS Evasive Maneuvers Definitions */

#define MAILER    "/usr/bin/mail %s"
#define  LOG(A, ...) { openlog("mod_retry_later", LOG_PID, LOG_DAEMON); syslog( A, __VA_ARGS__ ); closelog(); }

#define DEFAULT_HASH_TBL_SIZE   3097ul  // Default hash table size
#define DEFAULT_PAGE_COUNT      2       // Default maximum page hit count per interval
#define DEFAULT_SITE_COUNT      50      // Default maximum site hit count per interval
#define DEFAULT_PAGE_INTERVAL   1       // Default 1 Second page interval
#define DEFAULT_SITE_INTERVAL   1       // Default 1 Second site interval
#define DEFAULT_BLOCKING_PERIOD 10      // Default for Detected IPs; blocked for 10 seconds
#define DEFAULT_LOG_DIR        "/tmp"  // Default temp directory
#define DEFAULT_HTTP_RESPONSE_CODE HTTP_TOO_MANY_REQUESTS

/* END DoS Evasive Maneuvers Definitions */

/* BEGIN NTT (Named Timestamp Tree) Headers */

enum {
    ntt_num_primes = 28
};

/* ntt root tree */
struct ntt {
    long size;
    long items;
    struct ntt_node **tbl;
};

/* ntt node (entry in the ntt root tree) */
struct ntt_node {
    char *key;
    time_t timestamp;
    long count;
    struct ntt_node *next;
};

/* ntt cursor */
struct ntt_c {
    long iter_index;
    struct ntt_node *iter_next;
};

struct ntt *ntt_create(long size);

int ntt_destroy(struct ntt *ntt);

struct ntt_node *ntt_find(struct ntt *ntt, const char *key);

struct ntt_node *ntt_insert(struct ntt *ntt, const char *key, time_t timestamp);

int ntt_delete(struct ntt *ntt, const char *key);

long ntt_hashcode(struct ntt *ntt, const char *key);

struct ntt_node *c_ntt_first(struct ntt *ntt, struct ntt_c *c);

struct ntt_node *c_ntt_next(struct ntt *ntt, struct ntt_c *c);

typedef struct {
    char *ip; // Client IP retrieved from the connection
    char *real_ip; // Client IP extracted from custom header
    char *source; // Information from where the Client IP was retrieved
} Client_IP;

/* END NTT (Named Timestamp Tree) Headers */


/* BEGIN DoS Evasive Maneuvers Globals */

struct ntt *hit_list;    // Our dynamic hash table

static unsigned long hash_table_size = DEFAULT_HASH_TBL_SIZE;
static int page_count = DEFAULT_PAGE_COUNT;
static int page_interval = DEFAULT_PAGE_INTERVAL;
static int site_count = DEFAULT_SITE_COUNT;
static int site_interval = DEFAULT_SITE_INTERVAL;
static int blocking_period = DEFAULT_BLOCKING_PERIOD;
static char *email_notify = NULL;
static char *log_dir = NULL;
static char *system_command = NULL;
static char *response_document = NULL;
static char *exclude_uri_re = NULL;
static char *debug_log_path = NULL;
static char *client_ip_header = NULL; // Header from where to extract the Client IP

static const char *whitelist(cmd_parms *cmd, void *dconfig, const char *ip);

static int http_response_code = DEFAULT_HTTP_RESPONSE_CODE;

int is_whitelisted(const char *ip);

// Function to remove leading and trailing spaces from a string
void trim_spaces(char *str) {
    char *start = str;
    char *end;

    // Trim leading space
    while (isspace((unsigned char) *start)) start++;

    // Shift the string, so it starts from the first non-space character
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }

    if (*str == 0)  // All spaces?
        return;

    // Trim trailing space
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char) *end)) end--;

    // Write new null terminator character
    end[1] = '\0';
}

// Function to get the last element in a comma-separated string
void get_last_element(const char *input, char *output) {
    // Make a copy of the input string because strtok modifies the string it processes
    char temp[256];
    strncpy(temp, input, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0'; // Ensure null termination

    char *token;
    char *last_token = NULL;

    // Use strtok to split the string by commas
    token = strtok(temp, ",");
    while (token != NULL) {
        trim_spaces(token);  // Trim spaces around the token
        last_token = token;
        token = strtok(NULL, ",");
    }

    if (last_token != NULL) {
        // Copy the last token to output
        strncpy(output, last_token, 256);
        output[255] = '\0'; // Ensure null termination
    } else {
        output[0] = '\0'; // If no tokens were found, return an empty string
    }
}

// Function to get the client's IP address from different sources
Client_IP get_client_ip(request_rec *r) {
    Client_IP c = {0};
    c.ip = apr_pstrdup(r->pool, r->connection->client_ip);
    c.real_ip = apr_pstrdup(r->pool, c.ip);
    c.source = "connection"; // Default source
    if (!client_ip_header) {
        // End here because no custom header specified to retrieve the client ip from.
        return c;
    }
    // Try to get the client ip from a custom header
    const char *custom_client_ip = apr_table_get(r->headers_in, client_ip_header);
    if (!custom_client_ip) {
        return c;
    }
    char last_ip[256];  // Buffer to hold the last IP
    get_last_element(custom_client_ip, last_ip);
    if (strlen(last_ip) > 0) {
        c.real_ip = apr_pstrdup(r->pool, last_ip);
        c.source = apr_pstrcat(r->pool, "Header ", client_ip_header, NULL);
    }
    return c;
}

static void log_debug(request_rec *r, Client_IP *c) {
    if (debug_log_path == NULL) {
        return;
    }

    apr_file_t *file = NULL;
    apr_status_t rv = apr_file_open(&file, debug_log_path, APR_WRITE | APR_APPEND | APR_CREATE, APR_OS_DEFAULT,
                                    r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "Failed to open debug log file: %s", debug_log_path);
        return;
    }

    apr_time_exp_t tm;
    apr_time_exp_gmt(&tm, apr_time_now());

    char time_str[40];
    apr_snprintf(time_str, sizeof(time_str), "%04d-%02d-%02d %02d:%02d:%02d",
                 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

    const char *user_agent = apr_table_get(r->headers_in, "User-Agent");
    if (!user_agent) {
        user_agent = "-";
    }

    apr_file_printf(file, "[%s] \"%s %s\" %d \"%s\" \"Remote-IP: %s\", \"Real-Client-IP (From %s): %s\"\n",
                    time_str, r->method, r->uri, DEFAULT_HTTP_RESPONSE_CODE, user_agent, c->ip, c->source,
                    c->real_ip);

    apr_file_close(file);
}

static void *create_hit_list(apr_pool_t *p, server_rec *s) {
    /* Create a new hit list for this listener */

    hit_list = ntt_create(hash_table_size);
}

static const char *whitelist(cmd_parms *cmd, void *dconfig, const char *ip) {
    char entry[128];
    snprintf(entry, sizeof(entry), "WHITELIST_%s", ip);
    ntt_insert(hit_list, entry, time(NULL));

    return NULL;
}


static int access_checker(request_rec *r) {
    int ret = OK;
    Client_IP client_ip = get_client_ip(r);

    /* BEGIN DoS Evasive Maneuvers Code */
    if (r->prev == NULL && r->main == NULL && hit_list != NULL) {
        char hash_key[2048];
        struct ntt_node *n;
        time_t t = time(NULL);

        /* Check whitelist */
        if (is_whitelisted(client_ip.real_ip))
            return OK;

        /* Check if URI shall be ignored */
        if (exclude_uri_re) {
            ap_regex_t *re = ap_pregcomp(r->pool, exclude_uri_re, AP_REG_EXTENDED | AP_REG_NOSUB);
            if (ap_regexec(re, r->uri, 0, NULL, 0) == 0) {
                ap_pregfree(r->pool, re);
                return OK;
            }
            ap_pregfree(r->pool, re);
        }

        /* First see if the IP itself is on "hold" */
        n = ntt_find(hit_list, client_ip.real_ip);

        if (n != NULL && t - n->timestamp < blocking_period) {

            /* If the IP is on "hold", make it wait longer on blacklist */
            ret = http_response_code;
            n->timestamp = time(NULL);

            /* Not on hold, check hit stats */
        } else {

            /* Has URI been hit too much? */
            snprintf(hash_key, 2048, "%s_%s", client_ip.real_ip, r->uri);
            n = ntt_find(hit_list, hash_key);
            if (n != NULL) {

                /* If URI is being hit too much, add to "hold" list */
                if (t - n->timestamp < page_interval && n->count >= page_count) {
                    ret = http_response_code;
                    ntt_insert(hit_list, client_ip.real_ip, time(NULL));
                } else {

                    /* Reset our hit count list as necessary */
                    if (t - n->timestamp >= page_interval) {
                        n->count = 0;
                    }
                }
                n->timestamp = t;
                n->count++;
            } else {
                ntt_insert(hit_list, hash_key, t);
            }

            /* Has site been hit too much? */
            snprintf(hash_key, 2048, "%s_SITE", client_ip.real_ip);
            n = ntt_find(hit_list, hash_key);
            if (n != NULL) {

                /* If site is being hit too much, add to "hold" list */
                if (t - n->timestamp < site_interval && n->count >= site_count) {
                    ret = http_response_code;
                    ntt_insert(hit_list, client_ip.real_ip, time(NULL));
                } else {

                    /* Reset our hit count list as necessary */
                    if (t - n->timestamp >= site_interval) {
                        n->count = 0;
                    }
                }
                n->timestamp = t;
                n->count++;
            } else {
                ntt_insert(hit_list, hash_key, t);
            }
        }

        /* Perform email notification, system functions, and response */
        if (ret == http_response_code) {
            log_debug(r, &client_ip);
            char filename[1024];
            struct stat s;
            FILE *file;

            snprintf(filename, sizeof(filename), "%s/dos-%s", log_dir != NULL ? log_dir : DEFAULT_LOG_DIR,
                     client_ip.real_ip);
            if (stat(filename, &s)) {
                file = fopen(filename, "w");
                if (file != NULL) {
                    fprintf(file, "%d\n", getpid());
                    fclose(file);

                    LOG(LOG_ALERT, "Blacklisting address %s: possible DoS attack.", client_ip.real_ip);
                    if (email_notify != NULL) {
                        snprintf(filename, sizeof(filename), MAILER, email_notify);
                        file = popen(filename, "w");
                        if (file != NULL) {
                            fprintf(file, "To: %s\n", email_notify);
                            fprintf(file, "Subject: HTTP BLACKLIST %s\n\n", client_ip.real_ip);
                            fprintf(file, "mod_retry_later HTTP Blacklisted %s\n", client_ip.real_ip);
                            pclose(file);
                        }
                    }

                    if (system_command != NULL) {
                        snprintf(filename, sizeof(filename), system_command, client_ip.real_ip);
                        int ret = system(filename);
                        if (ret == -1) {
                            // Handle error when the system command cannot be executed
                            LOG(LOG_ALERT, "mod_retry_later: system command failed: %d", ret);
                        }
                    }

                } else {
                    LOG(LOG_ALERT, "Couldn't open logfile %s: %s", filename, strerror(errno));
                }

            } /* if (temp file does not exist) */

            if (DEFAULT_HTTP_RESPONSE_CODE == HTTP_TOO_MANY_REQUESTS) {
                // Set the content type of the response
                ap_set_content_type(r, "text/html");

                // Convert blocking_period to a string
                char blocking_period_str[20];
                snprintf(blocking_period_str, sizeof(blocking_period_str), "%d", blocking_period);
                // Send Header
                apr_table_set(r->headers_out, "Retry-After", blocking_period_str);

                // Declare response_body pointer here to have function-wide scope
                char *response_body = NULL;

                // Get or generate the custom response message
                if (response_document) {
                    /* We have a custom response document from a file */
                    // Open the file
                    apr_file_t *file = NULL;
                    apr_finfo_t finfo;
                    apr_status_t rv = apr_file_open(&file, response_document, APR_READ, APR_OS_DEFAULT, r->pool);
                    if (rv != APR_SUCCESS) {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "Failed to open response document: %s",
                                      response_document);
                        return HTTP_INTERNAL_SERVER_ERROR; // Or some other appropriate error response
                    }

                    // Get file info
                    apr_file_info_get(&finfo, APR_FINFO_SIZE, file);

                    // Allocate buffer for the file content
                    response_body = apr_palloc(r->pool, finfo.size + 1);
                    if (response_body == NULL) {
                        apr_file_close(file);
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_ENOMEM, r, "Memory allocation failure.");
                        return HTTP_INTERNAL_SERVER_ERROR;
                    }

                    // Read the file into the buffer
                    apr_size_t bytes_read;
                    apr_file_read_full(file, response_body, finfo.size, &bytes_read);
                    response_body[bytes_read] = '\0'; // Ensure null termination

                    // Close the file
                    apr_file_close(file);
                } else {
                    response_body = apr_palloc(r->pool, 1024);
                    if (response_body == NULL) {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_ENOMEM, r, "Memory allocation failure.");
                        return HTTP_INTERNAL_SERVER_ERROR;
                    }
                    snprintf(response_body, 1024, "Too many requests. Try again after %s seconds.\n",
                             blocking_period_str);
                }

                // Return HTTP status code
                r->status = DEFAULT_HTTP_RESPONSE_CODE;

                // Send response
                ap_rputs(response_body, r);

                // Tell Apache the request is DONE. No further processing.
                return DONE;
            }
        } /* if (ret == http_response_code) */

    } /* if (r->prev == NULL && r->main == NULL && hit_list != NULL) */

    /* END DoS Evasive Maneuvers Code */

    if (ret == http_response_code
        && (ap_satisfies(r) != SATISFY_ANY || !ap_some_auth_required(r))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "client denied by server configuration: %s",
                      r->filename);

    }

    return ret;
}

int is_whitelisted(const char *ip) {
    char hashkey[128];
    char octet[4][4];
    char *dip;
    char *oct;
    int i = 0;

    memset(octet, 0, 16);
    dip = strdup(ip);
    if (dip == NULL)
        return 0;

    oct = strtok(dip, ".");
    while (oct != NULL && i < 4) {
        if (strlen(oct) <= 3)
            strcpy(octet[i], oct);
        i++;
        oct = strtok(NULL, ".");
    }
    free(dip);

    /* Exact Match */
    snprintf(hashkey, sizeof(hashkey), "WHITELIST_%s", ip);
    if (ntt_find(hit_list, hashkey) != NULL)
        return 1;

    /* IPv4 Wildcards */
    snprintf(hashkey, sizeof(hashkey), "WHITELIST_%s.*.*.*", octet[0]);
    if (ntt_find(hit_list, hashkey) != NULL)
        return 1;

    snprintf(hashkey, sizeof(hashkey), "WHITELIST_%s.%s.*.*", octet[0], octet[1]);
    if (ntt_find(hit_list, hashkey) != NULL)
        return 1;

    snprintf(hashkey, sizeof(hashkey), "WHITELIST_%s.%s.%s.*", octet[0], octet[1], octet[2]);
    if (ntt_find(hit_list, hashkey) != NULL)
        return 1;

    /* No match */
    return 0;
}

static apr_status_t destroy_hit_list(void *not_used) {
    ntt_destroy(hit_list);
    free(email_notify);
    free(system_command);
}


/* BEGIN NTT (Named Timestamp Tree) Functions */

static unsigned long ntt_prime_list[ntt_num_primes] =
        {
                53ul, 97ul, 193ul, 389ul, 769ul,
                1543ul, 3079ul, 6151ul, 12289ul, 24593ul,
                49157ul, 98317ul, 196613ul, 393241ul, 786433ul,
                1572869ul, 3145739ul, 6291469ul, 12582917ul, 25165843ul,
                50331653ul, 100663319ul, 201326611ul, 402653189ul, 805306457ul,
                1610612741ul, 3221225473ul, 4294967291ul
        };


/* Find the numeric position in the hash table based on key and modulus */

long ntt_hashcode(struct ntt *ntt, const char *key) {
    unsigned long val = 0;
    for (; *key; ++key) val = 5 * val + *key;
    return (val % ntt->size);
}

/* Creates a single node in the tree */

struct ntt_node *ntt_node_create(const char *key) {
    char *node_key;
    struct ntt_node *node;

    node = (struct ntt_node *) malloc(sizeof(struct ntt_node));
    if (node == NULL) {
        return NULL;
    }
    if ((node_key = strdup(key)) == NULL) {
        free(node);
        return NULL;
    }
    node->key = node_key;
    node->timestamp = time(NULL);
    node->next = NULL;
    return (node);
}

/* Tree initializer */

struct ntt *ntt_create(long size) {
    long i = 0;
    struct ntt *ntt = (struct ntt *) malloc(sizeof(struct ntt));

    if (ntt == NULL)
        return NULL;
    while (ntt_prime_list[i] < size) { i++; }
    ntt->size = ntt_prime_list[i];
    ntt->items = 0;
    ntt->tbl = (struct ntt_node **) calloc(ntt->size, sizeof(struct ntt_node *));
    if (ntt->tbl == NULL) {
        free(ntt);
        return NULL;
    }
    return (ntt);
}

/* Find an object in the tree */

struct ntt_node *ntt_find(struct ntt *ntt, const char *key) {
    long hash_code;
    struct ntt_node *node;

    if (ntt == NULL) return NULL;

    hash_code = ntt_hashcode(ntt, key);
    node = ntt->tbl[hash_code];

    while (node) {
        if (!strcmp(key, node->key)) {
            return (node);
        }
        node = node->next;
    }
    return ((struct ntt_node *) NULL);
}

/* Insert a node into the tree */

struct ntt_node *ntt_insert(struct ntt *ntt, const char *key, time_t timestamp) {
    long hash_code;
    struct ntt_node *parent;
    struct ntt_node *node;
    struct ntt_node *new_node = NULL;

    if (ntt == NULL) return NULL;

    hash_code = ntt_hashcode(ntt, key);
    parent = NULL;
    node = ntt->tbl[hash_code];

    while (node != NULL) {
        if (strcmp(key, node->key) == 0) {
            new_node = node;
            node = NULL;
        }

        if (new_node == NULL) {
            parent = node;
            node = node->next;
        }
    }

    if (new_node != NULL) {
        new_node->timestamp = timestamp;
        new_node->count = 0;
        return new_node;
    }

    /* Create a new node */
    new_node = ntt_node_create(key);
    new_node->timestamp = timestamp;
    new_node->timestamp = 0;

    ntt->items++;

    /* Insert */
    if (parent) {  /* Existing parent */
        parent->next = new_node;
        return new_node;  /* Return the locked node */
    }

    /* No existing parent; add directly to hash table */
    ntt->tbl[hash_code] = new_node;
    return new_node;
}

/* Tree destructor */

int ntt_destroy(struct ntt *ntt) {
    struct ntt_node *node, *next;
    struct ntt_c c;

    if (ntt == NULL) return -1;

    node = c_ntt_first(ntt, &c);
    while (node != NULL) {
        next = c_ntt_next(ntt, &c);
        ntt_delete(ntt, node->key);
        node = next;
    }

    free(ntt->tbl);
    free(ntt);
    ntt = (struct ntt *) NULL;

    return 0;
}

/* Delete a single node in the tree */

int ntt_delete(struct ntt *ntt, const char *key) {
    long hash_code;
    struct ntt_node *parent = NULL;
    struct ntt_node *node;
    struct ntt_node *del_node = NULL;

    if (ntt == NULL) return -1;

    hash_code = ntt_hashcode(ntt, key);
    node = ntt->tbl[hash_code];

    while (node != NULL) {
        if (strcmp(key, node->key) == 0) {
            del_node = node;
            node = NULL;
        }

        if (del_node == NULL) {
            parent = node;
            node = node->next;
        }
    }

    if (del_node != NULL) {

        if (parent) {
            parent->next = del_node->next;
        } else {
            ntt->tbl[hash_code] = del_node->next;
        }

        free(del_node->key);
        free(del_node);
        ntt->items--;

        return 0;
    }

    return -5;
}

/* Point cursor to first item in tree */

struct ntt_node *c_ntt_first(struct ntt *ntt, struct ntt_c *c) {

    c->iter_index = 0;
    c->iter_next = (struct ntt_node *) NULL;
    return (c_ntt_next(ntt, c));
}

/* Point cursor to next iteration in tree */

struct ntt_node *c_ntt_next(struct ntt *ntt, struct ntt_c *c) {
    long index;
    struct ntt_node *node = c->iter_next;

    if (ntt == NULL) return NULL;

    if (node) {
        if (node != NULL) {
            c->iter_next = node->next;
            return (node);
        }
    }

    if (!node) {
        while (c->iter_index < ntt->size) {
            index = c->iter_index++;

            if (ntt->tbl[index]) {
                c->iter_next = ntt->tbl[index]->next;
                return (ntt->tbl[index]);
            }
        }
    }
    return ((struct ntt_node *) NULL);
}

/* END NTT (Named Pointer Tree) Functions */


/* BEGIN Configuration Functions */

static const char *
get_hash_tbl_size(cmd_parms *cmd, void *dconfig, const char *value) {
    long n = strtol(value, NULL, 0);

    if (n <= 0) {
        hash_table_size = DEFAULT_HASH_TBL_SIZE;
    } else {
        hash_table_size = n;
    }

    return NULL;
}

static const char *
get_page_count(cmd_parms *cmd, void *dconfig, const char *value) {
    long n = strtol(value, NULL, 0);
    if (n <= 0) {
        page_count = DEFAULT_PAGE_COUNT;
    } else {
        page_count = n;
    }

    return NULL;
}

static const char *
get_site_count(cmd_parms *cmd, void *dconfig, const char *value) {
    long n = strtol(value, NULL, 0);
    if (n <= 0) {
        site_count = DEFAULT_SITE_COUNT;
    } else {
        site_count = n;
    }

    return NULL;
}

static const char *
get_page_interval(cmd_parms *cmd, void *dconfig, const char *value) {
    long n = strtol(value, NULL, 0);
    if (n <= 0) {
        page_interval = DEFAULT_PAGE_INTERVAL;
    } else {
        page_interval = n;
    }

    return NULL;
}

static const char *
get_site_interval(cmd_parms *cmd, void *dconfig, const char *value) {
    long n = strtol(value, NULL, 0);
    if (n <= 0) {
        site_interval = DEFAULT_SITE_INTERVAL;
    } else {
        site_interval = n;
    }

    return NULL;
}

static const char *
get_blocking_period(cmd_parms *cmd, void *dconfig, const char *value) {
    long n = strtol(value, NULL, 0);
    if (n <= 0) {
        blocking_period = DEFAULT_BLOCKING_PERIOD;
    } else {
        blocking_period = n;
    }

    return NULL;
}

static const char *
get_log_dir(cmd_parms *cmd, void *dconfig, const char *value) {
    if (value != NULL && value[0] != 0) {
        if (log_dir != NULL)
            free(log_dir);
        log_dir = strdup(value);
    }

    return NULL;
}

static const char *
get_email_notify(cmd_parms *cmd, void *dconfig, const char *value) {
    if (value != NULL && value[0] != 0) {
        if (email_notify != NULL)
            free(email_notify);
        email_notify = strdup(value);
    }

    return NULL;
}

static const char *
get_system_command(cmd_parms *cmd, void *dconfig, const char *value) {
    if (value != NULL && value[0] != 0) {
        if (system_command != NULL)
            free(system_command);
        system_command = strdup(value);
    }

    return NULL;
}

static const char *
get_http_response_code(cmd_parms *cmd, void *dconfig, const char *value) {
    int n = strtol(value, NULL, 0);
    // Allow HTTP response codes between 100 and 599 as per RFC 7231
    if (n >= 100 && n < 600) {
        http_response_code = n;
    } else {
        http_response_code = DEFAULT_HTTP_RESPONSE_CODE;
    }

    return NULL;
}

/* Declaration of the function to get the response document path */
static const char *
get_response_document(cmd_parms *cmd, void *dummy, const char *arg) {
    if (arg != NULL && arg[0] != '\0') {
        if (response_document != NULL)
            free(response_document);
        response_document = strdup(arg);
    }
    return NULL;
}

/* Declaration of the function to get the regex pattern for excluding URIs */
static const char *
get_exclude_re(cmd_parms *cmd, void *dummy, const char *arg) {
    if (arg != NULL && arg[0] != '\0') {
        if (exclude_uri_re != NULL)
            free(exclude_uri_re);
        exclude_uri_re = strdup(arg);
    }
    return NULL;
}

static const char *
get_debug_log(cmd_parms *cmd, void *dummy, const char *arg) {
    if (arg != NULL && arg[0] != '\0') {
        if (debug_log_path != NULL)
            free(debug_log_path);
        debug_log_path = strdup(arg);
    }
    return NULL;
}

static const char *
get_client_ip_header(cmd_parms *cmd, void *dummy, const char *arg) {
    if (arg != NULL && arg[0] != '\0') {
        if (client_ip_header != NULL)
            free(client_ip_header);
        client_ip_header = strdup(arg);
    }
    return NULL;
}


/* END Configuration Functions */

static const command_rec access_cmds[] =
        {
                AP_INIT_TAKE1("DOSHashTableSize", get_hash_tbl_size, NULL, RSRC_CONF,
                              "Set size of hash table"),

                AP_INIT_TAKE1("DOSPageCount", get_page_count, NULL, RSRC_CONF,
                              "Set maximum page hit count per interval"),

                AP_INIT_TAKE1("DOSSiteCount", get_site_count, NULL, RSRC_CONF,
                              "Set maximum site hit count per interval"),

                AP_INIT_TAKE1("DOSPageInterval", get_page_interval, NULL, RSRC_CONF,
                              "Set page interval"),

                AP_INIT_TAKE1("DOSSiteInterval", get_site_interval, NULL, RSRC_CONF,
                              "Set site interval"),

                AP_INIT_TAKE1("DOSBlockingPeriod", get_blocking_period, NULL, RSRC_CONF,
                              "Set blocking period for detected DoS IPs"),

                AP_INIT_TAKE1("DOSEmailNotify", get_email_notify, NULL, RSRC_CONF,
                              "Set email notification"),

                AP_INIT_TAKE1("DOSLogDir", get_log_dir, NULL, RSRC_CONF,
                              "Set log dir"),

                AP_INIT_TAKE1("DOSSystemCommand", get_system_command, NULL, RSRC_CONF,
                              "Set system command on DoS"),

                AP_INIT_ITERATE("DOSWhitelist", whitelist, NULL, RSRC_CONF,
                                "IP-addresses wildcards to whitelist"),

                AP_INIT_TAKE1("DOSHTTPResponseCode", get_http_response_code, NULL, RSRC_CONF,
                              "Set HTTP response code returned when IP is blocked"),

                AP_INIT_TAKE1("DOSResponseDocument", get_response_document, NULL, RSRC_CONF,
                              "Set document to be returned on limit hit"),

                AP_INIT_TAKE1("DOSExcludeURIRe", get_exclude_re, NULL, RSRC_CONF,
                              "Regular expression to exclude requests from rate limiting if URI macthes regex"),

                AP_INIT_TAKE1("DOSDebugLog", get_debug_log, NULL, RSRC_CONF,
                              "File path for debug logs. If not set, debug logging switched of"),

                AP_INIT_TAKE1("DOSClientIPHeader", get_client_ip_header, NULL, RSRC_CONF,
                              "Use custom header to determine the client ip address"),

                {NULL}
        };

static void register_hooks(apr_pool_t *p) {
    ap_hook_access_checker(access_checker, NULL, NULL, APR_HOOK_MIDDLE);
    apr_pool_cleanup_register(p, NULL, apr_pool_cleanup_null, destroy_hit_list);
};

module AP_MODULE_DECLARE_DATA
retry_later_module =
        {
                STANDARD20_MODULE_STUFF,
                NULL,
                NULL,
                create_hit_list,
                NULL,
                access_cmds,
                register_hooks
        };

