#include <iostream>
#include <cstring>
#include <vector>
#include <stdint.h>
#include <unordered_map>
#include <regex>
#include "../header/http.h"

using namespace std;

const char *HTTP_METHOD_HTTP = "HTTP";
const char *HTTP_METHOD_GET = "GET";
const char *HTTP_METHOD_POST = "POST";
const char *HTTP_METHOD_PUT = "PUT";
const char *HTTP_METHOD_DELETE = "DELETE";
const char *HTTP_METHOD_CONNECT = "CONNECT";
const char *HTTP_METHOD_OPTIONS = "OPTIONS";
const char *HTTP_METHOD_TRACE = "TRACE";
const char *HTTP_METHOD_PATCH = "PATCH";

void *HTTP_METHOD[] =
    {(void *)HTTP_METHOD_HTTP,
     (void *)HTTP_METHOD_GET,
     (void *)HTTP_METHOD_POST,
     (void *)HTTP_METHOD_PUT,
     (void *)HTTP_METHOD_DELETE,
     (void *)HTTP_METHOD_CONNECT,
     (void *)HTTP_METHOD_OPTIONS,
     (void *)HTTP_METHOD_TRACE,
     (void *)HTTP_METHOD_PATCH};

bool check_http_method(uint8_t *data, const char *http_method, uint32_t size)
{
    int http_method_size = strlen(http_method);

    if (size <= http_method_size)
        return false;
    return memcmp(data, http_method, http_method_size) == 0;
}

bool is_http_protocol(uint8_t *p, uint32_t size)
{
    for (int i = 0; i < (sizeof(HTTP_METHOD) / sizeof(void *)); i++)
    {
        bool is_find = check_http_method(p, (const char *)HTTP_METHOD[i], size);

        if (is_find)
            return is_find;
    }

    return false;
}

bool parse_http(uint8_t *p, uint32_t size, unordered_map<string, string> *http_header)
{
    char http_data[size];
    memcpy(http_data, p, size);

    vector<string> header_str_lines;
    split(http_data, "\r\n", &header_str_lines);
    vector<string>::iterator header_str_line_it;

    for (header_str_line_it = header_str_lines.begin() + 1; header_str_line_it != header_str_lines.end(); header_str_line_it++)
    {
        regex rgx("^([^:]+)*:*(.+)$"); // 정규식
        smatch matches;

        if (regex_search(*header_str_line_it, matches, rgx))
        {
            if (matches.size() >= 3)
            {
                string http_header_key(matches[1].str());
                string http_header_value(matches[2].str());

                http_header_key = trim(http_header_key);
                http_header_value = trim(http_header_value);

                http_header->insert(make_pair(http_header_key, http_header_value));
            }
        }
    }
}