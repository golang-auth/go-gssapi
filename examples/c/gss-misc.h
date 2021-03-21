#pragma once


extern FILE *display_file;

int send_token(int s, gss_buffer_t tok);
int recv_token(int s, gss_buffer_t tok);
void display_status(char *msg, OM_uint32 maj_stat, OM_uint32 min_stat);
void display_ctx_flags(OM_uint32 flags);
void print_token(gss_buffer_t tok);




