/*
 * Copyright 1994 by OpenVision Technologies, Inc.
 * 
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 * 
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */



#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>

#include <gssapi/gssapi.h>
#include "gss-misc.h"

void usage()
{
     fprintf(stderr, "Usage: gss-client [-port port] [-d] [-seal] [-mutual] host service \
msg\n");
     exit(1);
}

/*
 * Function: connect_to_server
 *
 * Purpose: Opens a TCP connection to the name host and port.
 *
 * Arguments:
 *
 *      host            (r) the target host name
 *      port            (r) the target port, in host byte order
 *
 * Returns: the established socket file descriptor, or -1 on failure
 *
 * Effects:
 *
 * The host name is resolved with gethostbyname(), and the socket is
 * opened and connected.  If an error occurs, an error message is
 * displayed and -1 is returned.
 */
int connect_to_server(host, port)
     char *host;
     u_short port;
{
     struct sockaddr_in saddr;
     struct hostent *hp;
     int s;
     
     if ((hp = gethostbyname(host)) == NULL) {
          fprintf(stderr, "Unknown host: %s\n", host);
          return -1;
     }
     
     saddr.sin_family = hp->h_addrtype;
     memcpy((char *)&saddr.sin_addr, hp->h_addr, sizeof(saddr.sin_addr));
     saddr.sin_port = htons(port);

     if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
          perror("creating socket");
          return -1;
     }
     if (connect(s, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
          perror("connecting to server");
          (void) close(s);
          return -1;
     }
     return s;
}

/*
 * Function: client_establish_context
 *
 * Purpose: establishes a GSS-API context with a specified service and
 * returns the context handle
 *
 * Arguments:
 *
 *      s               (r) an established TCP connection to the service
 *      service_name    (r) the ASCII service name of the service
 *      context         (w) the established GSS-API context
 *      ret_flags       (w) the returned flags from init_sec_context
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 * 
 * service_name is imported as a GSS-API name and a GSS-API context is
 * established with the corresponding service; the service should be
 * listening on the TCP connection s.  The default GSS-API mechanism
 * is used, and mutual authentication and replay detection are
 * requested.
 * 
 * If successful, the context handle is returned in context.  If
 * unsuccessful, the GSS-API error messages are displayed on stderr
 * and -1 is returned.
 */
int client_establish_context(s, service_name, req_flags,  oid,
                             gss_context, ret_flags)
     int s;
     char *service_name;
     gss_OID oid;
     OM_uint32 req_flags;
     gss_ctx_id_t *gss_context;
     OM_uint32 *ret_flags;
{
     gss_buffer_desc send_tok, recv_tok, *token_ptr;
     gss_name_t target_name;
     OM_uint32 maj_stat, min_stat, init_sec_min_stat;

     /*
      * Import the name into target_name.  Use send_tok to save
      * local variable space.
      */
     send_tok.value = service_name;
     send_tok.length = strlen(service_name) + 1;
     maj_stat = gss_import_name(&min_stat, &send_tok,
         (gss_OID) GSS_C_NT_HOSTBASED_SERVICE, &target_name);
     if (maj_stat != GSS_S_COMPLETE) {
          display_status("parsing name", maj_stat, min_stat);
          return -1;
     }
     
     /*
      * Perform the context-establishement loop.
      *
      * On each pass through the loop, token_ptr points to the token
      * to send to the server (or GSS_C_NO_BUFFER on the first pass).
      * Every generated token is stored in send_tok which is then
      * transmitted to the server; every received token is stored in
      * recv_tok, which token_ptr is then set to, to be processed by
      * the next call to gss_init_sec_context.
      * 
      * GSS-API guarantees that send_tok's length will be non-zero
      * if and only if the server is expecting another token from us,
      * and that gss_init_sec_context returns GSS_S_CONTINUE_NEEDED if
      * and only if the server has another token to send us.
      */
     
     fprintf(stderr, "req_flags: %d\n", req_flags);
     fprintf(stderr, "service_name: %s\n", service_name);
     token_ptr = GSS_C_NO_BUFFER;
     *gss_context = GSS_C_NO_CONTEXT;

     do {
          maj_stat =
               gss_init_sec_context(&init_sec_min_stat,
                                    GSS_C_NO_CREDENTIAL,
                                    gss_context,
                                    target_name,
                                    oid,
                                    req_flags | GSS_C_REPLAY_FLAG,
                                    0,
                                    NULL,       /* no channel bindings */
                                    token_ptr,
                                    NULL,       /* ignore mech type */
                                    &send_tok,
                                    ret_flags,
                                    NULL);      /* ignore time_rec */

          if (token_ptr != GSS_C_NO_BUFFER)
               (void) gss_release_buffer(&min_stat, &recv_tok);

          if (send_tok.length != 0) {
               printf("Sending init_sec_context token (size=%ld)...",
                     send_tok.length);
               if (send_token(s, &send_tok) < 0) {
                    (void) gss_release_buffer(&min_stat, &send_tok);
                    (void) gss_release_name(&min_stat, &target_name);
                    return -1;
               }
          }
          (void) gss_release_buffer(&min_stat, &send_tok);

          if (maj_stat!=GSS_S_COMPLETE && maj_stat!=GSS_S_CONTINUE_NEEDED) {
               display_status("initializing context", maj_stat,
                              init_sec_min_stat);
               (void) gss_release_name(&min_stat, &target_name);
               if (*gss_context == GSS_C_NO_CONTEXT)
                       gss_delete_sec_context(&min_stat, gss_context,
                                              GSS_C_NO_BUFFER);
               return -1;
          }
          
          if (maj_stat == GSS_S_CONTINUE_NEEDED) {
               printf("continue needed...");
               if (recv_token(s, &recv_tok) < 0) {
                    (void) gss_release_name(&min_stat, &target_name);
                    return -1;
               }
               token_ptr = &recv_tok;
          }
          printf("\n");
     } while (maj_stat == GSS_S_CONTINUE_NEEDED);

     (void) gss_release_name(&min_stat, &target_name);
     return 0;
}

void read_file(file_name, in_buf)
    char                *file_name;
    gss_buffer_t        in_buf;
{
    int fd, count;
    struct stat stat_buf;
    
    if ((fd = open(file_name, O_RDONLY, 0)) < 0) {
        perror("open");
        fprintf(stderr, "Couldn't open file %s\n", file_name);
        exit(1);
    }
    if (fstat(fd, &stat_buf) < 0) {
        perror("fstat");
        exit(1);
    }
    in_buf->length = stat_buf.st_size;

    if (in_buf->length == 0) {
        in_buf->value = NULL;
        return;
    }

    if ((in_buf->value = malloc(in_buf->length)) == 0) {
        fprintf(stderr, \
            "Couldn't allocate %ld byte buffer for reading file\n",
            in_buf->length);
        exit(1);
    }

    /* this code used to check for incomplete reads, but you can't get
       an incomplete read on any file for which fstat() is meaningful */

    count = read(fd, in_buf->value, in_buf->length);
    if (count < 0) {
        perror("read");
        exit(1);
    }
    if (count < in_buf->length)
        fprintf(stderr, "Warning, only read in %d bytes, expected %ld\n",
                count, in_buf->length);
}

/*
 * Function: call_server
 *
 * Purpose: Call the "sign" service.
 *
 * Arguments:
 *
 *      host            (r) the host providing the service
 *      port            (r) the port to connect to on host
 *      service_name    (r) the GSS-API service name to authenticate to
 *      msg             (r) the message to have "signed"
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 * 
 * call_server opens a TCP connection to <host:port> and establishes a
 * GSS-API context with service_name over the connection.  It then
 * seals msg in a GSS-API token with gss_seal, sends it to the server,
 * reads back a GSS-API signature block for msg from the server, and
 * verifies it with gss_verify.  -1 is returned if any step fails,
 * otherwise 0 is returned.  */
int call_server(host, port, oid, service_name, req_flag, msg, use_file, seal)
     char *host;
     u_short port;
     gss_OID oid;
     char *service_name;
     OM_uint32 req_flag;
     char *msg;
     int use_file;
     bool seal;
{
     gss_ctx_id_t context;
     gss_buffer_desc in_buf, out_buf;
     int s, state;
     OM_uint32 ret_flags;
     OM_uint32 maj_stat, min_stat;
     gss_name_t         src_name, targ_name;
     gss_buffer_desc    sname, tname;
     OM_uint32          lifetime;
     gss_OID            mechanism, name_type;
     int                is_local;
     OM_uint32          context_flags;
     int                is_open;
     gss_qop_t          qop_state;
     gss_OID_set        mech_names;
     gss_buffer_desc    oid_name;
     size_t     i;

     /* Open connection */
     if ((s = connect_to_server(host, port)) < 0)
          return -1;

     /* Establish context */
     if (client_establish_context(s, service_name, req_flag,  oid,
         &context, &ret_flags) < 0) {
         (void) close(s);
         return -1;
     }

     /* display the flags */
     display_ctx_flags(ret_flags);

     /* Get context information */
     maj_stat = gss_inquire_context(&min_stat, context,
                                    &src_name, &targ_name, &lifetime,
                                    &mechanism, &context_flags,
                                    &is_local,
                                    &is_open);
     if (maj_stat != GSS_S_COMPLETE) {
         display_status("inquiring context", maj_stat, min_stat);
         return -1;
     }

     maj_stat = gss_display_name(&min_stat, src_name, &sname,
                                 &name_type);
     if (maj_stat != GSS_S_COMPLETE) {
         display_status("displaying source name", maj_stat, min_stat);
         return -1;
     }
     maj_stat = gss_display_name(&min_stat, targ_name, &tname,
                                 (gss_OID *) NULL);
     if (maj_stat != GSS_S_COMPLETE) {
         display_status("displaying target name", maj_stat, min_stat);
         return -1;
     }
     fprintf(stderr, "\"%.*s\" to \"%.*s\", lifetime %d, flags %x, %s, %s\n",
             (int) sname.length, (char *) sname.value,
             (int) tname.length, (char *) tname.value, lifetime,
             context_flags,
             (is_local) ? "locally initiated" : "remotely initiated",
             (is_open) ? "open" : "closed");

     (void) gss_release_name(&min_stat, &src_name);
     (void) gss_release_name(&min_stat, &targ_name);
     (void) gss_release_buffer(&min_stat, &sname);
     (void) gss_release_buffer(&min_stat, &tname);

     maj_stat = gss_oid_to_str(&min_stat,
                               name_type,
                               &oid_name);
     if (maj_stat != GSS_S_COMPLETE) {
         display_status("converting oid->string", maj_stat, min_stat);
         return -1;
     }
     fprintf(stderr, "Name type of source name is %.*s.\n",
             (int) oid_name.length, (char *) oid_name.value);
     (void) gss_release_buffer(&min_stat, &oid_name);

     /* Now get the names supported by the mechanism */
     maj_stat = gss_inquire_names_for_mech(&min_stat,
                                           mechanism,
                                           &mech_names);
     if (maj_stat != GSS_S_COMPLETE) {
         display_status("inquiring mech names", maj_stat, min_stat);
         return -1;
     }

     maj_stat = gss_oid_to_str(&min_stat,
                               mechanism,
                               &oid_name);
     if (maj_stat != GSS_S_COMPLETE) {
         display_status("converting oid->string", maj_stat, min_stat);
         return -1;
     }
     fprintf(stderr, "Mechanism %.*s supports %ld names\n",
             (int) oid_name.length, (char *) oid_name.value,
             mech_names->count);
     (void) gss_release_buffer(&min_stat, &oid_name);

     for (i=0; i<mech_names->count; i++) {
         maj_stat = gss_oid_to_str(&min_stat,
                                   &mech_names->elements[i],
                                   &oid_name);
         if (maj_stat != GSS_S_COMPLETE) {
             display_status("converting oid->string", maj_stat, min_stat);
             return -1;
         }
         fprintf(stderr, "  %ld: %.*s\n", i,
                 (int) oid_name.length, (char *) oid_name.value);

         (void) gss_release_buffer(&min_stat, &oid_name);
     }
     (void) gss_release_oid_set(&min_stat, &mech_names);

     if (use_file) {
         read_file(msg, &in_buf);
     } else {
         /* Seal the message */
         in_buf.value = msg;
         in_buf.length = strlen(msg);
     }

     maj_stat = gss_wrap(&min_stat, context, seal ? 1 : 0, GSS_C_QOP_DEFAULT,
                         &in_buf, &state, &out_buf);
     if (maj_stat != GSS_S_COMPLETE) {
          display_status("sealing message", maj_stat, min_stat);
          (void) close(s);
          (void) gss_delete_sec_context(&min_stat, &context, 
              GSS_C_NO_BUFFER);
          return -1;
     } else if (! state) {
          fprintf(stderr, "Warning!  Message not encrypted.\n");
     }

     /* Send to server */
     if (send_token(s, &out_buf) < 0) {
          (void) close(s);
          (void) gss_delete_sec_context(&min_stat, &context, GSS_C_NO_BUFFER);
          return -1;
     }
     (void) gss_release_buffer(&min_stat, &out_buf);

     /* Read signature block into out_buf */
     if (recv_token(s, &out_buf) < 0) {
          (void) close(s);
          (void) gss_delete_sec_context(&min_stat, &context, GSS_C_NO_BUFFER);
          return -1;
     }

     /* Verify signature block */
     maj_stat = gss_verify_mic(&min_stat, context, &in_buf,
                               &out_buf, &qop_state);
     if (maj_stat != GSS_S_COMPLETE) {
          display_status("verifying signature", maj_stat, min_stat);
          (void) close(s);
          (void) gss_delete_sec_context(&min_stat, &context, GSS_C_NO_BUFFER);
          return -1;
     }
     (void) gss_release_buffer(&min_stat, &out_buf);

     if (use_file)
         free(in_buf.value);

     printf("Signature verified.\n");

     /* Delete context */
     maj_stat = gss_delete_sec_context(&min_stat, &context, &out_buf);
     if (maj_stat != GSS_S_COMPLETE) {
          display_status("deleting context", maj_stat, min_stat);
          (void) close(s);
          (void) gss_delete_sec_context(&min_stat, &context, GSS_C_NO_BUFFER);
          return -1;
     }

     (void) gss_release_buffer(&min_stat, &out_buf);
     (void) close(s);
     return 0;
}

static void parse_oid(char *mechanism, gss_OID *oid)
{
    char        *mechstr = 0, *cp;
    gss_buffer_desc tok;
    OM_uint32 maj_stat, min_stat;
    
    if (isdigit(mechanism[0])) {
        mechstr = malloc(strlen(mechanism)+5);
        if (!mechstr) {
            printf("Couldn't allocate mechanism scratch!\n");
            return;
        }
        sprintf(mechstr, "{ %s }", mechanism);
        for (cp = mechstr; *cp; cp++)
            if (*cp == '.')
                *cp = ' ';
        tok.value = mechstr;
    } else
        tok.value = mechanism;
    tok.length = strlen(tok.value);
    maj_stat = gss_str_to_oid(&min_stat, &tok, oid);
    if (maj_stat != GSS_S_COMPLETE) {
        display_status("str_to_oid", maj_stat, min_stat);
        return;
    }
    if (mechstr)
        free(mechstr);
}

int main(argc, argv)
     int argc;
     char **argv;
{
     char *service_name, *server_host, *msg;
     char *mechanism = 0;
     u_short port = 4444;
     int use_file = 0;
     bool seal = false;
     OM_uint32 req_flags = 0, min_stat;
     gss_OID oid = GSS_C_NULL_OID;
     
     display_file = stdout;

     /* Parse arguments. */
     argc--; argv++;
     while (argc) {
          if (strcmp(*argv, "-port") == 0) {
               argc--; argv++;
               if (!argc) usage();
               port = atoi(*argv);
          } else if (strcmp(*argv, "-mech") == 0) {
               argc--; argv++;
               if (!argc) usage();
               mechanism = *argv;
          } else if (strcmp(*argv, "-d") == 0) {
               req_flags |= GSS_C_DELEG_FLAG;
          } else if (strcmp(*argv, "-f") == 0) {
               use_file = 1;
          } else if (strcmp(*argv, "-seal") == 0) {
               seal = true;
          } else if (strcmp(*argv, "-mutual") == 0) {
               req_flags |= GSS_C_MUTUAL_FLAG;
          } else 
               break;
          argc--; argv++;
     }
     if (argc != 3)
          usage();

     server_host = *argv++;
     service_name = *argv++;
     msg = *argv++;

     if (mechanism)
         parse_oid(mechanism, &oid);

     if (call_server(server_host, port, oid, service_name,
                     req_flags, msg, use_file, seal) < 0)
          exit(1);

     if (oid != GSS_C_NULL_OID)
         (void) gss_release_oid(&min_stat, &oid);
         
     return 0;
}