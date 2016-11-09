/* File: netrace.i */
%module netrace

%{
#define SWIG_FILE_WITH_INIT
#include "netrace.h"
%}

%include "netrace.h"

%inline %{

nt_context_t* open(char * filename) {
    nt_context_t* ctx = calloc( 1, sizeof(nt_context_t) );
    nt_open_trfile( ctx, filename );
    return ctx;
}

%}

%extend nt_context {
    nt_context( char * filename ) {
        nt_context_t* ctx = calloc( 1, sizeof(nt_context_t) );
        nt_open_trfile( ctx, filename );
        return ctx;
    }
    
    ~nt_context() {
    }
    
    void close( void ) {
        nt_close_trfile( $self );
    }
    
    nt_packet_t* read( void ) {
        return nt_read_packet( $self );
    }
};

