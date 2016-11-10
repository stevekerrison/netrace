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

%extend nt_packet {
    PyObject* GetDeps() {
        PyObject *l = PyList_New($self->num_deps);
        for (int i = 0; i < $self->num_deps; i++) {
            PyObject *o = PyInt_FromLong($self->deps[i]);
            PyList_SetItem(l, i, o);
        }
        return l;
    }
    
    const char* GetType( void ) {
        return nt_packet_type_to_string( $self );
    }

    %pythoncode %{
        __swig_getmethods__["type_str"] = GetType
        __swig_getmethods__["deps_list"] = GetDeps
    %}
};
