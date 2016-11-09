/* File: netrace.i */
%module netrace

%{
#define SWIG_FILE_WITH_INIT
#include "netrace.h"
%}

typedef unsigned int nt_dependency_t;
typedef struct nt_header nt_header_t;
typedef struct nt_regionhead nt_regionhead_t;
typedef struct nt_packet nt_packet_t;
typedef struct nt_dep_ref_node nt_dep_ref_node_t;
typedef struct nt_packet_list nt_packet_list_t;
typedef struct nt_context nt_context_t;

struct nt_header {
	unsigned int nt_magic;
	float version;
	char benchmark_name[NT_BMARK_NAME_LENGTH];
	unsigned char num_nodes;
	unsigned long long int num_cycles;
	unsigned long long int num_packets;
	unsigned int notes_length;  // Includes null-terminating char
	unsigned int num_regions;
	char* notes;
	nt_regionhead_t* regions;
};

struct nt_regionhead {
	unsigned long long int seek_offset;
	unsigned long long int num_cycles;
	unsigned long long int num_packets;
};

struct nt_packet {
	unsigned long long int cycle;
	unsigned int id;
	unsigned int addr;
	unsigned char type;
	unsigned char src;
	unsigned char dst;
	unsigned char node_types;
	unsigned char num_deps;
	nt_dependency_t* deps;
};

struct nt_dep_ref_node {
	nt_packet_t* node_packet;
	unsigned int packet_id;
	unsigned int ref_count;
	nt_dep_ref_node_t* next_node;
};

struct nt_packet_list {
	nt_packet_t* node_packet;
	nt_packet_list_t* next;
};

struct nt_context {
  char*	input_popencmd;
  FILE*	input_tracefile;
  char*	input_buffer;
  nt_header_t*	input_trheader;
  int	dependencies_off;
  int	self_throttling;
  int	primed_self_throttle;
  int	done_reading;
  unsigned long long int latest_active_packet_cycle;
  nt_dep_ref_node_t** dependency_array;
  unsigned long long int num_active_packets;
  nt_packet_list_t*	cleared_packets_list;
  nt_packet_list_t*	cleared_packets_list_tail;
  int track_cleared_packets_list;
};

// Interface Functions
void			nt_open_trfile( nt_context_t*, const char* );
void			nt_disable_dependencies( nt_context_t* );
void			nt_seek_region( nt_context_t*, nt_regionhead_t* );
nt_packet_t*		nt_read_packet( nt_context_t* );
int			nt_dependencies_cleared( nt_context_t*, nt_packet_t* );
void			nt_clear_dependencies_free_packet( nt_context_t*, nt_packet_t* );
void			nt_close_trfile( nt_context_t* );
void			nt_init_cleared_packets_list( nt_context_t* );
void			nt_init_self_throttling( nt_context_t* );
nt_packet_list_t*	nt_get_cleared_packets_list( nt_context_t* );
void			nt_empty_cleared_packets_list( nt_context_t* );

// Utility Functions
void			nt_print_trheader( nt_context_t* );
void			nt_print_packet( nt_packet_t* );
nt_header_t*		nt_get_trheader( nt_context_t* );
float			nt_get_trversion( nt_context_t* );
int			nt_get_src_type( nt_packet_t* );
int			nt_get_dst_type( nt_packet_t* );
const char* 		nt_node_type_to_string( int );
const char* 		nt_packet_type_to_string( nt_packet_t* );
int			nt_get_packet_size( nt_packet_t* );
