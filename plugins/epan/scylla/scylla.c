/* scylla.c
 *
 * Scylla RPC dissector
 * Piotr Sarna <sarna@scylladb.com> <p.sarna@tlen.pl>
 * Copyright (C) 2020 ScyllaDB
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "config.h"
#include <epan/dissectors/packet-tcp.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <stdint.h>

#define SCYLLA_PORT 7000

struct __attribute__((__packed__)) scylla_header {
    uint64_t timeout_in_ms; // - only if timeout is negotiated, but in Scylla it is
    uint64_t verb_type;
    int64_t msg_id;
    uint32_t len;
};

struct __attribute__((__packed__)) scylla_response {
    uint64_t msg_id;
    uint32_t len;
};

struct __attribute__((__packed__)) scylla_negotiation {
    uint64_t magic;
    uint32_t len;
};

static int proto_scylla = -1;

static int hf_scylla_timeout = -1;
static int hf_scylla_verb = -1;
static int hf_scylla_msg_id = -1;
static int hf_scylla_len = -1;
static int hf_scylla_response_size = -1;
static int hf_scylla_negotiation_size = -1;
static int hf_scylla_payload = -1; // TODO: dissect everything, so that generic "payload" is not needed

// Mutation
static int hf_scylla_mut_size1 = -1;
static int hf_scylla_mut_size2 = -1;
static int hf_scylla_mut_table_id = -1;
static int hf_scylla_mut_schema_id = -1;
static int hf_scylla_mut_len_pkeys = -1;
static int hf_scylla_mut_num_pkeys = -1;
static int hf_scylla_mut_len_pkey = -1;
static int hf_scylla_mut_pkey = -1;

// Read data
static int hf_scylla_read_data_timeout = -1;
static int hf_scylla_read_data_table_id = -1;
static int hf_scylla_read_data_schema_version = -1;

static gint ett_scylla = -1;
static gint ett_scylla_header = -1;
static gint ett_scylla_response = -1;
static gint ett_scylla_negotiation = -1;
static gint ett_scylla_mut = -1;
static gint ett_scylla_pkey = -1;
static gint ett_scylla_read_data = -1;
static gint ett_scylla_read_command = -1;

static gboolean scylla_desegment = TRUE;

enum scylla_packets {
    CLIENT_ID = 0,
    MUTATION = 1,
    MUTATION_DONE = 2,
    READ_DATA = 3,
    READ_MUTATION_DATA = 4,
    READ_DIGEST = 5,
    // Used by gossip
    GOSSIP_DIGEST_SYN = 6,
    GOSSIP_DIGEST_ACK = 7,
    GOSSIP_DIGEST_ACK2 = 8,
    GOSSIP_ECHO = 9,
    GOSSIP_SHUTDOWN = 10,
    // end of gossip verb
    DEFINITIONS_UPDATE = 11,
    TRUNCATE = 12,
    REPLICATION_FINISHED = 13,
    MIGRATION_REQUEST = 14,
    // Used by streaming
    PREPARE_MESSAGE = 15,
    PREPARE_DONE_MESSAGE = 16,
    STREAM_MUTATION = 17,
    STREAM_MUTATION_DONE = 18,
    COMPLETE_MESSAGE = 19,
    // end of streaming verbs
    REPAIR_CHECKSUM_RANGE = 20,
    GET_SCHEMA_VERSION = 21,
    SCHEMA_CHECK = 22,
    COUNTER_MUTATION = 23,
    MUTATION_FAILED = 24,
    STREAM_MUTATION_FRAGMENTS = 25,
    REPAIR_ROW_LEVEL_START = 26,
    REPAIR_ROW_LEVEL_STOP = 27,
    REPAIR_GET_FULL_ROW_HASHES = 28,
    REPAIR_GET_COMBINED_ROW_HASH = 29,
    REPAIR_GET_SYNC_BOUNDARY = 30,
    REPAIR_GET_ROW_DIFF = 31,
    REPAIR_PUT_ROW_DIFF = 32,
    REPAIR_GET_ESTIMATED_PARTITIONS= 33,
    REPAIR_SET_ESTIMATED_PARTITIONS= 34,
    REPAIR_GET_DIFF_ALGORITHMS = 35,
    REPAIR_GET_ROW_DIFF_WITH_RPC_STREAM = 36,
    REPAIR_PUT_ROW_DIFF_WITH_RPC_STREAM = 37,
    REPAIR_GET_FULL_ROW_HASHES_WITH_RPC_STREAM = 38,
    PAXOS_PREPARE = 39,
    PAXOS_ACCEPT = 40,
    PAXOS_LEARN = 41,
    HINT_MUTATION = 42,
    LAST = 43,
};

static const value_string packettypenames[] = {
        {CLIENT_ID, "CLIENT_ID"},
        {MUTATION, "MUTATION"},
        {MUTATION_DONE, "MUTATION_DONE"},
        {READ_DATA, "READ_DATA"},
        {READ_MUTATION_DATA, "READ_MUTATION_DATA"},
        {READ_DIGEST, "READ_DIGEST"},
        {GOSSIP_DIGEST_SYN, "GOSSIP_DIGEST_SYN"},
        {GOSSIP_DIGEST_ACK, "GOSSIP_DIGEST_ACK"},
        {GOSSIP_DIGEST_ACK2, "GOSSIP_DIGEST_ACK2"},
        {GOSSIP_ECHO, "GOSSIP_ECHO"},
        {GOSSIP_SHUTDOWN, "GOSSIP_SHUTDOWN"},
        {DEFINITIONS_UPDATE, "DEFINITIONS_UPDATE"},
        {TRUNCATE, "TRUNCATE"},
        {REPLICATION_FINISHED, "REPLICATION_FINISHED"},
        {MIGRATION_REQUEST, "MIGRATION_REQUEST"},
        {PREPARE_MESSAGE, "PREPARE_MESSAGE"},
        {PREPARE_DONE_MESSAGE, "PREPARE_DONE_MESSAGE"},
        {STREAM_MUTATION, "STREAM_MUTATION"},
        {STREAM_MUTATION_DONE, "STREAM_MUTATION_DONE"},
        {COMPLETE_MESSAGE, "COMPLETE_MESSAGE"},
        {REPAIR_CHECKSUM_RANGE, "REPAIR_CHECKSUM_RANGE"},
        {GET_SCHEMA_VERSION, "GET_SCHEMA_VERSION"},
        {SCHEMA_CHECK, "SCHEMA_CHECK"},
        {COUNTER_MUTATION, "COUNTER_MUTATION"},
        {MUTATION_FAILED, "MUTATION_FAILED"},
        {STREAM_MUTATION_FRAGMENTS, "STREAM_MUTATION_FRAGMENTS"},
        {REPAIR_ROW_LEVEL_START, "REPAIR_ROW_LEVEL_START"},
        {REPAIR_ROW_LEVEL_STOP, "REPAIR_ROW_LEVEL_STOP"},
        {REPAIR_GET_FULL_ROW_HASHES, "REPAIR_GET_FULL_ROW_HASHES"},
        {REPAIR_GET_COMBINED_ROW_HASH, "REPAIR_GET_COMBINED_ROW_HASH"},
        {REPAIR_GET_SYNC_BOUNDARY, "REPAIR_GET_SYNC_BOUNDARY"},
        {REPAIR_GET_ROW_DIFF, "REPAIR_GET_ROW_DIFF"},
        {REPAIR_PUT_ROW_DIFF, "REPAIR_PUT_ROW_DIFF"},
        {REPAIR_GET_ESTIMATED_PARTITIONS, "REPAIR_GET_ESTIMATED_PARTITIONS"},
        {REPAIR_SET_ESTIMATED_PARTITIONS, "REPAIR_SET_ESTIMATED_PARTITIONS"},
        {REPAIR_GET_DIFF_ALGORITHMS, "REPAIR_GET_DIFF_ALGORITHMS"},
        {REPAIR_GET_ROW_DIFF_WITH_RPC_STREAM, "REPAIR_GET_ROW_DIFF_WITH_RPC_STREAM"},
        {REPAIR_PUT_ROW_DIFF_WITH_RPC_STREAM, "REPAIR_PUT_ROW_DIFF_WITH_RPC_STREAM"},
        {REPAIR_GET_FULL_ROW_HASHES_WITH_RPC_STREAM, "REPAIR_GET_FULL_ROW_HASHES_WITH_RPC_STREAM"},
        {PAXOS_PREPARE, "PAXOS_PREPARE"},
        {PAXOS_ACCEPT, "PAXOS_ACCEPT"},
        {PAXOS_LEARN, "PAXOS_LEARN"},
        {HINT_MUTATION, "HINT_MUTATION"},
};

// Small static cache for translating msg_id to verbs.
// Useful when determining verb types for responses.
struct msg_id_cache_entry {
    guint64 msg_id;
    guint64 verb_type;
};
#define SCYLLA_MSG_ID_CACHE_SIZE 8
static struct msg_id_cache_entry msg_id_cache[SCYLLA_MSG_ID_CACHE_SIZE] = {};

void register_verb_for(guint64 msg_id, guint64 verb) {
    static int msg_id_cache_head = 0;
    msg_id_cache[msg_id_cache_head].msg_id = msg_id;
    msg_id_cache[msg_id_cache_head].verb_type = verb;
    msg_id_cache_head = (msg_id_cache_head + 1) % SCYLLA_MSG_ID_CACHE_SIZE;
}

guint64 lookup_verb_for(guint64 msg_id) {
    guint64 verb = LAST;
    for (unsigned i = 0; i < SCYLLA_MSG_ID_CACHE_SIZE; ++i) {
        if (msg_id_cache[i].msg_id == msg_id) {
            verb = msg_id_cache[i].verb_type;
        }
    }
    return verb;
}

static gboolean
looks_like_rpc_negotiation(const char *buf) {
    return memcmp(buf, "SSTARRPC", 8) == 0;
}

static gboolean
looks_like_response(guint64 verb_type, guint32 len) {
    return verb_type > LAST || len > 64*1024*1024;
}

static guint
get_scylla_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    guint64 verb_type = tvb_get_letoh64(tvb, offset + offsetof(struct scylla_header, verb_type));
    guint32 plen = tvb_get_letohl(tvb, offset + offsetof(struct scylla_header, len));
    if (looks_like_rpc_negotiation(tvb_get_ptr(tvb, offset, 8))) {
        return tvb_get_letohl(tvb, offset + offsetof(struct scylla_negotiation, len)) + sizeof(struct scylla_response);
    } else if (looks_like_response(verb_type, plen)) {
        return tvb_get_letohl(tvb, offset + offsetof(struct scylla_response, len)) + sizeof(struct scylla_response);
    }
    return plen + sizeof(struct scylla_header);
}

static int
dissect_scylla_negotiation_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *scylla_tree)
{
    gint offset = 0;

    proto_tree *scylla_negotiation_tree = proto_tree_add_subtree(scylla_tree, tvb, offset,
            sizeof(struct scylla_header), ett_scylla_negotiation, NULL, "Protocol negotiation");
    guint32 len = tvb_get_letohl(tvb, offset + offsetof(struct scylla_negotiation, len));
    gint negotiation_offset = 8;
    proto_tree_add_item(scylla_negotiation_tree, hf_scylla_negotiation_size, tvb, offset + negotiation_offset, 4, ENC_LITTLE_ENDIAN);
    negotiation_offset += 4;
    proto_tree_add_item(scylla_negotiation_tree, hf_scylla_payload, tvb, offset + negotiation_offset, len - negotiation_offset, ENC_NA);

    col_clear(pinfo->cinfo, COL_INFO);
    col_clear(pinfo->cinfo, COL_PROTOCOL);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Scylla");
    col_add_str(pinfo->cinfo, COL_INFO, "Protocol negotiation");
    return tvb_reported_length(tvb);
}

static int
dissect_scylla_response_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *scylla_tree)
{
    gint offset = 0;

    proto_tree *scylla_response_tree = proto_tree_add_subtree(scylla_tree, tvb, offset,
            sizeof(struct scylla_header), ett_scylla_response, NULL, "Response");
    gint resp_offset = 0;
    guint64 msg_id = tvb_get_letohl(tvb, offset + offsetof(struct scylla_response, msg_id));
    guint32 len = tvb_get_letohl(tvb, offset + offsetof(struct scylla_response, len));

    proto_tree_add_item(scylla_response_tree, hf_scylla_msg_id, tvb, offset + resp_offset, 8, ENC_LITTLE_ENDIAN);
    resp_offset += 8;
    proto_tree_add_item(scylla_response_tree, hf_scylla_response_size, tvb, offset + resp_offset, 4, ENC_LITTLE_ENDIAN);
    resp_offset += 4;
    proto_tree_add_item(scylla_response_tree, hf_scylla_payload, tvb, offset + resp_offset, len - resp_offset, ENC_NA);

    guint64 response_verb = lookup_verb_for(msg_id);

    col_clear(pinfo->cinfo, COL_INFO);
    col_clear(pinfo->cinfo, COL_PROTOCOL);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Scylla");
    col_add_fstr(pinfo->cinfo, COL_INFO, "response for %s",
            val_to_str(response_verb, packettypenames, "Unknown (0x%02x)"));
    return tvb_reported_length(tvb);
}

static int
dissect_scylla_msg_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *scylla_tree, proto_item *ti, guint64 verb_type, guint32 len)
{
    gint offset = 0;

    proto_tree *scylla_header_tree = proto_tree_add_subtree(scylla_tree, tvb, offset,
            sizeof(struct scylla_header), ett_scylla_header, NULL, "Header");

    proto_tree_add_item(scylla_header_tree, hf_scylla_timeout, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_item_append_text(ti, ", Type %s", val_to_str(verb_type, packettypenames, "Unknown (0x%02x)"));
    proto_tree_add_item(scylla_header_tree, hf_scylla_verb, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(scylla_header_tree, hf_scylla_msg_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(scylla_header_tree, hf_scylla_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    switch (verb_type) {
    case MUTATION: {
        proto_tree* scylla_mut_tree = proto_tree_add_subtree(scylla_tree, tvb, offset,
                sizeof(struct scylla_header), ett_scylla_pkey, NULL, "Mutation");
        gint mut_offset = 0;
        proto_tree_add_item(scylla_mut_tree, hf_scylla_mut_size1, tvb, offset + mut_offset, 4, ENC_LITTLE_ENDIAN);
        mut_offset += 4;
        proto_tree_add_item(scylla_mut_tree, hf_scylla_mut_size2, tvb, offset + mut_offset, 4, ENC_LITTLE_ENDIAN);
        mut_offset += 4;
        proto_tree_add_item(scylla_mut_tree, hf_scylla_mut_table_id, tvb, offset + mut_offset, 16, ENC_NA);
        mut_offset += 16;
        proto_tree_add_item(scylla_mut_tree, hf_scylla_mut_schema_id, tvb, offset + mut_offset, 16, ENC_NA);
        mut_offset += 16;
        proto_tree* scylla_pkey_tree = proto_tree_add_subtree(scylla_mut_tree, tvb, offset + mut_offset,
                sizeof(struct scylla_header), ett_scylla_pkey, NULL, "Partition key");
        proto_tree_add_item(scylla_pkey_tree, hf_scylla_mut_len_pkeys, tvb, offset + mut_offset, 4, ENC_LITTLE_ENDIAN);
        mut_offset += 4;
        guint32 num_keys = tvb_get_letohl(tvb, offset + mut_offset);
        proto_tree_add_item(scylla_pkey_tree, hf_scylla_mut_num_pkeys, tvb, offset + mut_offset, 4, ENC_LITTLE_ENDIAN);
        mut_offset += 4;
        for (guint32 i = 0; i < num_keys; ++i) {
            guint32 len_pkey = tvb_get_letohl(tvb, offset + mut_offset);
            proto_tree_add_item(scylla_pkey_tree, hf_scylla_mut_len_pkey, tvb, offset + mut_offset, 4, ENC_LITTLE_ENDIAN);
            mut_offset += 4;
            proto_tree_add_item(scylla_pkey_tree, hf_scylla_mut_pkey, tvb, offset + mut_offset, len_pkey, ENC_NA);
            mut_offset += len_pkey;
        }
        // TODO: dissect further
        proto_tree_add_item(scylla_mut_tree, hf_scylla_payload, tvb, offset + mut_offset, len - mut_offset, ENC_NA);
        }
        break;
    case READ_DATA: {
        proto_tree* scylla_read_tree = proto_tree_add_subtree(scylla_tree, tvb, offset,
                sizeof(struct scylla_header), ett_scylla_read_data, NULL, "Read data");
        gint rd_offset = 0;

        proto_tree_add_item(scylla_read_tree, hf_scylla_read_data_timeout, tvb, offset + rd_offset, 4, ENC_LITTLE_ENDIAN);
        rd_offset += 4;
        proto_tree* scylla_read_command_tree = proto_tree_add_subtree(scylla_read_tree, tvb, offset + rd_offset,
                sizeof(struct scylla_header), ett_scylla_read_command, NULL, "Read command");
        proto_tree_add_item(scylla_read_command_tree, hf_scylla_read_data_table_id, tvb, offset + rd_offset, 16, ENC_NA);
        rd_offset += 16;
        proto_tree_add_item(scylla_read_command_tree, hf_scylla_read_data_schema_version, tvb, offset + rd_offset, 16, ENC_NA);
        rd_offset += 16;

        //TODO: dissect further
        proto_tree_add_item(scylla_read_tree, hf_scylla_payload, tvb, offset + rd_offset, len - rd_offset, ENC_NA);
        }
        break;
    default:
        // Generic payload. TODO: dissect
        proto_tree_add_item(scylla_tree, hf_scylla_payload, tvb, offset, len, ENC_NA);
        break;
    }
    offset += len;

    col_clear(pinfo->cinfo, COL_INFO);
    col_clear(pinfo->cinfo, COL_PROTOCOL);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Scylla");
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
             val_to_str(verb_type, packettypenames, "Unknown (0x%02x)"));

    return tvb_reported_length(tvb);
}

static int
dissect_scylla_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    gint offset = 0;

    proto_item *ti = proto_tree_add_item(tree, proto_scylla, tvb, 0, -1, ENC_NA);
    proto_tree *scylla_tree = proto_item_add_subtree(ti, ett_scylla);

    guint64 verb_type = tvb_get_letoh64(tvb, offset + offsetof(struct scylla_header, verb_type));
    guint32 len = tvb_get_letohl(tvb, offset + offsetof(struct scylla_header, len));

    if (looks_like_rpc_negotiation(tvb_get_ptr(tvb, offset, 8))) {
        return dissect_scylla_negotiation_pdu(tvb, pinfo, scylla_tree);
    } else if (looks_like_response(verb_type, len)) {
        return dissect_scylla_response_pdu(tvb, pinfo, scylla_tree);
    }

    guint64 msg_id = tvb_get_letoh64(tvb, offset + offsetof(struct scylla_header, msg_id));
    register_verb_for(msg_id, verb_type);
    return dissect_scylla_msg_pdu(tvb, pinfo, scylla_tree, ti, verb_type, len);

}

static int
dissect_scylla(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, scylla_desegment, sizeof(struct scylla_header),
        get_scylla_pdu_len, dissect_scylla_pdu, data);
    return tvb_reported_length(tvb);
}

void
proto_register_scylla(void)
{
    static hf_register_info hf[] = {
        // RPC header
        { &hf_scylla_timeout, { "RPC timeout", "scylla.timeout", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_verb, { "verb", "scylla.verb", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_msg_id, { "msg id", "scylla.msg_id", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_len, { "packet length", "scylla.len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_payload, { "payload", "scylla.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_response_size, { "response size", "scylla.response.size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_negotiation_size, { "negotiation size", "scylla.negotiation.size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        // mutation verb
        { &hf_scylla_mut_size1, { "mutation size 1", "scylla.mut.size1", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_mut_size2, { "mutation size 2", "scylla.mut.size2", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_mut_table_id, { "mutation table id", "scylla.mut.table_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_mut_schema_id, { "mutation schema id", "scylla.mut.schema_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_mut_len_pkeys, { "size of partition keys payload", "scylla.mut.len_pkeys", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_mut_num_pkeys, { "number of partition keys", "scylla.mut.num_pkeys", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_mut_len_pkey, { "length of a partition key", "scylla.mut.len_pkey", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_mut_pkey, { "partition key", "scylla.mut.pkey", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        // read_data verb
        { &hf_scylla_read_data_timeout, { "timeout", "scylla.read_data.timeout", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_read_data_table_id, { "Table ID", "scylla.read_data.table_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_read_data_schema_version, { "Schema version", "scylla.read_data.schema_version", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_scylla,
        &ett_scylla_header,
        &ett_scylla_response,
        &ett_scylla_negotiation,
        &ett_scylla_mut,
        &ett_scylla_pkey,
        &ett_scylla_read_data,
        &ett_scylla_read_command
    };

    proto_scylla = proto_register_protocol("Scylla RPC protocol", "Scylla", "scylla");
    module_t* scylla_module = prefs_register_protocol(proto_scylla, NULL);
    prefs_register_bool_preference(scylla_module, "desegment",
        "Desegment all Scylla messages spanning multiple TCP segments",
        "Whether Scylla dissector should desegment all messages spanning multiple TCP segments",
        &scylla_desegment);

    proto_register_field_array(proto_scylla, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_scylla(void)
{
    static dissector_handle_t scylla_handle;

    scylla_handle = create_dissector_handle(dissect_scylla, proto_scylla);
    dissector_add_uint_with_preference("tcp.port", SCYLLA_PORT, scylla_handle);
}
