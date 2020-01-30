#include "config.h"
#include <epan/packet.h>

#define SCYLLA_PORT 7000

static int proto_scylla = -1;

static int hf_scylla_verb = -1;

static gint ett_scylla = -1;

static const value_string packettypenames[] = {
        {0, "CLIENT_ID"},
        {1, "MUTATION"},
        {2, "MUTATION_DONE"},
        {3, "READ_DATA"},
        {4, "READ_MUTATION_DATA"},
        {5, "READ_DIGEST"},
        {6, "GOSSIP_DIGEST_SYN"},
        {7, "GOSSIP_DIGEST_ACK"},
        {8, "GOSSIP_DIGEST_ACK2"},
        {9, "GOSSIP_ECHO"},
        {10, "GOSSIP_SHUTDOWN"},
        {11, "DEFINITIONS_UPDATE"},
        {12, "TRUNCATE"},
        {13, "REPLICATION_FINISHED"},
        {14, "MIGRATION_REQUEST"},
        {15, "PREPARE_MESSAGE"},
        {16, "PREPARE_DONE_MESSAGE"},
        {17, "STREAM_MUTATION"},
        {18, "STREAM_MUTATION_DONE"},
        {19, "COMPLETE_MESSAGE"},
        {20, "REPAIR_CHECKSUM_RANGE"},
        {21, "GET_SCHEMA_VERSION"},
        {22, "SCHEMA_CHECK"},
        {23, "COUNTER_MUTATION"},
        {24, "MUTATION_FAILED"},
        {25, "STREAM_MUTATION_FRAGMENTS"},
        {26, "REPAIR_ROW_LEVEL_START"},
        {27, "REPAIR_ROW_LEVEL_STOP"},
        {28, "REPAIR_GET_FULL_ROW_HASHES"},
        {29, "REPAIR_GET_COMBINED_ROW_HASH"},
        {30, "REPAIR_GET_SYNC_BOUNDARY"},
        {31, "REPAIR_GET_ROW_DIFF"},
        {32, "REPAIR_PUT_ROW_DIFF"},
        {33, "REPAIR_GET_ESTIMATED_PARTITIONS"},
        {34, "REPAIR_SET_ESTIMATED_PARTITIONS"},
        {35, "REPAIR_GET_DIFF_ALGORITHMS"},
        {36, "REPAIR_GET_ROW_DIFF_WITH_RPC_STREAM"},
        {37, "REPAIR_PUT_ROW_DIFF_WITH_RPC_STREAM"},
        {38, "REPAIR_GET_FULL_ROW_HASHES_WITH_RPC_STREAM"},
        {39, "PAXOS_PREPARE"},
        {40, "PAXOS_ACCEPT"},
        {41, "PAXOS_LEARN"},
        {42, "HINT_MUTATION"},
        {43, "LAST"}
};

static int
dissect_scylla(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint offset = 0;
    guint64 packet_type = tvb_get_letoh64(tvb, 0);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Scylla");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Type %s",
             val_to_str(packet_type, packettypenames, "Unknown (0x%02x)"));

    proto_item *ti = proto_tree_add_item(tree, proto_scylla, tvb, 0, -1, ENC_NA);
    proto_item_append_text(ti, ", Type %s",
        val_to_str(packet_type, packettypenames, "Unknown (0x%02x)"));
    proto_tree *scylla_tree = proto_item_add_subtree(ti, ett_scylla);
    proto_tree_add_item(scylla_tree, hf_scylla_verb, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    return tvb_captured_length(tvb);
}

void
proto_register_scylla(void)
{
    static hf_register_info hf[] = {
        { &hf_scylla_verb,
            { "Scylla verb", "scylla.verb",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_scylla
    };

    proto_scylla = proto_register_protocol("Scylla RPC protocol", "Scylla", "scl");

    proto_register_field_array(proto_scylla, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_scylla(void)
{
    static dissector_handle_t scylla_handle;

    scylla_handle = create_dissector_handle(dissect_scylla, proto_scylla);
    dissector_add_uint("tcp.port", SCYLLA_PORT, scylla_handle);
}
