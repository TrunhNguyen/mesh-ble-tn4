#include "network.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <nrf_error.h>
#include "nrf_gpio.h"
#include "nrf_delay.h"
#include "nrf_mesh_config_core.h"
#include "nrf_mesh_config_bearer.h"
#include "mesh_opt_core.h"
#include "msg_cache.h"
#include "transport.h"
#include "nrf_mesh_assert.h"
#include "net_beacon.h"
#include "net_state.h"
#include "utils.h"
#include "internal_event.h"
#include "nrf_mesh_utils.h"
#include "nrf_mesh_externs.h"
#include "packet_mesh.h"
#include "core_tx.h"
#include "core_tx_adv.h"
#include "core_tx_instaburst.h"
#include "heartbeat.h"
#include "enc.h"
#include "log.h"
#include "SEGGER_RTT.h"
#if MESH_FEATURE_GATT_PROXY_ENABLED
#include "proxy.h"
#endif
#if MESH_FEATURE_FRIEND_ENABLED
#include "friend_internal.h"
#endif
#if MESH_FEATURE_LPN_ENABLED
#include "mesh_lpn.h"
#endif

extern volatile uint8_t g_dbg_rx_mac_left;
extern void exp_trig_begin(void);
extern void exp_trig_end(uint8_t pulses);
#define EXP_TRIG_FWD_PULSES 2

extern bool exp_packet_allow(const uint8_t * p_adv_addr, uint8_t adv_type);
extern bool exp_packet_is_neighbor_echo(const uint8_t * p_adv_addr, uint8_t adv_type);
extern void offline_log_push_relay(uint16_t src, uint16_t dst, uint32_t net_seq, uint8_t ttl_tx, uint8_t ttl_rx, int8_t rssi);
extern void offline_log_on_drop_cache(uint16_t src, uint32_t net_seq, uint8_t ttl_rx, int8_t rssi);

static nrf_mesh_relay_check_cb_t m_relay_check_cb;

static inline uint32_t m_core_tx_buffer_size_get(const network_packet_metadata_t * p_net_metadata, uint32_t payload_len)
{
    return PACKET_MESH_NET_PDU_OFFSET + payload_len +
           net_packet_mic_size_get(p_net_metadata->control_packet);
}

static uint32_t allocate_packet(network_tx_packet_buffer_t * p_buffer)
{
    packet_mesh_net_packet_t * p_net_packet;

    const core_tx_alloc_params_t alloc_params =
    {
        .role            = p_buffer->user_data.role,
        .net_packet_len  = m_core_tx_buffer_size_get(p_buffer->user_data.p_metadata,
                                                     p_buffer->user_data.payload_len),
        .p_metadata      = p_buffer->user_data.p_metadata,
        .token           = p_buffer->user_data.token,
        .bearer_selector = p_buffer->user_data.bearer_selector,
    };

    if (core_tx_packet_alloc(&alloc_params, (uint8_t **) &p_net_packet) != 0)
    {
#if MESH_FEATURE_RELAY_ENABLED || MESH_FEATURE_FRIEND_ENABLED
        if (p_buffer->user_data.role != CORE_TX_ROLE_RELAY)
#endif
        {
            uint32_t status = net_state_iv_index_and_seqnum_alloc(
                    &p_buffer->user_data.p_metadata->internal.iv_index,
                    &p_buffer->user_data.p_metadata->internal.sequence_number);

            if (status != NRF_SUCCESS)
            {
                core_tx_packet_discard();
                return status;
            }
        }
        net_packet_header_set(p_net_packet, p_buffer->user_data.p_metadata);
        p_buffer->p_payload = (uint8_t *) packet_mesh_net_payload_get(p_net_packet);
        return NRF_SUCCESS;
    }
    else
    {
        return NRF_ERROR_NO_MEM;
    }
}

#if MESH_FEATURE_RELAY_ENABLED
static uint32_t packet_relay(network_packet_metadata_t *    p_net_metadata,
                             const uint8_t *                p_net_payload,
                             uint8_t                        payload_len,
                             const nrf_mesh_rx_metadata_t * p_rx_metadata)
{
    const uint8_t ttl_rx = p_net_metadata->ttl;
    p_net_metadata->ttl--;

    network_tx_packet_buffer_t buffer;
    buffer.user_data.p_metadata = p_net_metadata;
    buffer.user_data.payload_len = payload_len;
    buffer.user_data.token = NRF_MESH_RELAY_TOKEN;
    buffer.user_data.bearer_selector = CORE_TX_BEARER_TYPE_ALLOW_ALL ^ CORE_TX_BEARER_TYPE_LOCAL;
    buffer.user_data.role = CORE_TX_ROLE_RELAY;

#if MESH_FEATURE_GATT_PROXY_ENABLED
    if (p_rx_metadata->source != NRF_MESH_RX_SOURCE_GATT && !proxy_is_enabled())
    {
        buffer.user_data.bearer_selector ^= CORE_TX_BEARER_TYPE_GATT_SERVER;
    }
#else
    UNUSED_PARAMETER(p_rx_metadata);
#endif

    uint32_t status = allocate_packet(&buffer);

    if (status == NRF_SUCCESS)
    {
        exp_trig_begin();
        memcpy(buffer.p_payload, p_net_payload, payload_len);
        network_packet_send(&buffer);
        __INTERNAL_EVENT_PUSH(INTERNAL_EVENT_PACKET_RELAYED, 0, payload_len, p_net_payload);
        exp_trig_end(EXP_TRIG_FWD_PULSES);

        int8_t rx_rssi = 0;
        if (p_rx_metadata != NULL && p_rx_metadata->source == NRF_MESH_RX_SOURCE_SCANNER)
        {
            rx_rssi = p_rx_metadata->params.scanner.rssi;
        }
        offline_log_push_relay(p_net_metadata->src,
                               p_net_metadata->dst.value,
                               p_net_metadata->internal.sequence_number,
                               p_net_metadata->ttl,
                               ttl_rx,
                               rx_rssi);
    }
    else
    {
        __LOG(LOG_SRC_NETWORK, LOG_LEVEL_WARN, "Unable to allocate memory for relay packet.\n");
    }

    p_net_metadata->ttl++;
    return status;
}
#endif

static bool metadata_is_valid(const network_packet_metadata_t * p_net_metadata)
{
    NRF_MESH_ASSERT(p_net_metadata != NULL);

    return (p_net_metadata->dst.type != NRF_MESH_ADDRESS_TYPE_INVALID &&
            p_net_metadata->internal.sequence_number <= NETWORK_SEQNUM_MAX &&
            !(p_net_metadata->control_packet && p_net_metadata->dst.type == NRF_MESH_ADDRESS_TYPE_VIRTUAL) &&
            p_net_metadata->ttl <= NRF_MESH_TTL_MAX);
}

#if MESH_FEATURE_RELAY_ENABLED
static bool should_relay(const network_packet_metadata_t * p_metadata,
                         const nrf_mesh_rx_metadata_t * p_rx_metadata)
{
    nrf_mesh_address_t dummy_addr;
    if (nrf_mesh_rx_address_get(p_metadata->src, &dummy_addr))
    {
        return false;
    }

#if EXPERIMENTAL_INSTABURST_ENABLED
    if (!core_tx_instaburst_is_enabled(CORE_TX_ROLE_RELAY))
#else
    if (!core_tx_adv_is_enabled(CORE_TX_ROLE_RELAY))
#endif
    {
        return false;
    }

    if (p_metadata->ttl < 2)
    {
        return false;
    }

    if (p_metadata->dst.type == NRF_MESH_ADDRESS_TYPE_UNICAST)
    {
        if (nrf_mesh_rx_address_get(p_metadata->dst.value, &dummy_addr))
        {
            return false;
        }
    }

#if MESH_FEATURE_GATT_PROXY_ENABLED
    if (p_rx_metadata->source == NRF_MESH_RX_SOURCE_GATT && !proxy_is_enabled())
    {
        return false;
    }
#endif

    if (m_relay_check_cb != NULL)
    {
        if (!m_relay_check_cb(p_metadata->src, p_metadata->dst.value, p_metadata->ttl))
        {
            return false;
        }
    }
    return true;
}
#endif

void network_init(const nrf_mesh_init_params_t * p_init_params)
{
    if (p_init_params == NULL)
    {
        m_relay_check_cb = NULL;
    }
    else
    {
        m_relay_check_cb = p_init_params->relay_cb;
    }

    net_state_init();
    net_beacon_init();
}

void network_enable(void)
{
    net_state_enable();
#if !MESH_FEATURE_LPN_ENABLED || MESH_FEATURE_LPN_ACT_AS_REGULAR_NODE_OUT_OF_FRIENDSHIP
    net_beacon_enable();
#endif
}

uint32_t network_packet_alloc(network_tx_packet_buffer_t * p_buffer)
{
    NRF_MESH_ASSERT(p_buffer != NULL);
    NRF_MESH_ASSERT(p_buffer->user_data.p_metadata != NULL);
    NRF_MESH_ASSERT(p_buffer->user_data.p_metadata->p_security_material != NULL);
    NRF_MESH_ASSERT(p_buffer->user_data.role < CORE_TX_ROLE_COUNT);
    NRF_MESH_ASSERT(p_buffer->user_data.bearer_selector != CORE_TX_BEARER_TYPE_INVALID);
    return allocate_packet(p_buffer);
}

void network_packet_send(const network_tx_packet_buffer_t * p_buffer)
{
    NRF_MESH_ASSERT(p_buffer != NULL);
    NRF_MESH_ASSERT(p_buffer->p_payload != NULL);
    NRF_MESH_ASSERT(p_buffer->user_data.p_metadata != NULL);
    NRF_MESH_ASSERT(p_buffer->user_data.p_metadata->p_security_material != NULL);

    packet_mesh_net_packet_t * p_net_packet = net_packet_from_payload(p_buffer->p_payload);
    __LOG_XB(LOG_SRC_NETWORK, LOG_LEVEL_DBG1, "Net TX", (const uint8_t *) p_net_packet, sizeof(packet_mesh_net_packet_t));
    net_packet_encrypt(p_buffer->user_data.p_metadata,
                       p_buffer->user_data.payload_len,
                       p_net_packet,
                       NET_PACKET_KIND_TRANSPORT);

    core_tx_packet_send();

    __INTERNAL_EVENT_PUSH(INTERNAL_EVENT_NET_PACKET_QUEUED_TX, 0, p_buffer->user_data.payload_len, p_buffer->p_payload);
}

void network_packet_discard(const network_tx_packet_buffer_t * p_buffer)
{
    NRF_MESH_ASSERT(p_buffer != NULL);
    NRF_MESH_ASSERT(p_buffer->p_payload != NULL);

    core_tx_packet_discard();
}

uint32_t network_packet_in(const uint8_t * p_packet, uint32_t net_packet_len, const nrf_mesh_rx_metadata_t * p_rx_metadata)
{
    if (p_packet == NULL)
    {
        return NRF_ERROR_NULL;
    }

    bool is_echo_only = false;
    int8_t rx_rssi = 0;

    if (p_rx_metadata != NULL && p_rx_metadata->source == NRF_MESH_RX_SOURCE_SCANNER)
    {
        rx_rssi = p_rx_metadata->params.scanner.rssi;

        #if EXP_DEBUG_RX_MAC
        if (g_dbg_rx_mac_left > 0)
        {
            const uint8_t * p_addr = p_rx_metadata->params.scanner.adv_addr.addr;
            SEGGER_RTT_printf(0, "# [RX_DEBUG_MAC] adv_addr: { 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X }\r\n",
                              p_addr[0], p_addr[1], p_addr[2], p_addr[3], p_addr[4], p_addr[5]);
            g_dbg_rx_mac_left--;
        }
        #endif

        if (!exp_packet_allow(p_rx_metadata->params.scanner.adv_addr.addr, 0x2A))
        {
            if (exp_packet_is_neighbor_echo(p_rx_metadata->params.scanner.adv_addr.addr, 0x2A))
            {
                is_echo_only = true;
            }
            else
            {
                return NRF_SUCCESS;
            }
        }
    }

    const packet_mesh_net_packet_t * p_net_packet = (const packet_mesh_net_packet_t *) p_packet;
    uint32_t status = NRF_SUCCESS;

    packet_mesh_net_packet_t net_decrypted_packet;

    memcpy(&net_decrypted_packet,
           p_net_packet,
           net_packet_obfuscation_start_get(p_net_packet) - (uint8_t *) p_net_packet);

    __LOG_XB(LOG_SRC_NETWORK, LOG_LEVEL_DBG1, "  Net RX (enc)", p_packet, net_packet_len);
    network_packet_metadata_t net_metadata;
    memset(&net_metadata, 0, sizeof(net_metadata));

    status = net_packet_decrypt(&net_metadata,
                                net_packet_len,
                                p_net_packet,
                                &net_decrypted_packet,
                                NET_PACKET_KIND_TRANSPORT);

    if (status == NRF_ERROR_NOT_FOUND &&
        net_metadata.src != NRF_MESH_ADDR_UNASSIGNED &&
        !net_metadata.control_packet &&
        msg_cache_entry_exists(net_metadata.src, net_metadata.internal.sequence_number))
    {
        offline_log_on_drop_cache(net_metadata.src,
                                  net_metadata.internal.sequence_number,
                                  net_metadata.ttl,
                                  rx_rssi);
        return NRF_SUCCESS;
    }

    if (is_echo_only)
    {
        return NRF_SUCCESS;
    }

    if ((status == NRF_SUCCESS) && metadata_is_valid(&net_metadata))
    {
        __LOG_XB(LOG_SRC_NETWORK, LOG_LEVEL_DBG1, "Net RX (unenc)", &net_decrypted_packet.pdu[0], net_packet_len);
        NRF_MESH_ASSERT(net_metadata.p_security_material != NULL);

#if MESH_FEATURE_GATT_PROXY_ENABLED
        proxy_net_packet_processed(&net_metadata, p_rx_metadata);
#endif

        const uint8_t * p_net_payload = packet_mesh_net_payload_get(&net_decrypted_packet);
        uint8_t payload_len = net_packet_payload_len_get(&net_metadata, net_packet_len);

        __INTERNAL_EVENT_PUSH(INTERNAL_EVENT_NET_PACKET_RECEIVED, 0, net_packet_len, &net_decrypted_packet);

        status = transport_packet_in((const packet_mesh_trs_packet_t *) p_net_payload,
                                     payload_len,
                                     &net_metadata,
                                     p_rx_metadata);

#if MESH_FEATURE_RELAY_ENABLED
#if MESH_FEATURE_FRIEND_ENABLED
        if (friend_friendship_established(net_metadata.src))
        {
            nrf_mesh_network_secmat_t * p_tx_secmat = nrf_mesh_net_master_secmat_get(net_metadata.p_security_material);
            if (p_tx_secmat != NULL)
            {
                net_metadata.p_security_material = p_tx_secmat;
            }
        }
#endif
        if (should_relay(&net_metadata, p_rx_metadata)
#if MESH_FEATURE_LPN_ENABLED
            && !mesh_lpn_is_in_friendship()
#endif
            )
        {
            if (packet_relay(&net_metadata, p_net_payload, payload_len, p_rx_metadata) == NRF_SUCCESS)
            {
                msg_cache_entry_add(net_metadata.src, net_metadata.internal.sequence_number);
            }
        }
        else
#endif
        {
            msg_cache_entry_add(net_metadata.src, net_metadata.internal.sequence_number);
        }
    }
    return status;
}

uint32_t network_opt_set(nrf_mesh_opt_id_t id, const nrf_mesh_opt_t * p_opt)
{
    if (p_opt == NULL)
    {
        return NRF_ERROR_NULL;
    }

    switch (id)
    {
#if MESH_FEATURE_RELAY_ENABLED
        case NRF_MESH_OPT_NET_RELAY_RETRANSMIT_INTERVAL_MS:
        {
            mesh_opt_core_adv_t cfg;
            NRF_MESH_ERROR_CHECK(mesh_opt_core_adv_get(CORE_TX_ROLE_RELAY, &cfg));
            cfg.tx_interval_ms = p_opt->opt.val;
            return mesh_opt_core_adv_set(CORE_TX_ROLE_RELAY, &cfg);
        }
        case NRF_MESH_OPT_NET_RELAY_ENABLE:
        {
            mesh_opt_core_adv_t cfg;
            NRF_MESH_ERROR_CHECK(mesh_opt_core_adv_get(CORE_TX_ROLE_RELAY, &cfg));
            cfg.enabled = (bool) p_opt->opt.val;
            return mesh_opt_core_adv_set(CORE_TX_ROLE_RELAY, &cfg);
        }
        case NRF_MESH_OPT_NET_RELAY_RETRANSMIT_COUNT:
        {
            mesh_opt_core_adv_t cfg;
            NRF_MESH_ERROR_CHECK(mesh_opt_core_adv_get(CORE_TX_ROLE_RELAY, &cfg));
            cfg.tx_count = p_opt->opt.val;
            return mesh_opt_core_adv_set(CORE_TX_ROLE_RELAY, &cfg);
        }
        case NRF_MESH_OPT_NET_RELAY_TX_POWER:
            return mesh_opt_core_tx_power_set(CORE_TX_ROLE_RELAY, (radio_tx_power_t) p_opt->opt.val);
#else
        case NRF_MESH_OPT_NET_RELAY_RETRANSMIT_INTERVAL_MS:
        case NRF_MESH_OPT_NET_RELAY_ENABLE:
        case NRF_MESH_OPT_NET_RELAY_RETRANSMIT_COUNT:
        case NRF_MESH_OPT_NET_RELAY_TX_POWER:
            return NRF_ERROR_NOT_FOUND;
#endif
        case NRF_MESH_OPT_NET_NETWORK_TRANSMIT_INTERVAL_MS:
        {
            mesh_opt_core_adv_t cfg;
            NRF_MESH_ERROR_CHECK(mesh_opt_core_adv_get(CORE_TX_ROLE_ORIGINATOR, &cfg));
            cfg.tx_interval_ms = p_opt->opt.val;
            return mesh_opt_core_adv_set(CORE_TX_ROLE_ORIGINATOR, &cfg);
        }
        case NRF_MESH_OPT_NET_NETWORK_TRANSMIT_COUNT:
        {
            mesh_opt_core_adv_t cfg;
            NRF_MESH_ERROR_CHECK(mesh_opt_core_adv_get(CORE_TX_ROLE_ORIGINATOR, &cfg));
            cfg.tx_count = p_opt->opt.val;
            return mesh_opt_core_adv_set(CORE_TX_ROLE_ORIGINATOR, &cfg);
        }
        case NRF_MESH_OPT_NET_NETWORK_TX_POWER:
            return mesh_opt_core_tx_power_set(CORE_TX_ROLE_ORIGINATOR, (radio_tx_power_t) p_opt->opt.val);
        default:
            return NRF_ERROR_NOT_FOUND;
    }
}

uint32_t network_opt_get(nrf_mesh_opt_id_t id, nrf_mesh_opt_t * p_opt)
{
    if (p_opt == NULL)
    {
        return NRF_ERROR_NULL;
    }

    switch (id)
    {
#if MESH_FEATURE_RELAY_ENABLED
        case NRF_MESH_OPT_NET_RELAY_RETRANSMIT_INTERVAL_MS:
        {
            mesh_opt_core_adv_t cfg;
            NRF_MESH_ERROR_CHECK(mesh_opt_core_adv_get(CORE_TX_ROLE_RELAY, &cfg));
            p_opt->opt.val = cfg.tx_interval_ms;
            p_opt->len = sizeof(p_opt->opt.val);
            break;
        }
        case NRF_MESH_OPT_NET_RELAY_ENABLE:
        {
            mesh_opt_core_adv_t cfg;
            NRF_MESH_ERROR_CHECK(mesh_opt_core_adv_get(CORE_TX_ROLE_RELAY, &cfg));
            p_opt->opt.val = cfg.enabled;
            p_opt->len = sizeof(p_opt->opt.val);
            break;
        }
        case NRF_MESH_OPT_NET_RELAY_RETRANSMIT_COUNT:
        {
            mesh_opt_core_adv_t cfg;
            NRF_MESH_ERROR_CHECK(mesh_opt_core_adv_get(CORE_TX_ROLE_RELAY, &cfg));
            p_opt->opt.val = cfg.tx_count;
            p_opt->len = sizeof(p_opt->opt.val);
            break;
        }
        case NRF_MESH_OPT_NET_RELAY_TX_POWER:
        {
            radio_tx_power_t tx_power;
            NRF_MESH_ERROR_CHECK(mesh_opt_core_tx_power_get(CORE_TX_ROLE_RELAY, &tx_power));
            p_opt->opt.val = tx_power;
            p_opt->len = sizeof(p_opt->opt.val);
            break;
        }
#else
        case NRF_MESH_OPT_NET_RELAY_RETRANSMIT_INTERVAL_MS:
        case NRF_MESH_OPT_NET_RELAY_ENABLE:
        case NRF_MESH_OPT_NET_RELAY_RETRANSMIT_COUNT:
        case NRF_MESH_OPT_NET_RELAY_TX_POWER:
            return NRF_ERROR_NOT_FOUND;
#endif
        case NRF_MESH_OPT_NET_NETWORK_TRANSMIT_INTERVAL_MS:
        {
            mesh_opt_core_adv_t cfg;
            NRF_MESH_ERROR_CHECK(mesh_opt_core_adv_get(CORE_TX_ROLE_ORIGINATOR, &cfg));
            p_opt->opt.val = cfg.tx_interval_ms;
            p_opt->len = sizeof(p_opt->opt.val);
            break;
        }
        case NRF_MESH_OPT_NET_NETWORK_TRANSMIT_COUNT:
        {
            mesh_opt_core_adv_t cfg;
            NRF_MESH_ERROR_CHECK(mesh_opt_core_adv_get(CORE_TX_ROLE_ORIGINATOR, &cfg));
            p_opt->opt.val = cfg.tx_count;
            p_opt->len = sizeof(p_opt->opt.val);
            break;
        }
        case NRF_MESH_OPT_NET_NETWORK_TX_POWER:
        {
            radio_tx_power_t tx_power;
            NRF_MESH_ERROR_CHECK(mesh_opt_core_tx_power_get(CORE_TX_ROLE_ORIGINATOR, &tx_power));
            p_opt->opt.val = tx_power;
            p_opt->len = sizeof(p_opt->opt.val);
            break;
        }
        default:
            break;
    }

    return NRF_SUCCESS;
}