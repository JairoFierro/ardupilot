#pragma once
#include <stdint.h>
#include "mavlink/v2.0/common/mavlink.h"  // o el include MAVLink que ya uses

// Devuelve true si el tag verifica y deja el payload en claro (msg->len queda sin el tag).
bool ascon_decrypt_msg_payload_inplace(mavlink_message_t* msg);