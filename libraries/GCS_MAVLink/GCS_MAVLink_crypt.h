#pragma once
#include <stdint.h>

// Devuelve true si el tag verifica y deja el payload en claro (msg->len queda sin el tag).
struct __mavlink_message;
typedef __mavlink_message mavlink_message_t;

#ifdef AP_MAVLINK_ENCRYPT
bool ascon_encrypt_msg_payload_inplace(mavlink_message_t* msg);
bool ascon_decrypt_msg_payload_inplace(mavlink_message_t* msg);
#endif