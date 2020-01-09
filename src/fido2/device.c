#include "device.h"

#include <random.h>

/*
 * Get the AAGUID (identifier of the type of device authenticating).
 */
void device_read_aaguid(uint8_t * dst) {
    /*
     * Hack:
     * For now, return the AAGUID of a YubiKey 5 (USB-A, No NFC) - ee882879-721c-4913-9775-3dfcce97072a
     * See https://support.yubico.com/support/solutions/articles/15000028710-yubikey-hardware-fido2-aaguids
     */
    const char yubikey_aaguid[16] = {0xee, 0x88, 0x28, 0x79, 0x72, 0x1c, 0x49, 0x13, 0x97, 0x75, 0x3d, 0xfc, 0xce, 0x97, 0x07, 0x2a};
    memcpy(dst, yubikey_aaguid, 16);
}

int ctap_generate_rng(uint8_t* dst, size_t num) {
    /* Generate bytes in chunks of 4 into the destination buffer. */
    for (size_t i = 0; i < num; i += 4) {
        random_32_bytes(dst + i);
    }
    /* Generate the last N bytes as needed. */
    int bytes_missing = num % 4;
    if (bytes_missing) {
        int final_word_offset = num - bytes_missing;
        uint32_t last_bytes;
        random_32_bytes((uint8_t*)&last_bytes);
        memcpy(dst + final_word_offset, &last_bytes, bytes_missing);
    }
    return 1;
}

uint32_t ctap_atomic_count(uint32_t amount)
{
    /* TODO: increment the secure chip counter. */
    static uint32_t counter1 = 25;
    counter1 += (amount + 1);
    return counter1;
}

static  AuthenticatorState _tmp_state = {0};
int authenticator_read_state(AuthenticatorState * s){
    if (_tmp_state.is_initialized != INITIALIZED_MARKER){
        return 0;
    }
    else {
        memmove(s, &_tmp_state, sizeof(AuthenticatorState));
        return 1;
    }
}

void authenticator_write_state(AuthenticatorState * s){
    memmove(&_tmp_state, s, sizeof(AuthenticatorState));
}


void device_set_status(uint32_t status)
{
    (void)status;
}
bool _up_disabled = false;

int ctap_user_presence_test(uint32_t delay) {
    (void)delay;
    if (_up_disabled)
    {
        return 2;
    }
    return 1;
}

#define RK_NUM  50

struct ResidentKeyStore {
    CTAP_residentKey rks[RK_NUM];
} RK_STORE;

void ctap_load_rk(int index, CTAP_residentKey * rk)
{
    memmove(rk, RK_STORE.rks + index, sizeof(CTAP_residentKey));
}

void ctap_reset_rk(void)
{
    memset(&RK_STORE,0xff,sizeof(RK_STORE));
}

uint32_t ctap_rk_size(void)
{
    return RK_NUM;
}

void ctap_overwrite_rk(int index, CTAP_residentKey * rk)
{
    if (index < RK_NUM)
    {
        memmove(RK_STORE.rks + index, rk, sizeof(CTAP_residentKey));
    }
    else
    {
        printf1(TAG_ERR,"Out of bounds for store_rk\r\n");
    }
}

__attribute__((weak)) void ctap_store_rk(int index, CTAP_residentKey * rk)
{
    if (index < RK_NUM)
    {
        memmove(RK_STORE.rks + index, rk, sizeof(CTAP_residentKey));
    }
    else
    {
        printf1(TAG_ERR,"Out of bounds for store_rk\r\n");
    }

}
int device_is_nfc(void)
{
    return 0;
}

void device_wink(void)
{
    printf1(TAG_GREEN,"*WINK*\n");
}

void device_set_clock_rate(DEVICE_CLOCK_RATE param)
{
    (void)param;
}
static uint8_t _attestation_cert_der[] =
"\x30\x82\x01\xfb\x30\x82\x01\xa1\xa0\x03\x02\x01\x02\x02\x01\x00\x30\x0a\x06\x08"
"\x2a\x86\x48\xce\x3d\x04\x03\x02\x30\x2c\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13"
"\x02\x55\x53\x31\x0b\x30\x09\x06\x03\x55\x04\x08\x0c\x02\x4d\x44\x31\x10\x30\x0e"
"\x06\x03\x55\x04\x0a\x0c\x07\x54\x45\x53\x54\x20\x43\x41\x30\x20\x17\x0d\x31\x38"
"\x30\x35\x31\x30\x30\x33\x30\x36\x32\x30\x5a\x18\x0f\x32\x30\x36\x38\x30\x34\x32"
"\x37\x30\x33\x30\x36\x32\x30\x5a\x30\x7c\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13"
"\x02\x55\x53\x31\x0b\x30\x09\x06\x03\x55\x04\x08\x0c\x02\x4d\x44\x31\x0f\x30\x0d"
"\x06\x03\x55\x04\x07\x0c\x06\x4c\x61\x75\x72\x65\x6c\x31\x15\x30\x13\x06\x03\x55"
"\x04\x0a\x0c\x0c\x54\x45\x53\x54\x20\x43\x4f\x4d\x50\x41\x4e\x59\x31\x22\x30\x20"
"\x06\x03\x55\x04\x0b\x0c\x19\x41\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x6f\x72"
"\x20\x41\x74\x74\x65\x73\x74\x61\x74\x69\x6f\x6e\x31\x14\x30\x12\x06\x03\x55\x04"
"\x03\x0c\x0b\x63\x6f\x6e\x6f\x72\x70\x70\x2e\x63\x6f\x6d\x30\x59\x30\x13\x06\x07"
"\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00"
"\x04\x45\xa9\x02\xc1\x2e\x9c\x0a\x33\xfa\x3e\x84\x50\x4a\xb8\x02\xdc\x4d\xb9\xaf"
"\x15\xb1\xb6\x3a\xea\x8d\x3f\x03\x03\x55\x65\x7d\x70\x3f\xb4\x02\xa4\x97\xf4\x83"
"\xb8\xa6\xf9\x3c\xd0\x18\xad\x92\x0c\xb7\x8a\x5a\x3e\x14\x48\x92\xef\x08\xf8\xca"
"\xea\xfb\x32\xab\x20\xa3\x62\x30\x60\x30\x46\x06\x03\x55\x1d\x23\x04\x3f\x30\x3d"
"\xa1\x30\xa4\x2e\x30\x2c\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31"
"\x0b\x30\x09\x06\x03\x55\x04\x08\x0c\x02\x4d\x44\x31\x10\x30\x0e\x06\x03\x55\x04"
"\x0a\x0c\x07\x54\x45\x53\x54\x20\x43\x41\x82\x09\x00\xf7\xc9\xec\x89\xf2\x63\x94"
"\xd9\x30\x09\x06\x03\x55\x1d\x13\x04\x02\x30\x00\x30\x0b\x06\x03\x55\x1d\x0f\x04"
"\x04\x03\x02\x04\xf0\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02\x03\x48\x00"
"\x30\x45\x02\x20\x18\x38\xb0\x45\x03\x69\xaa\xa7\xb7\x38\x62\x01\xaf\x24\x97\x5e"
"\x7e\x74\x64\x1b\xa3\x7b\xf7\xe6\xd3\xaf\x79\x28\xdb\xdc\xa5\x88\x02\x21\x00\xcd"
"\x06\xf1\xe3\xab\x16\x21\x8e\xd8\xc0\x14\xaf\x09\x4f\x5b\x73\xef\x5e\x9e\x4b\xe7"
"\x35\xeb\xdd\x9b\x6d\x8f\x7d\xf3\xc4\x3a\xd7";

void device_attestation_read_cert_der(uint8_t * dst) {
    memmove(dst, _attestation_cert_der, device_attestation_cert_der_get_size());
}

uint16_t device_attestation_cert_der_get_size(void) {
    return sizeof(_attestation_cert_der)-1;
}

void device_disable_up(bool disable)
{
    _up_disabled = disable;
}

uint8_t * device_get_attestation_key(void){
    static uint8_t attestation_key[] = 
        "\xcd\x67\xaa\x31\x0d\x09\x1e\xd1\x6e\x7e\x98\x92\xaa"
        "\x07\x0e\x19\x94\xfc\xd7\x14\xae\x7c\x40\x8f\xb9\x46"
        "\xb7\x2e\x5f\xe7\x5d\x30";
    return attestation_key;
}
