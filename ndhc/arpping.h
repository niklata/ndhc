#ifndef ARPPING_H_
#define ARPPING_H_

int arpping(uint32_t test_nip, const uint8_t *safe_mac, uint32_t from_ip,
            uint8_t *from_mac, const char *interface);


#endif /* ARPPING_H_ */
