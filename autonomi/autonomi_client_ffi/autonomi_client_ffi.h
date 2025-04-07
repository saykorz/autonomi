#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

void autonomi_free_string(char *ptr);

void autonomi_free_bytes(uint8_t *ptr, uintptr_t len);

/**
 * Initialize the client with default configuration.
 */
void *autonomi_client_init(void);

/**
 * Initialize a client that is configured to be local.
 */
void *autonomi_client_init_local(void);

/**
 * Initialize a client that bootstraps from a list of peers.
 * If any of the provided peers is a global address, the client will not be local.
 */
void *autonomi_client_init_with_peers(const char *const *peers_ptr, uintptr_t peers_len);

/**
 * Initialize the client with the given configuration.
 */
void *autonomi_client_init_with_config(void *config);

/**
 * Upload public data to the network.
 */
char *autonomi_client_data_put_public(void *client,
                                      const uint8_t *data,
                                      uintptr_t data_len,
                                      void *payment,
                                      char **out_cost,
                                      void **out_addr);

/**
 * Get public data from the network.
 */
uint8_t *autonomi_client_data_get_public(void *client, void *addr, uintptr_t *out_data_len);

/**
 * Upload a piece of private data to the network. This data will be self-encrypted.
 * The DataMapChunk is not uploaded to the network, keeping the data private.
 */
char *autonomi_client_data_put(void *client,
                               const uint8_t *data,
                               uintptr_t data_len,
                               void *payment,
                               char *out_cost,
                               void **out_data_map);

/**
 * Fetch a blob of (private) data from the network
 */
uint8_t *autonomi_client_data_get(void *client, void *data_map, uintptr_t *out_data_len);

/**
 * Get the estimated cost of storing a piece of data.
 */
char *autonomi_client_data_cost(void *client, const uint8_t *data, uintptr_t data_len);

/**
 * Upload a directory from the local file system to the network as a public archive.
 */
char *autonomi_client_dir_upload_public(void *client,
                                        const char *dir_path,
                                        void *payment,
                                        char *out_cost,
                                        void **out_addr);

/**
 * Download a public archive from the network to the local file system.
 */
char *autonomi_client_dir_download_public(void *client, void *addr, const char *dir_path);

/**
 * Upload a directory to the network. The directory is recursively walked and each file is uploaded to the network.
 * Returns, but does not upload, the PrivateArchive containing the data maps of the uploaded files.
 */
char *autonomi_client_dir_upload(void *client,
                                 const char *dir_path,
                                 void *payment,
                                 char *out_cost,
                                 void **out_data_map);

/**
 * Free a client instance
 */
void autonomi_client_free(void *client);

/**
 * Create a new network configuration.
 * If local is true, configures for local network connections.
 */
void *autonomi_network_new(bool local);

/**
 * Create a custom network
 */
void *autonomi_network_new_custom(const char *rpc_url,
                                  const char *payment_token_address,
                                  const char *data_payment_address);

/**
 * Get the default network (Arbitrum One)
 */
void *autonomi_network_default(void);

/**
 * Get the Arbitrum Sepolia network
 */
void *autonomi_network_arbitrum_sepolia(void);

/**
 * Free a Network instance
 */
void autonomi_network_free(void *network);

/**
 * Create a new wallet with a random key
 */
void *autonomi_wallet_new(void *network);

/**
 * Create a wallet from a private key
 */
void *autonomi_wallet_from_private_key(void *network, const char *private_key);

/**
 * Get the balance of a wallet
 */
char *autonomi_wallet_get_balance(void *wallet);

/**
 * Get the balance of gas tokens in a wallet
 */
char *autonomi_wallet_get_balance_of_gas(void *wallet);

/**
 * Get the address of a wallet
 */
char *autonomi_wallet_address(void *wallet);

/**
 * Get the network of a wallet
 */
void *autonomi_wallet_network(void *wallet);

/**
 * Generate a random private key
 */
char *autonomi_wallet_random_private_key(void);

/**
 * Transfer tokens from one wallet to another
 */
char *autonomi_wallet_transfer_tokens(void *wallet, const char *to_address, const char *amount);

/**
 * Free a Wallet instance
 */
void autonomi_wallet_free(void *wallet);

/**
 * Create a PaymentOption from a Wallet
 */
void *autonomi_payment_option_from_wallet(void *wallet);

/**
 * Free a PaymentOption instance
 */
void autonomi_payment_option_free(void *payment);

/**
 * Get the hex string representation of a DataAddress
 */
char *autonomi_data_address_to_hex(void *addr);

/**
 * Create a DataAddress from a hex string
 */
void *autonomi_data_address_from_hex(const char *hex);

/**
 * Free a DataAddress instance
 */
void autonomi_data_address_free(void *addr);

/**
 * Get the hex string representation of an ArchiveAddress
 */
char *autonomi_archive_address_to_hex(void *addr);

/**
 * Create an ArchiveAddress from a hex string
 */
void *autonomi_archive_address_from_hex(const char *hex);

/**
 * Free an ArchiveAddress instance
 */
void autonomi_archive_address_free(void *addr);

/**
 * Create a DataMapChunk from a hex string
 */
void *autonomi_data_map_chunk_from_hex(const char *hex);

/**
 * Get the hex string representation of a DataMapChunk
 */
char *autonomi_data_map_chunk_to_hex(void *chunk);

/**
 * Get the address of a DataMapChunk
 */
char *autonomi_data_map_chunk_address(void *chunk);

/**
 * Free a DataMapChunk instance
 */
void autonomi_data_map_chunk_free(void *chunk);

/**
 * Get the hex string representation of a PrivateArchiveDataMap
 */
char *autonomi_private_archive_data_map_to_hex(void *data_map);

/**
 * Create a PrivateArchiveDataMap from a hex string
 */
void *autonomi_private_archive_data_map_from_hex(const char *hex);

/**
 * Free a PrivateArchiveDataMap instance
 */
void autonomi_private_archive_data_map_free(void *data_map);
