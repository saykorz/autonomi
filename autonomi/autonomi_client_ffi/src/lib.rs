use std::{path::PathBuf, ffi::{c_char, CString, CStr}, os::raw::{c_void}};
use ruint::Uint;
use std::str::FromStr;
use std::ptr;
use autonomi_client::client::data::DataAddress;
use autonomi_client::client::files::archive_private::PrivateArchiveDataMap;
use autonomi_client::client::files::archive_public::ArchiveAddress;
use autonomi_client::pointer::PointerTarget;
use autonomi_client::{
    client::{
        chunk::DataMapChunk,
        payment::PaymentOption,
        vault::{UserData, VaultSecretKey},
    },
    files::{Metadata, PrivateArchive, PublicArchive},
    register::{RegisterAddress, RegisterHistory},
    Client, ClientConfig,
};
use autonomi_client::{Bytes, Network, Wallet};
use autonomi_client::{
    Chunk, ChunkAddress, GraphEntry, GraphEntryAddress, Pointer, PointerAddress, Scratchpad,
    ScratchpadAddress,
};

use blst::min_pk::{PublicKey, SecretKey};
use libp2p::Multiaddr;
use xor_name::XorName;

fn result_to_c_char<T, E: std::fmt::Display>(result: Result<T, E>, success_fn: impl FnOnce(T) -> String) -> *mut c_char {
    match result {
        Ok(value) => get_cost_string_from_string(success_fn(value)),
		Err(e) => get_cost_string_from_string(format!("ERROR: {}", e)),
    }
}

// Вътрешна функция, която приема String и връща *mut i8
#[no_mangle]
pub extern "C" fn get_cost_string_from_string(cost_str: String) -> *mut c_char {
    CString::new(cost_str).unwrap().into_raw()
}

// Helper to check if a string starts with "ERROR:"
fn is_error(result: *mut c_char) -> bool {
    unsafe {
        let c_str = CStr::from_ptr(result);
        let r_str = c_str.to_str().unwrap_or("");
        r_str.starts_with("ERROR:")
    }
}

// Free a C string allocated by Rust
#[no_mangle]
pub extern "C" fn autonomi_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

// Free a byte array allocated by Rust
#[no_mangle]
pub extern "C" fn autonomi_free_bytes(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(ptr, len, len);
        }
    }
}

// Client methods

/// Initialize the client with default configuration.
#[no_mangle]
pub extern "C" fn autonomi_client_init() -> *mut c_void {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let client_result = runtime.block_on(async {
        Client::init().await
    });
    
    match client_result {
        Ok(client) => Box::into_raw(Box::new(client)) as *mut c_void,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Initialize a client that is configured to be local.
#[no_mangle]
pub extern "C" fn autonomi_client_init_local() -> *mut c_void {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let client_result = runtime.block_on(async {
        Client::init_local().await
    });
    
    match client_result {
        Ok(client) => Box::into_raw(Box::new(client)) as *mut c_void,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Initialize a client that bootstraps from a list of peers.
/// If any of the provided peers is a global address, the client will not be local.
#[no_mangle]
pub extern "C" fn autonomi_client_init_with_peers(peers_ptr: *const *const c_char, peers_len: usize) -> *mut c_void {
    if peers_ptr.is_null() {
        return std::ptr::null_mut();
    }

    let mut peers = Vec::with_capacity(peers_len);
    for i in 0..peers_len {
        let peer_ptr = unsafe { *peers_ptr.add(i) };
        if peer_ptr.is_null() {
            continue;
        }
        
        let peer_cstr = unsafe { CStr::from_ptr(peer_ptr) };
        let peer_str = match peer_cstr.to_str() {
            Ok(s) => s,
            Err(_) => continue,
        };
        
        match Multiaddr::from_str(peer_str) {
			Ok(addr) => peers.push(addr),
			Err(_) => continue,
		}
    }
    
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let client_result = runtime.block_on(async {
        Client::init_with_peers(peers).await
    });
    
    match client_result {
        Ok(client) => Box::into_raw(Box::new(client)) as *mut c_void,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Initialize the client with the given configuration.
#[no_mangle]
pub extern "C" fn autonomi_client_init_with_config(config: *mut c_void) -> *mut c_void {
    if config.is_null() {
        return std::ptr::null_mut();
    }
    
    let config = unsafe { &*(config as *const ClientConfig) };
    
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let client_result = runtime.block_on(async {
        Client::init_with_config(config.clone()).await
    });
    
    match client_result {
        Ok(client) => Box::into_raw(Box::new(client)) as *mut c_void,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Upload public data to the network.
#[no_mangle]
pub extern "C" fn autonomi_client_data_put_public(
    client: *mut c_void,
    data: *const u8,
    data_len: usize,
    payment: *mut c_void,
    out_cost: *mut *mut c_char,
    out_addr: *mut *mut c_void
) -> *mut c_char {
    if client.is_null() || data.is_null() || payment.is_null() || out_cost.is_null() || out_addr.is_null() {
        return get_cost_string_from_string(String::from("ERROR: Null pointer provided"));
    }
    
    let client = unsafe { &*(client as *const Client) };
    let payment = unsafe { &*(payment as *const PaymentOption) };
    
    let data_vec = unsafe { std::slice::from_raw_parts(data, data_len).to_vec() };
    let bytes = Bytes::from(data_vec);
    
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime.block_on(async {
        client.data_put_public(bytes, payment.clone()).await
    });
    
    match result {
        Ok((cost, addr)) => {
            let cost_str = cost.to_string();
            unsafe { 
                *out_cost = get_cost_string_from_string(cost_str);
                let addr_box = Box::new(addr);
                *out_addr = Box::into_raw(addr_box) as *mut c_void;
            }
            get_cost_string_from_string(String::from("SUCCESS"))
        },
        Err(e) => {
            unsafe { 
                *out_cost = std::ptr::null_mut();
                *out_addr = std::ptr::null_mut();
            }
            get_cost_string_from_string(format!("ERROR: {}", e))
        }
    }
}

/// Get public data from the network.
#[no_mangle]
pub extern "C" fn autonomi_client_data_get_public(
    client: *mut c_void,
    addr: *mut c_void,
    out_data_len: *mut usize
) -> *mut u8 {
    if client.is_null() || addr.is_null() || out_data_len.is_null() {
        return std::ptr::null_mut();
    }
    
    let client = unsafe { &*(client as *const Client) };
    let addr = unsafe { &*(addr as *const DataAddress) };
    
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime.block_on(async {
        client.data_get_public(addr).await
    });
    
    match result {
        Ok(data) => {
            let data_vec = data.to_vec();
            let len = data_vec.len();
            let ptr = Box::into_raw(data_vec.into_boxed_slice()) as *mut u8;
            unsafe { *out_data_len = len; }
            ptr
        },
        Err(_) => {
            unsafe { *out_data_len = 0; }
            std::ptr::null_mut()
        }
    }
}

/// Upload a piece of private data to the network. This data will be self-encrypted.
/// The DataMapChunk is not uploaded to the network, keeping the data private.
#[no_mangle]
pub extern "C" fn autonomi_client_data_put(
    client: *mut c_void,
    data: *const u8,
    data_len: usize,
    payment: *mut c_void,
    out_cost: *mut *mut c_char,
    out_data_map: *mut *mut c_void
) -> *mut c_char {
    if client.is_null() || data.is_null() || payment.is_null() || out_cost.is_null() || out_data_map.is_null() {
        return get_cost_string_from_string(String::from("ERROR: Null pointer provided"));
    }
    
    let client = unsafe { &*(client as *const Client) };
    let payment = unsafe { &*(payment as *const PaymentOption) };
    
    let data_vec = unsafe { std::slice::from_raw_parts(data, data_len).to_vec() };
    let bytes = Bytes::from(data_vec);
    
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime.block_on(async {
        client.data_put(bytes, payment.clone()).await
    });
    
    match result {
        Ok((cost, data_map)) => {
            let cost_str = cost.to_string();
            unsafe { 
                *out_cost = get_cost_string_from_string(cost_str);
                let data_map_box = Box::new(data_map);
                *out_data_map = Box::into_raw(data_map_box) as *mut c_void;
            }
            get_cost_string_from_string(String::from("SUCCESS"))
        },
        Err(e) => {
            unsafe { 
                *out_cost = std::ptr::null_mut();
                *out_data_map = std::ptr::null_mut();
            }
            get_cost_string_from_string(format!("ERROR: {}", e))
        }
    }
}

/// Fetch a blob of (private) data from the network
#[no_mangle]
pub extern "C" fn autonomi_client_data_get(
    client: *mut c_void,
    data_map: *mut c_void,
    out_data_len: *mut usize
) -> *mut u8 {
    if client.is_null() || data_map.is_null() || out_data_len.is_null() {
        return std::ptr::null_mut();
    }
    
    let client = unsafe { &*(client as *const Client) };
    let data_map = unsafe { &*(data_map as *const DataMapChunk) };
    
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime.block_on(async {
        client.data_get(data_map).await
    });
    
    match result {
        Ok(data) => {
            let data_vec = data.to_vec();
            let len = data_vec.len();
            let ptr = Box::into_raw(data_vec.into_boxed_slice()) as *mut u8;
            unsafe { *out_data_len = len; }
            ptr
        },
        Err(_) => {
            unsafe { *out_data_len = 0; }
            std::ptr::null_mut()
        }
    }
}

/// Get the estimated cost of storing a piece of data.
#[no_mangle]
pub extern "C" fn autonomi_client_data_cost(
    client: *mut c_void,
    data: *const u8,
    data_len: usize
) -> *mut c_char {
    if client.is_null() || data.is_null() {
        return get_cost_string_from_string(String::from("ERROR: Null pointer provided"));
    }
    
    let client = unsafe { &*(client as *const Client) };
    
    // Copy data into a Vec<u8>
    let data_vec = unsafe { std::slice::from_raw_parts(data, data_len).to_vec() };
    let bytes = Bytes::from(data_vec);
    
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime.block_on(async {
        client.data_cost(bytes).await
    });
    
    result_to_c_char(result, |cost| cost.to_string())
}

/// Upload a directory from the local file system to the network as a public archive.
#[no_mangle]
pub extern "C" fn autonomi_client_dir_upload_public(
    client: *mut c_void,
    dir_path: *const c_char,
    payment: *mut c_void,
    out_cost: *mut *mut c_char,
    out_addr: *mut *mut c_void
) -> *mut c_char {
    if client.is_null() || dir_path.is_null() || payment.is_null() || out_cost.is_null() || out_addr.is_null() {
        return get_cost_string_from_string(String::from("ERROR: Null pointer provided"));
    }
    
    let client = unsafe { &*(client as *const Client) };
    let payment = unsafe { &*(payment as *const PaymentOption) };
    
    let dir_path_cstr = unsafe { CStr::from_ptr(dir_path) };
    let dir_path_str = match dir_path_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return get_cost_string_from_string(String::from("ERROR: Invalid directory path")),
    };
    
    let path = PathBuf::from(dir_path_str);
    
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime.block_on(async {
        client.dir_upload_public(path, payment.clone()).await
    });
    
    match result {
        Ok((cost, addr)) => {
            let cost_str = cost.to_string();
            unsafe { 
                *out_cost = get_cost_string_from_string(cost_str);
                let addr_box = Box::new(addr);
                *out_addr = Box::into_raw(addr_box) as *mut c_void;
            }
            get_cost_string_from_string(String::from("SUCCESS"))
        },
        Err(e) => {
            unsafe { 
                *out_cost = std::ptr::null_mut();
                *out_addr = std::ptr::null_mut();
            }
            get_cost_string_from_string(format!("ERROR: {}", e))
        }
    }
}

/// Download a public archive from the network to the local file system.
#[no_mangle]
pub extern "C" fn autonomi_client_dir_download_public(
    client: *mut c_void,
    addr: *mut c_void,
    dir_path: *const c_char
) -> *mut c_char {
    if client.is_null() || addr.is_null() || dir_path.is_null() {
        return get_cost_string_from_string(String::from("ERROR: Null pointer provided"));
    }
    
    let client = unsafe { &*(client as *const Client) };
    let addr = unsafe { &*(addr as *const ArchiveAddress) };
    
    let dir_path_cstr = unsafe { CStr::from_ptr(dir_path) };
    let dir_path_str = match dir_path_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return get_cost_string_from_string(String::from("ERROR: Invalid directory path")),
    };
    
    let path = PathBuf::from(dir_path_str);
    
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime.block_on(async {
        client.dir_download_public(addr, path).await
    });
    
    match result {
        Ok(_) => get_cost_string_from_string(String::from("SUCCESS")),
        Err(e) => get_cost_string_from_string(format!("ERROR: {}", e)),
    }
}

/// Upload a directory to the network. The directory is recursively walked and each file is uploaded to the network.
/// Returns, but does not upload, the PrivateArchive containing the data maps of the uploaded files.
#[no_mangle]
pub extern "C" fn autonomi_client_dir_upload(
    client: *mut c_void,
    dir_path: *const c_char,
    payment: *mut c_void,
    out_cost: *mut *mut c_char,
    out_data_map: *mut *mut c_void
) -> *mut c_char {
    if client.is_null() || dir_path.is_null() || payment.is_null() || out_cost.is_null() || out_data_map.is_null() {
        return get_cost_string_from_string(String::from("ERROR: Null pointer provided"));
    }
    
    let client = unsafe { &*(client as *const Client) };
    let payment = unsafe { &*(payment as *const PaymentOption) };
    
    let dir_path_cstr = unsafe { CStr::from_ptr(dir_path) };
    let dir_path_str = match dir_path_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return get_cost_string_from_string(String::from("ERROR: Invalid directory path")),
    };
    
    let path = PathBuf::from(dir_path_str);
    
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime.block_on(async {
        client.dir_upload(path, payment.clone()).await
    });
    
    match result {
        Ok((cost, data_map)) => {
            let cost_str = cost.to_string();
            unsafe { 
                *out_cost = get_cost_string_from_string(cost_str);
                let data_map_box = Box::new(data_map);
                *out_data_map = Box::into_raw(data_map_box) as *mut c_void;
            }
            get_cost_string_from_string(String::from("SUCCESS"))
        },
        Err(e) => {
            unsafe { 
                *out_cost = std::ptr::null_mut();
                *out_data_map = std::ptr::null_mut();
            }
            get_cost_string_from_string(format!("ERROR: {}", e))
        }
    }
}

/// Free a client instance
#[no_mangle]
pub extern "C" fn autonomi_client_free(client: *mut c_void) {
    if !client.is_null() {
        unsafe {
            let _ = Box::from_raw(client as *mut Client);
        }
    }
}

// Network methods

/// Create a new network configuration.
/// If local is true, configures for local network connections.
#[no_mangle]
pub extern "C" fn autonomi_network_new(local: bool) -> *mut c_void {
    match Network::new(local) {
        Ok(network) => Box::into_raw(Box::new(network)) as *mut c_void,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Create a custom network
#[no_mangle]
pub extern "C" fn autonomi_network_new_custom(
    rpc_url: *const c_char,
    payment_token_address: *const c_char,
    data_payment_address: *const c_char
) -> *mut c_void {
    if rpc_url.is_null() || payment_token_address.is_null() || data_payment_address.is_null() {
        return std::ptr::null_mut();
    }
    
    let rpc_url_cstr = unsafe { CStr::from_ptr(rpc_url) };
    let rpc_url_str = match rpc_url_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let payment_token_address_cstr = unsafe { CStr::from_ptr(payment_token_address) };
    let payment_token_address_str = match payment_token_address_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let data_payment_address_cstr = unsafe { CStr::from_ptr(data_payment_address) };
    let data_payment_address_str = match data_payment_address_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let network = Network::new_custom(rpc_url_str, payment_token_address_str, data_payment_address_str);
    Box::into_raw(Box::new(network)) as *mut c_void
}

/// Get the default network (Arbitrum One)
#[no_mangle]
pub extern "C" fn autonomi_network_default() -> *mut c_void {
    let network = Network::default();
    Box::into_raw(Box::new(network)) as *mut c_void
}

/// Get the Arbitrum Sepolia network
#[no_mangle]
pub extern "C" fn autonomi_network_arbitrum_sepolia() -> *mut c_void {
    let network = Network::ArbitrumSepolia;
    Box::into_raw(Box::new(network)) as *mut c_void
}

/// Free a Network instance
#[no_mangle]
pub extern "C" fn autonomi_network_free(network: *mut c_void) {
    if !network.is_null() {
        unsafe {
            let _ = Box::from_raw(network as *mut Network);
        }
    }
}

// Wallet methods

/// Create a new wallet with a random key
#[no_mangle]
pub extern "C" fn autonomi_wallet_new(network: *mut c_void) -> *mut c_void {
    if network.is_null() {
        return std::ptr::null_mut();
    }
    
    let network = unsafe { &*(network as *const Network) };
    let wallet = Wallet::new_with_random_wallet(network.clone());
    Box::into_raw(Box::new(wallet)) as *mut c_void
}

/// Create a wallet from a private key
#[no_mangle]
pub extern "C" fn autonomi_wallet_from_private_key(network: *mut c_void, private_key: *const c_char) -> *mut c_void {
    if network.is_null() || private_key.is_null() {
        return std::ptr::null_mut();
    }
    
    let network = unsafe { &*(network as *const Network) };
    
    let key_cstr = unsafe { CStr::from_ptr(private_key) };
    let key_str = match key_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    
    match Wallet::new_from_private_key(network.clone(), key_str) {
        Ok(wallet) => Box::into_raw(Box::new(wallet)) as *mut c_void,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get the balance of a wallet
#[no_mangle]
pub extern "C" fn autonomi_wallet_get_balance(wallet: *mut c_void) -> *mut c_char {
    if wallet.is_null() {
        return get_cost_string_from_string(String::from("ERROR: Null pointer provided"));
    }
    
    let wallet = unsafe { &*(wallet as *const Wallet) };
    
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime.block_on(async {
        wallet.balance_of_tokens().await
    });
    
    result_to_c_char(result, |balance| balance.to_string())
}

/// Get the balance of gas tokens in a wallet
#[no_mangle]
pub extern "C" fn autonomi_wallet_get_balance_of_gas(wallet: *mut c_void) -> *mut c_char {
    if wallet.is_null() {
        return get_cost_string_from_string(String::from("ERROR: Null pointer provided"));
    }
    
    let wallet = unsafe { &*(wallet as *const Wallet) };
    
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime.block_on(async {
        wallet.balance_of_gas_tokens().await
    });
    
    result_to_c_char(result, |balance| balance.to_string())
}

/// Get the address of a wallet
#[no_mangle]
pub extern "C" fn autonomi_wallet_address(wallet: *mut c_void) -> *mut c_char {
    if wallet.is_null() {
        return get_cost_string_from_string(String::from("ERROR: Null pointer provided"));
    }
    
    let wallet = unsafe { &*(wallet as *const Wallet) };
    get_cost_string_from_string(wallet.address().to_string())
}

/// Get the network of a wallet
#[no_mangle]
pub extern "C" fn autonomi_wallet_network(wallet: *mut c_void) -> *mut c_void {
    if wallet.is_null() {
        return std::ptr::null_mut();
    }
    
    let wallet = unsafe { &*(wallet as *const Wallet) };
    let network = wallet.network().clone();
    
    Box::into_raw(Box::new(network)) as *mut c_void
}

/// Generate a random private key
#[no_mangle]
pub extern "C" fn autonomi_wallet_random_private_key() -> *mut c_char {
    let private_key = Wallet::random_private_key();
    get_cost_string_from_string(private_key)
}

/// Transfer tokens from one wallet to another
#[no_mangle]
pub extern "C" fn autonomi_wallet_transfer_tokens(
    wallet: *mut c_void,
    to_address: *const c_char,
    amount: *const c_char
) -> *mut c_char {
    if wallet.is_null() || to_address.is_null() || amount.is_null() {
        return get_cost_string_from_string(String::from("ERROR: Null pointer provided"));
    }
    
    let wallet = unsafe { &*(wallet as *const Wallet) };
    
    let to_address_cstr = unsafe { CStr::from_ptr(to_address) };
    let to_address_str = match to_address_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return get_cost_string_from_string(String::from("ERROR: Invalid to_address")),
    };
    
    let amount_cstr = unsafe { CStr::from_ptr(amount) };
    let amount_str = match amount_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return get_cost_string_from_string(String::from("ERROR: Invalid amount")),
    };
    
    // Преобразуване на amount от низ към u64
    let amount = match amount_str.parse::<u64>() {
        Ok(a) => a,
        Err(_) => return get_cost_string_from_string(String::from("ERROR: Invalid amount format")),
    };
    
    // Преобразуване на u64 към ruint::Uint<256, 4>
    let amount = ruint::Uint::<256, 4>::from(amount);
    
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime.block_on(async {
        wallet.transfer_tokens(to_address_str.parse().unwrap(), amount).await  // <-- Use amount directly
    });
    
    match result {
        Ok(_) => get_cost_string_from_string(String::from("SUCCESS")),
        Err(e) => get_cost_string_from_string(format!("ERROR: {}", e)),
    }
}

/// Free a Wallet instance
#[no_mangle]
pub extern "C" fn autonomi_wallet_free(wallet: *mut c_void) {
    if !wallet.is_null() {
        unsafe {
            let _ = Box::from_raw(wallet as *mut Wallet);
        }
    }
}

// PaymentOption methods

/// Create a PaymentOption from a Wallet
#[no_mangle]
pub extern "C" fn autonomi_payment_option_from_wallet(wallet: *mut c_void) -> *mut c_void {
    if wallet.is_null() {
        return std::ptr::null_mut();
    }
    
    let wallet = unsafe { &*(wallet as *const Wallet) };
    let payment_option = PaymentOption::Wallet(wallet.clone());
    
    Box::into_raw(Box::new(payment_option)) as *mut c_void
}

/// Free a PaymentOption instance
#[no_mangle]
pub extern "C" fn autonomi_payment_option_free(payment: *mut c_void) {
    if !payment.is_null() {
        unsafe {
            let _ = Box::from_raw(payment as *mut PaymentOption);
        }
    }
}

// DataAddress methods

/// Get the hex string representation of a DataAddress
#[no_mangle]
pub extern "C" fn autonomi_data_address_to_hex(addr: *mut c_void) -> *mut c_char {
    if addr.is_null() {
        return get_cost_string_from_string(String::from("ERROR: Null pointer provided"));
    }
    
    let addr = unsafe { &*(addr as *const DataAddress) };
    get_cost_string_from_string(addr.to_hex())
}

/// Create a DataAddress from a hex string
#[no_mangle]
pub extern "C" fn autonomi_data_address_from_hex(hex: *const c_char) -> *mut c_void {
    if hex.is_null() {
        return std::ptr::null_mut();
    }
    
    let hex_cstr = unsafe { CStr::from_ptr(hex) };
    let hex_str = match hex_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    
    match DataAddress::from_hex(hex_str) {
        Ok(addr) => Box::into_raw(Box::new(addr)) as *mut c_void,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a DataAddress instance
#[no_mangle]
pub extern "C" fn autonomi_data_address_free(addr: *mut c_void) {
    if !addr.is_null() {
        unsafe {
            let _ = Box::from_raw(addr as *mut DataAddress);
        }
    }
}

// ArchiveAddress methods

/// Get the hex string representation of an ArchiveAddress
#[no_mangle]
pub extern "C" fn autonomi_archive_address_to_hex(addr: *mut c_void) -> *mut c_char {
    if addr.is_null() {
        return get_cost_string_from_string(String::from("ERROR: Null pointer provided"));
    }
    
    let addr = unsafe { &*(addr as *const ArchiveAddress) };
    get_cost_string_from_string(addr.to_hex())
}

/// Create an ArchiveAddress from a hex string
#[no_mangle]
pub extern "C" fn autonomi_archive_address_from_hex(hex: *const c_char) -> *mut c_void {
    if hex.is_null() {
        return std::ptr::null_mut();
    }
    
    let hex_cstr = unsafe { CStr::from_ptr(hex) };
    let hex_str = match hex_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    
    match ArchiveAddress::from_hex(hex_str) {
        Ok(addr) => Box::into_raw(Box::new(addr)) as *mut c_void,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free an ArchiveAddress instance
#[no_mangle]
pub extern "C" fn autonomi_archive_address_free(addr: *mut c_void) {
    if !addr.is_null() {
        unsafe {
            let _ = Box::from_raw(addr as *mut ArchiveAddress);
        }
    }
}

// DataMapChunk methods

/// Create a DataMapChunk from a hex string
#[no_mangle]
pub extern "C" fn autonomi_data_map_chunk_from_hex(hex: *const c_char) -> *mut c_void {
    if hex.is_null() {
        return std::ptr::null_mut();
    }
    
    let hex_cstr = unsafe { CStr::from_ptr(hex) };
    let hex_str = match hex_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    
    match DataMapChunk::from_hex(hex_str) {
        Ok(chunk) => Box::into_raw(Box::new(chunk)) as *mut c_void,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get the hex string representation of a DataMapChunk
#[no_mangle]
pub extern "C" fn autonomi_data_map_chunk_to_hex(chunk: *mut c_void) -> *mut c_char {
    if chunk.is_null() {
        return get_cost_string_from_string(String::from("ERROR: Null pointer provided"));
    }
    
    let chunk = unsafe { &*(chunk as *const DataMapChunk) };
    get_cost_string_from_string(chunk.to_hex())
}

/// Get the address of a DataMapChunk
#[no_mangle]
pub extern "C" fn autonomi_data_map_chunk_address(chunk: *mut c_void) -> *mut c_char {
    if chunk.is_null() {
        return get_cost_string_from_string(String::from("ERROR: Null pointer provided"));
    }
    
    let chunk = unsafe { &*(chunk as *const DataMapChunk) };
    get_cost_string_from_string(chunk.address().to_string())
}

/// Free a DataMapChunk instance
#[no_mangle]
pub extern "C" fn autonomi_data_map_chunk_free(chunk: *mut c_void) {
    if !chunk.is_null() {
        unsafe {
            let _ = Box::from_raw(chunk as *mut DataMapChunk);
        }
    }
}

// PrivateArchiveDataMap methods

/// Get the hex string representation of a PrivateArchiveDataMap
#[no_mangle]
pub extern "C" fn autonomi_private_archive_data_map_to_hex(data_map: *mut c_void) -> *mut c_char {
    if data_map.is_null() {
        return get_cost_string_from_string(String::from("ERROR: Null pointer provided"));
    }
    
    let data_map = unsafe { &*(data_map as *const PrivateArchiveDataMap) };
    get_cost_string_from_string(data_map.to_hex())
}

/// Create a PrivateArchiveDataMap from a hex string
#[no_mangle]
pub extern "C" fn autonomi_private_archive_data_map_from_hex(hex: *const c_char) -> *mut c_void {
    if hex.is_null() {
        return std::ptr::null_mut();
    }
    
    let hex_cstr = unsafe { CStr::from_ptr(hex) };
    let hex_str = match hex_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    
    match PrivateArchiveDataMap::from_hex(hex_str) {
        Ok(data_map) => Box::into_raw(Box::new(data_map)) as *mut c_void,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a PrivateArchiveDataMap instance
#[no_mangle]
pub extern "C" fn autonomi_private_archive_data_map_free(data_map: *mut c_void) {
    if !data_map.is_null() {
        unsafe {
            let _ = Box::from_raw(data_map as *mut PrivateArchiveDataMap);
        }
    }
}

// This implementation covers the core functionality needed for the .NET wrapper,
// focusing on the key operations demonstrated in the Python example:
// - Client initialization
// - Wallet management
// - Data upload/download
// - Payment options
// 
// Additional functionality can be added as needed.