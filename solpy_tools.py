"""Set of tools for Solana Python and Metaplex Python"""
from os import getenv
from pathlib import Path
import json
from solana.keypair import Keypair
import based58
import struct
from solana.rpc.api import Client
from solana.publickey import PublicKey
from solana.rpc.types import MemcmpOpts
import base64
from solana.rpc.types import TokenAccountOpts
import time

METADATA_PROGRAM_ID = PublicKey('metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s')
TOKEN_PROGRAM_ID = PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA')


def get_keypair_from_raw_private_key(raw_private_key: list[bytes] | bytes | str | list[int]) -> Keypair:
    """Get Keypair from raw private key obtained from wallets."""
    if not isinstance(raw_private_key, bytes) and not isinstance(raw_private_key, list):
        raw_private_key = bytes(raw_private_key, encoding='utf-8')
        raw_private_key = based58.b58decode(raw_private_key)
    if isinstance(raw_private_key[0], int):
        raw_private_key = bytes(raw_private_key)
    return Keypair.from_secret_key(raw_private_key)


def get_raw_private_key_from_keypair(keypair: Keypair, encoding: str = 'base58') -> list[bytes] | bytes:
    """Get raw private key from Keypair to import to wallets."""
    if type(keypair) != Keypair:
        raise TypeError("Invalid type. Type has to be Keypair")
    if encoding == 'list':
        key = keypair.secret_key
        raw_private_key = [i for i in key]
        return raw_private_key

    raw_private_key = based58.b58encode(keypair.secret_key)
    return raw_private_key


def get_metadata_account(mint_key: PublicKey | str) -> PublicKey:
    """Get metadata account from mint address."""
    return PublicKey.find_program_address(
        [b'metadata', bytes(METADATA_PROGRAM_ID), bytes(PublicKey(mint_key))],
        METADATA_PROGRAM_ID
    )[0]


def get_nfts_raw_data_from_collection_creator(client: Client,
                                              creator_address: str | PublicKey) -> tuple():
    """Fetch nfts from collection creator. Maybe Deprecated."""
    memcmp_opts = [MemcmpOpts(offset=326, bytes=creator_address)]
    resp = client.get_program_accounts(
        METADATA_PROGRAM_ID, encoding="base64", memcmp_opts=memcmp_opts)
    nft_count = len(resp['result'])
    return resp['result'], nft_count


def get_nfts_from_address(client: Client,
                          address: PublicKey) -> tuple():
    """Fetchs tokens/nfts from address."""
    resp = client.get_token_accounts_by_owner(
        address, TokenAccountOpts(program_id=TOKEN_PROGRAM_ID),
        'max')
    tokens_owned = resp['result']['value']
    nft_count = len(tokens_owned)
    return tokens_owned, nft_count


def unpack_metadata_account_v2(data):
    """Unpack decoded base64 data obtained from metadata account."""
    assert(data[0] == 4)
    i = 1
    source_account = based58.b58encode(
        bytes(struct.unpack('<' + "B"*32, data[i:i+32]))).decode()
    i += 32
    mint_account = based58.b58encode(
        bytes(struct.unpack('<' + "B"*32, data[i:i+32]))).decode()
    i += 32
    name_len = struct.unpack('<I', data[i:i+4])[0]
    i += 4
    name = struct.unpack('<' + "B"*name_len, data[i:i+name_len])
    i += name_len
    symbol_len = struct.unpack('<I', data[i:i+4])[0]
    i += 4
    symbol = struct.unpack('<' + "B"*symbol_len, data[i:i+symbol_len])
    i += symbol_len
    uri_len = struct.unpack('<I', data[i:i+4])[0]
    i += 4
    uri = struct.unpack('<' + "B"*uri_len, data[i:i+uri_len])
    i += uri_len
    fee = struct.unpack('<h', data[i:i+2])[0]
    i += 2
    has_creator = data[i]
    i += 1
    creators = []
    verified = []
    share = []
    if has_creator:
        creator_len = struct.unpack('<I', data[i:i+4])[0]
        i += 4
        for _ in range(creator_len):
            creator = based58.b58encode(
                bytes(struct.unpack('<' + "B"*32, data[i:i+32]))).decode()
            creators.append(creator)
            i += 32
            verified.append(data[i])
            i += 1
            share.append(data[i])
            i += 1
    primary_sale_happened = bool(data[i])
    i += 1
    is_mutable = bool(data[i])
    # no idea what to do here but I added by 4 so that it matches then next data
    i += 4
    token_standard = struct.unpack('<b', data[i:i+1])[0]
    i += 1
    has_collection = bool(data[i])
    i += 1
    if has_collection:
        verified_collection = bool(data[i])
        i += 1
        collection_key = based58.b58encode(
            bytes(struct.unpack('<' + "B"*32, data[i:i+32]))).decode()
    i += 33
    has_uses = bool(data[i])
    if has_uses:
        use_method = struct.unpack('<b', data[i:i+1])[0]
        i += 1
        remaining = struct.unpack('<Q', data[i:i+8])[0]
        i += 8
        total = struct.unpack('<Q', data[i:i+8])[0]
        i += 8

    metadata = {
        "update_authority": source_account,
        "mint": mint_account,
        "data": {
            "name": bytes(name).decode("utf-8").strip("\x00"),
            "symbol": bytes(symbol).decode("utf-8").strip("\x00"),
            "uri": bytes(uri).decode("utf-8").strip("\x00"),
            "seller_fee_basis_points": fee,
            "creators": creators,
            "verified": verified,
            "share": share,
        },
        "primary_sale_happened": primary_sale_happened,
        "is_mutable": is_mutable,
        "token_standard": token_standard,
        "collection": {
            "verified": verified_collection,
            "key": collection_key
        } if has_collection else None,

        "uses": {
            "use_method": use_method,
            "remaining": remaining,
            "total": total
        } if has_uses else None
    }
    return metadata


def get_metadata(client: Client, mint_key: PublicKey) -> dict:
    """Fetchs tokens/nfts from address."""
    metadata_account = get_metadata_account(mint_key)
    try:
        data = base64.b64decode(client.get_account_info(
            metadata_account)['result']['value']['data'][0])

        metadata = unpack_metadata_account_v2(data)
        return metadata
    except Exception as e:
        print(e)
        print("Metadata not found")
    return {}


def get_mint_metadata_from_collection_data(raw_collection_data: list) -> list:
    """Parses tokens/nfts from collection data."""
    unpacked_data_list: list = []
    if len(raw_collection_data) == 0:
        print("No data found")
        return unpacked_data_list
    for raw_data in raw_collection_data:
        raw_data_decoded = base64.b64decode(raw_data['account']['data'][0])
        unpacked_data = unpack_metadata_account_v2(raw_data_decoded)
        unpacked_data_list.append(unpacked_data)

    return unpacked_data_list


def print_unpacked_metadata_nicely(unpacked_data: dict) -> None:
    """Prints first metadata nicely."""
    print(f"nft name                = {unpacked_data['data']['name']}")
    print(f"mint address            = {unpacked_data['mint']}")
    print(f"update authority        = {unpacked_data['update_authority']}")
    print(f"nft symbol              = {unpacked_data['data']['symbol']}")
    print(
        f"primary sale happened   = {unpacked_data['primary_sale_happened']}")
    print(f"is mutable              = {unpacked_data['is_mutable']}")
    print(
        f"royalty/sbfp (%)        = {unpacked_data['data']['seller_fee_basis_points'] / 100}")
    print(f"image link              = {unpacked_data['data']['uri']}")
    print("")
    if unpacked_data['collection']:
        print(
            f"collection | verified   = {unpacked_data['collection']['key']} | {unpacked_data['collection']['verified']}")
        print("")
    print(f"creators | verified | share(%)")
    for index in range(len(unpacked_data['data']['creators'])):
        print(
            f"{unpacked_data['data']['creators'][index]} | {unpacked_data['data']['verified'][index]} | {unpacked_data['data']['share'][index]}%")
    print("")


def print_first_mint_metadata_from_collection_data(raw_collection_data: list) -> None:
    """Unpacks and prints first token/nft from collection data nicely."""
    if len(raw_collection_data) == 0:
        print("No data found")
        return

    raw_data_decoded = base64.b64decode(
        raw_collection_data[0]['account']['data'][0])
    unpacked_data = unpack_metadata_account_v2(raw_data_decoded)
    print_unpacked_metadata_nicely(unpacked_data)


def load_system_wallet(path: str = ".config/solana/id.json") -> Keypair | None:
    """Loads system wallet."""
    path = Path(getenv("SOL_WALLET", Path.home() / path))
    if path.exists():
        with path.open() as f:
            keypair = json.load(f)
        return Keypair.from_secret_key(bytes(keypair))
    else:
        print("Wallet not found")
        return None


def get_mint_metadata_from_owner_data(client: Client,
                                      raw_owner_data: list,
                                      print_metadata: bool = True,
                                      sleep_in_sec: int = 1) -> list:
    """Fetch nfts from owner address. and prints metadata nicely."""
    unpacked_data_list: list = []

    if len(raw_owner_data) == 0:
        print("No data found")
        return unpacked_data_list

    for raw_data in raw_owner_data:
        token_address = raw_data['pubkey']
        token_address_info = client.get_account_info(
            token_address, 'max', 'jsonParsed')
        mint_address = token_address_info['result']['value'][
            'data']['parsed']['info']['mint']
        supply = token_address_info['result'][
            'value']['data']['parsed']['info']['tokenAmount'][
                'amount']
        if supply == '1':
            metadata = get_metadata(client, mint_address)
            unpacked_data_list.append(metadata)
            if print_metadata:
                print_unpacked_metadata_nicely(metadata)

        # avoid being rate limited
        time.sleep(sleep_in_sec)

    return unpacked_data_list
