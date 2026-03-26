"""
delta.py — Pure Python delta sync engine for LANxfer 2.0
Algorithm: simplified rsync (Adler-32 rolling + SHA-256 strong checksum)
No external dependencies — uses only zlib and hashlib (Python built-ins)
"""

import zlib
import hashlib
import struct
import io

BLOCK_SIZE = 2048  # 2KB blocks — good balance for LAN file sizes


# ─────────────────────────────────────────────
# Signature Generation
# Receiver calls this on their existing file
# Returns list of (adler32, sha256) per block
# ─────────────────────────────────────────────

def generate_signature(file_path, block_size=BLOCK_SIZE):
    """
    Read existing file in blocks, compute:
      - Adler-32 rolling checksum (fast, used for quick rejection)
      - SHA-256 strong checksum (slow, used for confirmation)
    Returns list of { adler, sha256, block_index }
    """
    signature = []
    with open(file_path, 'rb') as f:
        block_index = 0
        while True:
            block = f.read(block_size)
            if not block:
                break
            adler  = zlib.adler32(block) & 0xFFFFFFFF
            strong = hashlib.sha256(block).hexdigest()
            signature.append({
                'index':  block_index,
                'adler':  adler,
                'sha256': strong
            })
            block_index += 1
    return signature


def signature_to_bytes(signature):
    """
    Serialize signature list to compact binary format:
      [4 bytes: block_count]
      Per block: [4 bytes: adler32][32 bytes: sha256_hex as ascii]
    """
    buf = struct.pack('>I', len(signature))
    for entry in signature:
        buf += struct.pack('>I', entry['adler'])
        buf += entry['sha256'].encode('ascii')  # 64 bytes hex string
    return buf


def signature_from_bytes(data):
    """Deserialize signature bytes back to list."""
    offset      = 0
    block_count = struct.unpack_from('>I', data, offset)[0]
    offset      += 4
    signature   = []
    for i in range(block_count):
        adler  = struct.unpack_from('>I', data, offset)[0]
        offset += 4
        sha256 = data[offset:offset + 64].decode('ascii')
        offset += 64
        signature.append({'index': i, 'adler': adler, 'sha256': sha256})
    return signature


# ─────────────────────────────────────────────
# Delta Computation
# Sender calls this with: new file + old signature
# Returns delta instructions
# ─────────────────────────────────────────────

def compute_delta(new_file_path, signature, block_size=BLOCK_SIZE):
    """
    Compare new file against old file's signature.
    Returns list of delta instructions:
      { type: 'copy',   index: N }          → reuse block N from old file
      { type: 'literal', data: bytes }       → new data to insert
    """
    # Build fast lookup: adler32 → list of signature entries
    adler_map = {}
    for entry in signature:
        adler_map.setdefault(entry['adler'], []).append(entry)

    instructions = []

    with open(new_file_path, 'rb') as f:
        new_data = f.read()

    i         = 0
    literal   = bytearray()
    total_len = len(new_data)

    while i < total_len:
        block = new_data[i:i + block_size]
        if len(block) == 0:
            break

        adler = zlib.adler32(block) & 0xFFFFFFFF

        matched = False
        if adler in adler_map:
            # Adler matches — verify with SHA-256
            strong = hashlib.sha256(block).hexdigest()
            for entry in adler_map[adler]:
                if entry['sha256'] == strong:
                    # Found matching block — flush any pending literal first
                    if literal:
                        instructions.append({
                            'type': 'literal',
                            'data': bytes(literal)
                        })
                        literal = bytearray()
                    instructions.append({
                        'type':  'copy',
                        'index': entry['index']
                    })
                    i      += block_size
                    matched = True
                    break

        if not matched:
            # No match — accumulate as literal byte
            literal.append(new_data[i])
            i += 1

    # Flush remaining literal
    if literal:
        instructions.append({'type': 'literal', 'data': bytes(literal)})

    return instructions


# ─────────────────────────────────────────────
# Delta Serialization
# ─────────────────────────────────────────────

MAGIC   = b'LXDELTA1'   # LANxfer Delta v1 header

def delta_to_bytes(instructions, block_size=BLOCK_SIZE):
    """
    Binary delta format:
      [8 bytes: magic LXDELTA1]
      [4 bytes: block_size]
      [4 bytes: instruction_count]
      Per instruction:
        COPY:    [1 byte: 0x01][4 bytes: block_index]
        LITERAL: [1 byte: 0x02][4 bytes: length][N bytes: data]
    """
    buf  = MAGIC
    buf += struct.pack('>I', block_size)
    buf += struct.pack('>I', len(instructions))
    for instr in instructions:
        if instr['type'] == 'copy':
            buf += b'\x01'
            buf += struct.pack('>I', instr['index'])
        else:
            data = instr['data']
            buf += b'\x02'
            buf += struct.pack('>I', len(data))
            buf += data
    return buf


def delta_from_bytes(data):
    """Deserialize delta bytes back to instructions list."""
    offset = 0
    magic  = data[offset:offset + 8]
    offset += 8
    if magic != MAGIC:
        raise ValueError(f'Invalid delta magic: {magic}')
    block_size     = struct.unpack_from('>I', data, offset)[0]; offset += 4
    instr_count    = struct.unpack_from('>I', data, offset)[0]; offset += 4
    instructions   = []
    for _ in range(instr_count):
        kind = data[offset:offset + 1]; offset += 1
        if kind == b'\x01':
            index = struct.unpack_from('>I', data, offset)[0]; offset += 4
            instructions.append({'type': 'copy', 'index': index})
        elif kind == b'\x02':
            length  = struct.unpack_from('>I', data, offset)[0]; offset += 4
            payload = data[offset:offset + length];              offset += length
            instructions.append({'type': 'literal', 'data': payload})
        else:
            raise ValueError(f'Unknown instruction type: {kind}')
    return block_size, instructions


# ─────────────────────────────────────────────
# Patch Application
# Receiver calls this with: old file + delta
# ─────────────────────────────────────────────

def apply_delta(base_file_path, delta_bytes, output_path):
    """
    Reconstruct new file using:
      - COPY instructions → read block from base file
      - LITERAL instructions → write new bytes directly
    """
    block_size, instructions = delta_from_bytes(delta_bytes)

    # Load base file blocks into memory (or stream for large files)
    with open(base_file_path, 'rb') as f:
        base_data = f.read()

    with open(output_path, 'wb') as out:
        for instr in instructions:
            if instr['type'] == 'copy':
                start = instr['index'] * block_size
                end   = start + block_size
                out.write(base_data[start:end])
            else:
                out.write(instr['data'])


# ─────────────────────────────────────────────
# Stats Helper
# ─────────────────────────────────────────────

def delta_stats(instructions, new_file_size):
    """Return how much data is copied vs new (literal)."""
    copied_blocks  = sum(1 for i in instructions if i['type'] == 'copy')
    literal_bytes  = sum(len(i['data']) for i in instructions if i['type'] == 'literal')
    delta_size     = sum(
        5         if i['type'] == 'copy' else 5 + len(i['data'])
        for i in instructions
    )
    savings_pct    = max(0, round((1 - delta_size / max(new_file_size, 1)) * 100))
    return {
        'copied_blocks': copied_blocks,
        'literal_bytes': literal_bytes,
        'delta_size':    delta_size,
        'savings_pct':   savings_pct
    }
