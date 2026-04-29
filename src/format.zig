const std = @import("std");
const crypto = @import("crypto.zig");

pub const MAGIC = "ASYMCRY\x00";
pub const VERSION: u8 = 1;
pub const ALG_AEGIS_128X2: u8 = 1;
pub const KDF_ARGON2ID: u8 = 1;
pub const FLAG_PASSWORD_KDF: u8 = 1;

pub const DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024;
pub const MAX_CHUNK_SIZE: u32 = 64 * 1024 * 1024;

pub const HEADER_FIXED_LEN: usize = 8 + 1 + 1 + 1 + 4 + crypto.FILE_NONCE_LEN + 2;
pub const ARGON2_METADATA_LEN: usize = 1 + 16 + 4 + 4 + 4;
pub const MAX_HEADER_LEN: usize = HEADER_FIXED_LEN + ARGON2_METADATA_LEN;

pub const FINAL_CHUNK_FLAG: u8 = 1;
pub const CHUNK_FRAMING_LEN: usize = 4 + 1;
pub const CHUNK_AD_TRAILER_LEN: usize = 8 + 4 + 1;
pub const MAX_CHUNK_AD_LEN: usize = MAX_HEADER_LEN + CHUNK_AD_TRAILER_LEN;

pub const Argon2Meta = struct {
    salt: [16]u8,
    mem_kib: u32,
    iterations: u32,
    parallelism: u32,

    pub fn encode(self: *const Argon2Meta) [ARGON2_METADATA_LEN]u8 {
        var out: [ARGON2_METADATA_LEN]u8 = undefined;
        out[0] = KDF_ARGON2ID;
        out[1..17].* = self.salt;
        std.mem.writeInt(u32, out[17..21], self.mem_kib, .little);
        std.mem.writeInt(u32, out[21..25], self.iterations, .little);
        std.mem.writeInt(u32, out[25..29], self.parallelism, .little);
        return out;
    }

    pub const DecodeError = error{
        BadArgon2MetadataLength,
        UnknownKdfId,
    };

    pub fn decode(buf: []const u8) DecodeError!Argon2Meta {
        if (buf.len != ARGON2_METADATA_LEN) return error.BadArgon2MetadataLength;
        if (buf[0] != KDF_ARGON2ID) return error.UnknownKdfId;
        return .{
            .salt = buf[1..17].*,
            .mem_kib = std.mem.readInt(u32, buf[17..21], .little),
            .iterations = std.mem.readInt(u32, buf[21..25], .little),
            .parallelism = std.mem.readInt(u32, buf[25..29], .little),
        };
    }

    pub fn eql(a: Argon2Meta, b: Argon2Meta) bool {
        return std.mem.eql(u8, &a.salt, &b.salt) and
            a.mem_kib == b.mem_kib and
            a.iterations == b.iterations and
            a.parallelism == b.parallelism;
    }
};

pub const Header = struct {
    chunk_size: u32,
    file_nonce: crypto.FileNonce,
    kdf: ?Argon2Meta,

    pub fn encodedLen(self: *const Header) usize {
        return HEADER_FIXED_LEN + if (self.kdf != null) ARGON2_METADATA_LEN else 0;
    }

    pub fn encode(self: *const Header, buffer: *[MAX_HEADER_LEN]u8) []u8 {
        const out = buffer[0..self.encodedLen()];
        const kdf_len: u16 = if (self.kdf != null) ARGON2_METADATA_LEN else 0;
        out[0..8].* = MAGIC.*;
        out[8] = VERSION;
        out[9] = ALG_AEGIS_128X2;
        out[10] = if (self.kdf != null) FLAG_PASSWORD_KDF else 0;
        std.mem.writeInt(u32, out[11..15], self.chunk_size, .little);
        out[15..31].* = self.file_nonce;
        std.mem.writeInt(u16, out[31..33], kdf_len, .little);
        if (self.kdf) |k| {
            out[HEADER_FIXED_LEN..][0..ARGON2_METADATA_LEN].* = k.encode();
        }
        return out;
    }

    pub const Parsed = struct {
        header: Header,
        /// Slice into the caller-provided buffer holding the raw header
        /// bytes; reused as the leading part of the AEGIS associated data.
        raw_bytes: []u8,
    };

    /// Parses a header from `reader` into `buffer`. The returned `raw_bytes`
    /// aliases the prefix of `buffer`.
    pub fn read(reader: *std.Io.Reader, buffer: *[MAX_HEADER_LEN]u8) !Parsed {
        const fixed = buffer[0..HEADER_FIXED_LEN];
        try reader.readSliceAll(fixed);
        if (!std.mem.eql(u8, fixed[0..8], MAGIC)) return error.BadMagic;
        if (fixed[8] != VERSION) return error.UnsupportedVersion;
        if (fixed[9] != ALG_AEGIS_128X2) return error.UnsupportedAlgorithm;
        const flags = fixed[10];
        if ((flags & ~@as(u8, FLAG_PASSWORD_KDF)) != 0) return error.UnknownHeaderFlags;
        const chunk_size = std.mem.readInt(u32, fixed[11..15], .little);
        if (chunk_size == 0 or chunk_size > MAX_CHUNK_SIZE) return error.InvalidChunkSize;
        const header_len: usize = std.mem.readInt(u16, fixed[31..33], .little);
        if (header_len > ARGON2_METADATA_LEN) return error.UnknownHeaderFlags;

        const trailer = buffer[HEADER_FIXED_LEN..][0..header_len];
        if (header_len > 0) try reader.readSliceAll(trailer);

        var kdf: ?Argon2Meta = null;
        if ((flags & FLAG_PASSWORD_KDF) != 0) {
            kdf = try Argon2Meta.decode(trailer);
        } else if (header_len != 0) {
            return error.MetadataPresentWithoutKdfFlag;
        }

        return .{
            .header = .{ .chunk_size = chunk_size, .file_nonce = fixed[15..31].*, .kdf = kdf },
            .raw_bytes = buffer[0 .. HEADER_FIXED_LEN + header_len],
        };
    }
};

/// Writes the per-chunk AD trailer (`chunk_index ‖ plain_len ‖ flags`) into
/// `out`, which must be exactly `CHUNK_AD_TRAILER_LEN` bytes.
pub fn writeChunkAdTrailer(
    out: *[CHUNK_AD_TRAILER_LEN]u8,
    chunk_index: u64,
    plain_len: u32,
    flags: u8,
) void {
    std.mem.writeInt(u64, out[0..8], chunk_index, .little);
    std.mem.writeInt(u32, out[8..12], plain_len, .little);
    out[12] = flags;
}

pub fn encodeChunkFraming(plain_len: u32, flags: u8) [CHUNK_FRAMING_LEN]u8 {
    var out: [CHUNK_FRAMING_LEN]u8 = undefined;
    std.mem.writeInt(u32, out[0..4], plain_len, .little);
    out[4] = flags;
    return out;
}

pub fn decodeChunkFraming(buf: *const [CHUNK_FRAMING_LEN]u8) struct { u32, u8 } {
    return .{
        std.mem.readInt(u32, buf[0..4], .little),
        buf[4],
    };
}

pub fn validateChunkFlags(flags: u8) error{UnknownChunkFlags}!bool {
    if ((flags & ~@as(u8, FINAL_CHUNK_FLAG)) != 0) return error.UnknownChunkFlags;
    return (flags & FINAL_CHUNK_FLAG) != 0;
}

test "header round-trip without KDF" {
    const h: Header = .{
        .chunk_size = 64 * 1024,
        .file_nonce = @splat(0xa5),
        .kdf = null,
    };
    var enc_buf: [MAX_HEADER_LEN]u8 = undefined;
    const bytes = h.encode(&enc_buf);

    var reader: std.Io.Reader = .fixed(bytes);
    var read_buf: [MAX_HEADER_LEN]u8 = undefined;
    const parsed = try Header.read(&reader, &read_buf);
    try std.testing.expectEqual(h.chunk_size, parsed.header.chunk_size);
    try std.testing.expectEqualSlices(u8, &h.file_nonce, &parsed.header.file_nonce);
    try std.testing.expect(parsed.header.kdf == null);
    try std.testing.expectEqualSlices(u8, bytes, parsed.raw_bytes);
}

test "header round-trip with KDF" {
    const h: Header = .{
        .chunk_size = DEFAULT_CHUNK_SIZE,
        .file_nonce = @splat(0x11),
        .kdf = .{
            .salt = @splat(0x33),
            .mem_kib = 65536,
            .iterations = 3,
            .parallelism = 4,
        },
    };
    var enc_buf: [MAX_HEADER_LEN]u8 = undefined;
    const bytes = h.encode(&enc_buf);

    var reader: std.Io.Reader = .fixed(bytes);
    var read_buf: [MAX_HEADER_LEN]u8 = undefined;
    const parsed = try Header.read(&reader, &read_buf);
    try std.testing.expect(parsed.header.kdf != null);
    try std.testing.expect(h.kdf.?.eql(parsed.header.kdf.?));
    try std.testing.expectEqualSlices(u8, bytes, parsed.raw_bytes);
}

test "header rejects bad magic" {
    const h: Header = .{ .chunk_size = 1024, .file_nonce = @splat(0), .kdf = null };
    var enc_buf: [MAX_HEADER_LEN]u8 = undefined;
    const bytes = h.encode(&enc_buf);
    bytes[0] = 'X';
    var reader: std.Io.Reader = .fixed(bytes);
    var read_buf: [MAX_HEADER_LEN]u8 = undefined;
    try std.testing.expectError(error.BadMagic, Header.read(&reader, &read_buf));
}

test "header rejects zero chunk size" {
    const h: Header = .{ .chunk_size = 1, .file_nonce = @splat(0), .kdf = null };
    var enc_buf: [MAX_HEADER_LEN]u8 = undefined;
    const bytes = h.encode(&enc_buf);
    std.mem.writeInt(u32, bytes[11..15], 0, .little);
    var reader: std.Io.Reader = .fixed(bytes);
    var read_buf: [MAX_HEADER_LEN]u8 = undefined;
    try std.testing.expectError(error.InvalidChunkSize, Header.read(&reader, &read_buf));
}

test "header rejects oversized chunk size" {
    const h: Header = .{ .chunk_size = 1, .file_nonce = @splat(0), .kdf = null };
    var enc_buf: [MAX_HEADER_LEN]u8 = undefined;
    const bytes = h.encode(&enc_buf);
    std.mem.writeInt(u32, bytes[11..15], MAX_CHUNK_SIZE + 1, .little);
    var reader: std.Io.Reader = .fixed(bytes);
    var read_buf: [MAX_HEADER_LEN]u8 = undefined;
    try std.testing.expectError(error.InvalidChunkSize, Header.read(&reader, &read_buf));
}

test "chunk framing round-trip" {
    const enc = encodeChunkFraming(12345, FINAL_CHUNK_FLAG);
    const dec = decodeChunkFraming(&enc);
    try std.testing.expectEqual(@as(u32, 12345), dec[0]);
    try std.testing.expectEqual(@as(u8, FINAL_CHUNK_FLAG), dec[1]);
    try std.testing.expectEqual(true, try validateChunkFlags(dec[1]));
    try std.testing.expectEqual(false, try validateChunkFlags(0));
    try std.testing.expectError(error.UnknownChunkFlags, validateChunkFlags(0x80));
}
