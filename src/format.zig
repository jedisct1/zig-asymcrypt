const std = @import("std");
const crypto = @import("crypto.zig");

pub const MAGIC = "ASYMCRY\x00";
pub const VERSION: u8 = 1;
pub const ALG_AEGIS_128X2: u8 = 1;
pub const KDF_ARGON2ID: u8 = 1;
pub const FLAG_PASSWORD_BLOB: u8 = 1;

pub const DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024;
pub const MAX_CHUNK_SIZE: u32 = 64 * 1024 * 1024;

pub const HEADER_FIXED_LEN: usize = 8 + 1 + 1 + 1 + 4 + crypto.FILE_NONCE_LEN + 2 + crypto.KEM_CT_LEN;
pub const ARGON2_METADATA_LEN: usize = 1 + 16 + 4 + 4 + 4;
pub const PASSWORD_BLOB_LEN: usize = crypto.ENCRYPTED_SEED_LEN + crypto.SEED_TAG_LEN + ARGON2_METADATA_LEN;
pub const MAX_HEADER_LEN: usize = HEADER_FIXED_LEN + PASSWORD_BLOB_LEN;

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

pub const PasswordBlob = struct {
    encrypted_seed: [crypto.ENCRYPTED_SEED_LEN]u8,
    seed_tag: [crypto.SEED_TAG_LEN]u8,
    argon2: Argon2Meta,

    pub fn encode(self: *const PasswordBlob) [PASSWORD_BLOB_LEN]u8 {
        var out: [PASSWORD_BLOB_LEN]u8 = undefined;
        out[0..crypto.ENCRYPTED_SEED_LEN].* = self.encrypted_seed;
        out[crypto.ENCRYPTED_SEED_LEN..][0..crypto.SEED_TAG_LEN].* = self.seed_tag;
        out[crypto.ENCRYPTED_SEED_LEN + crypto.SEED_TAG_LEN ..][0..ARGON2_METADATA_LEN].* = self.argon2.encode();
        return out;
    }

    pub const DecodeError = error{
        BadPasswordBlobLength,
    } || Argon2Meta.DecodeError;

    pub fn decode(buf: []const u8) DecodeError!PasswordBlob {
        if (buf.len != PASSWORD_BLOB_LEN) return error.BadPasswordBlobLength;
        return .{
            .encrypted_seed = buf[0..crypto.ENCRYPTED_SEED_LEN].*,
            .seed_tag = buf[crypto.ENCRYPTED_SEED_LEN..][0..crypto.SEED_TAG_LEN].*,
            .argon2 = try Argon2Meta.decode(buf[crypto.ENCRYPTED_SEED_LEN + crypto.SEED_TAG_LEN ..]),
        };
    }
};

pub const Header = struct {
    chunk_size: u32,
    file_nonce: crypto.FileNonce,
    kem_ciphertext: crypto.KemCiphertext,
    password_blob: ?PasswordBlob,

    pub fn encodedLen(self: *const Header) usize {
        return HEADER_FIXED_LEN + if (self.password_blob != null) PASSWORD_BLOB_LEN else 0;
    }

    pub fn encode(self: *const Header, buffer: *[MAX_HEADER_LEN]u8) []u8 {
        const out = buffer[0..self.encodedLen()];
        const blob_len: u16 = if (self.password_blob != null) PASSWORD_BLOB_LEN else 0;
        out[0..8].* = MAGIC.*;
        out[8] = VERSION;
        out[9] = ALG_AEGIS_128X2;
        out[10] = if (self.password_blob != null) FLAG_PASSWORD_BLOB else 0;
        std.mem.writeInt(u32, out[11..15], self.chunk_size, .little);
        out[15..31].* = self.file_nonce;
        std.mem.writeInt(u16, out[31..33], blob_len, .little);
        out[33..][0..crypto.KEM_CT_LEN].* = self.kem_ciphertext;
        if (self.password_blob) |blob| {
            out[HEADER_FIXED_LEN..][0..PASSWORD_BLOB_LEN].* = blob.encode();
        }
        return out;
    }

    pub const Parsed = struct {
        header: Header,
        raw_bytes: []u8,
    };

    pub fn read(reader: *std.Io.Reader, buffer: *[MAX_HEADER_LEN]u8) !Parsed {
        const fixed = buffer[0..HEADER_FIXED_LEN];
        try reader.readSliceAll(fixed);
        if (!std.mem.eql(u8, fixed[0..8], MAGIC)) return error.BadMagic;
        if (fixed[8] != VERSION) return error.UnsupportedVersion;
        if (fixed[9] != ALG_AEGIS_128X2) return error.UnsupportedAlgorithm;
        const flags = fixed[10];
        if ((flags & ~@as(u8, FLAG_PASSWORD_BLOB)) != 0) return error.UnknownHeaderFlags;
        const chunk_size = std.mem.readInt(u32, fixed[11..15], .little);
        if (chunk_size == 0 or chunk_size > MAX_CHUNK_SIZE) return error.InvalidChunkSize;
        const header_len: usize = std.mem.readInt(u16, fixed[31..33], .little);
        if (header_len > PASSWORD_BLOB_LEN) return error.UnknownHeaderFlags;

        const trailer = buffer[HEADER_FIXED_LEN..][0..header_len];
        if (header_len > 0) try reader.readSliceAll(trailer);

        var password_blob: ?PasswordBlob = null;
        if ((flags & FLAG_PASSWORD_BLOB) != 0) {
            password_blob = try PasswordBlob.decode(trailer);
        } else if (header_len != 0) {
            return error.MetadataPresentWithoutBlobFlag;
        }

        return .{
            .header = .{
                .chunk_size = chunk_size,
                .file_nonce = fixed[15..31].*,
                .kem_ciphertext = fixed[33..][0..crypto.KEM_CT_LEN].*,
                .password_blob = password_blob,
            },
            .raw_bytes = buffer[0 .. HEADER_FIXED_LEN + header_len],
        };
    }
};

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

test "header round-trip without password blob" {
    const h: Header = .{
        .chunk_size = 64 * 1024,
        .file_nonce = @splat(0xa5),
        .kem_ciphertext = @splat(0x33),
        .password_blob = null,
    };
    var enc_buf: [MAX_HEADER_LEN]u8 = undefined;
    const bytes = h.encode(&enc_buf);

    var reader: std.Io.Reader = .fixed(bytes);
    var read_buf: [MAX_HEADER_LEN]u8 = undefined;
    const parsed = try Header.read(&reader, &read_buf);
    try std.testing.expectEqual(h.chunk_size, parsed.header.chunk_size);
    try std.testing.expectEqualSlices(u8, &h.file_nonce, &parsed.header.file_nonce);
    try std.testing.expectEqualSlices(u8, &h.kem_ciphertext, &parsed.header.kem_ciphertext);
    try std.testing.expect(parsed.header.password_blob == null);
    try std.testing.expectEqualSlices(u8, bytes, parsed.raw_bytes);
}

test "header round-trip with password blob" {
    const h: Header = .{
        .chunk_size = DEFAULT_CHUNK_SIZE,
        .file_nonce = @splat(0x11),
        .kem_ciphertext = @splat(0x55),
        .password_blob = .{
            .encrypted_seed = @splat(0xaa),
            .seed_tag = @splat(0xbb),
            .argon2 = .{
                .salt = @splat(0x33),
                .mem_kib = 65536,
                .iterations = 3,
                .parallelism = 4,
            },
        },
    };
    var enc_buf: [MAX_HEADER_LEN]u8 = undefined;
    const bytes = h.encode(&enc_buf);

    var reader: std.Io.Reader = .fixed(bytes);
    var read_buf: [MAX_HEADER_LEN]u8 = undefined;
    const parsed = try Header.read(&reader, &read_buf);
    try std.testing.expect(parsed.header.password_blob != null);
    const blob = parsed.header.password_blob.?;
    try std.testing.expectEqualSlices(u8, &h.password_blob.?.encrypted_seed, &blob.encrypted_seed);
    try std.testing.expectEqualSlices(u8, &h.password_blob.?.seed_tag, &blob.seed_tag);
    try std.testing.expect(h.password_blob.?.argon2.eql(blob.argon2));
    try std.testing.expectEqualSlices(u8, bytes, parsed.raw_bytes);
}

test "header rejects bad magic" {
    const h: Header = .{ .chunk_size = 1024, .file_nonce = @splat(0), .kem_ciphertext = @splat(0), .password_blob = null };
    var enc_buf: [MAX_HEADER_LEN]u8 = undefined;
    const bytes = h.encode(&enc_buf);
    bytes[0] = 'X';
    var reader: std.Io.Reader = .fixed(bytes);
    var read_buf: [MAX_HEADER_LEN]u8 = undefined;
    try std.testing.expectError(error.BadMagic, Header.read(&reader, &read_buf));
}

test "header rejects zero chunk size" {
    const h: Header = .{ .chunk_size = 1, .file_nonce = @splat(0), .kem_ciphertext = @splat(0), .password_blob = null };
    var enc_buf: [MAX_HEADER_LEN]u8 = undefined;
    const bytes = h.encode(&enc_buf);
    std.mem.writeInt(u32, bytes[11..15], 0, .little);
    var reader: std.Io.Reader = .fixed(bytes);
    var read_buf: [MAX_HEADER_LEN]u8 = undefined;
    try std.testing.expectError(error.InvalidChunkSize, Header.read(&reader, &read_buf));
}

test "header rejects oversized chunk size" {
    const h: Header = .{ .chunk_size = 1, .file_nonce = @splat(0), .kem_ciphertext = @splat(0), .password_blob = null };
    var enc_buf: [MAX_HEADER_LEN]u8 = undefined;
    const bytes = h.encode(&enc_buf);
    std.mem.writeInt(u32, bytes[11..15], MAX_CHUNK_SIZE + 1, .little);
    var reader: std.Io.Reader = .fixed(bytes);
    var read_buf: [MAX_HEADER_LEN]u8 = undefined;
    try std.testing.expectError(error.InvalidChunkSize, Header.read(&reader, &read_buf));
}

test "password blob round-trip" {
    const blob: PasswordBlob = .{
        .encrypted_seed = @splat(0x11),
        .seed_tag = @splat(0x22),
        .argon2 = .{
            .salt = @splat(0x44),
            .mem_kib = 32768,
            .iterations = 2,
            .parallelism = 1,
        },
    };
    const encoded = blob.encode();
    try std.testing.expectEqual(@as(usize, PASSWORD_BLOB_LEN), encoded.len);
    const decoded = try PasswordBlob.decode(&encoded);
    try std.testing.expectEqualSlices(u8, &blob.encrypted_seed, &decoded.encrypted_seed);
    try std.testing.expectEqualSlices(u8, &blob.seed_tag, &decoded.seed_tag);
    try std.testing.expect(blob.argon2.eql(decoded.argon2));
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
