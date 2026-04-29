const std = @import("std");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Aegis = std.crypto.aead.aegis.Aegis128X2_256;

pub const MASTER_KEY_LEN: usize = 32;
pub const CIPHER_KEY_LEN: usize = 16;
pub const TAG_LEN: usize = 32;
pub const NONCE_LEN: usize = 16;
pub const FILE_NONCE_LEN: usize = 16;
pub const KEY_CHECK_LEN: usize = 32;

pub const KEY_EVOLUTION_LABEL = "asymcrypt key evolution v1";
pub const FILE_DERIVATION_LABEL = "asymcrypt file derivation v1";
pub const KEY_CHECK_LABEL = "asymcrypt key check v1";

pub const MasterKey = [MASTER_KEY_LEN]u8;
pub const CipherKey = [CIPHER_KEY_LEN]u8;
pub const Nonce = [NONCE_LEN]u8;
pub const FileNonce = [FILE_NONCE_LEN]u8;
pub const Tag = [TAG_LEN]u8;
pub const KeyCheck = [KEY_CHECK_LEN]u8;

fn hmacParts(key: []const u8, parts: []const []const u8) [HmacSha256.mac_length]u8 {
    var ctx = HmacSha256.init(key);
    for (parts) |p| ctx.update(p);
    var out: [HmacSha256.mac_length]u8 = undefined;
    ctx.final(&out);
    return out;
}

pub fn evolveKey(key: *MasterKey) void {
    var full = hmacParts(key, &.{KEY_EVOLUTION_LABEL});
    defer std.crypto.secureZero(u8, &full);
    key.* = full;
}

pub fn deriveFileSecrets(stream_key: *const MasterKey, file_nonce: *const FileNonce) struct { CipherKey, Nonce } {
    var full = hmacParts(stream_key, &.{ FILE_DERIVATION_LABEL, file_nonce });
    defer std.crypto.secureZero(u8, &full);
    return .{
        full[0..CIPHER_KEY_LEN].*,
        full[CIPHER_KEY_LEN..][0..NONCE_LEN].*,
    };
}

pub fn deriveChunkNonce(base_nonce: *const Nonce, chunk_index: u64) Nonce {
    var nonce = base_nonce.*;
    var idx: [8]u8 = undefined;
    std.mem.writeInt(u64, &idx, chunk_index, .little);
    for (nonce[0..8], 0..) |*b, i| b.* ^= idx[i];
    return nonce;
}

pub fn keyCheck(stream_key: *const MasterKey, file_nonce: *const FileNonce) KeyCheck {
    return hmacParts(stream_key, &.{ KEY_CHECK_LABEL, file_nonce });
}

pub fn encryptChunkInPlace(key: *const CipherKey, nonce: *const Nonce, buf: []u8, ad: []const u8) Tag {
    var tag: Tag = undefined;
    Aegis.encrypt(buf, &tag, buf, ad, nonce.*, key.*);
    return tag;
}

pub fn decryptChunkInPlace(key: *const CipherKey, nonce: *const Nonce, buf: []u8, tag: *const Tag, ad: []const u8) error{AuthenticationFailed}!void {
    try Aegis.decrypt(buf, buf, tag.*, ad, nonce.*, key.*);
}

test "evolveKey is deterministic" {
    var a: MasterKey = @splat(0x42);
    var b: MasterKey = @splat(0x42);
    evolveKey(&a);
    evolveKey(&b);
    try std.testing.expectEqualSlices(u8, &a, &b);
    const original: MasterKey = @splat(0x42);
    try std.testing.expect(!std.mem.eql(u8, &a, &original));
}

test "evolveKey known vector" {
    var k: MasterKey = @splat(0);
    evolveKey(&k);
    const expected = hmacParts(&@as([MASTER_KEY_LEN]u8, @splat(0)), &.{KEY_EVOLUTION_LABEL});
    try std.testing.expectEqualSlices(u8, &expected, &k);
}

test "deriveFileSecrets is deterministic" {
    const k: MasterKey = @splat(0x42);
    const fn_: FileNonce = @splat(0x9e);
    const a = deriveFileSecrets(&k, &fn_);
    const b = deriveFileSecrets(&k, &fn_);
    try std.testing.expectEqualSlices(u8, &a[0], &b[0]);
    try std.testing.expectEqualSlices(u8, &a[1], &b[1]);
}

test "deriveFileSecrets depends on each input" {
    const k1: MasterKey = @splat(1);
    const k2: MasterKey = @splat(2);
    const fn1: FileNonce = @splat(0x55);
    const fn2: FileNonce = @splat(0xaa);
    const a = deriveFileSecrets(&k1, &fn1);
    const b = deriveFileSecrets(&k2, &fn1);
    const c = deriveFileSecrets(&k1, &fn2);
    try std.testing.expect(!std.mem.eql(u8, &a[0], &b[0]));
    try std.testing.expect(!std.mem.eql(u8, &a[1], &b[1]));
    try std.testing.expect(!std.mem.eql(u8, &a[0], &c[0]));
    try std.testing.expect(!std.mem.eql(u8, &a[1], &c[1]));
}

test "deriveFileSecrets known vector" {
    const k: MasterKey = @splat(0);
    const fn_: FileNonce = @splat(0);
    const got = deriveFileSecrets(&k, &fn_);
    const expected = hmacParts(&k, &.{ FILE_DERIVATION_LABEL, &fn_ });
    try std.testing.expectEqualSlices(u8, expected[0..CIPHER_KEY_LEN], &got[0]);
    try std.testing.expectEqualSlices(u8, expected[CIPHER_KEY_LEN..][0..NONCE_LEN], &got[1]);
}

test "chunk nonce XOR counter" {
    const base: Nonce = .{
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00,
    };
    const indices = [_]u64{ 0, 1, 0xff, 0x12345678, std.math.maxInt(u64) };
    for (indices) |i| {
        const got = deriveChunkNonce(&base, i);
        var want = base;
        var idx: [8]u8 = undefined;
        std.mem.writeInt(u64, &idx, i, .little);
        for (want[0..8], 0..) |*b, j| b.* ^= idx[j];
        try std.testing.expectEqualSlices(u8, &want, &got);
    }
}

test "chunk nonce high half is invariant" {
    const base: Nonce = @splat(0x77);
    const indices = [_]u64{ 0, 1, 0x100, std.math.maxInt(u64) };
    for (indices) |i| {
        const n = deriveChunkNonce(&base, i);
        try std.testing.expectEqualSlices(u8, base[8..], n[8..]);
    }
}

test "keyCheck matches label" {
    const k: MasterKey = @splat(0xab);
    const fn_: FileNonce = @splat(0x5c);
    const kc = keyCheck(&k, &fn_);
    const expected = hmacParts(&k, &.{ KEY_CHECK_LABEL, &fn_ });
    try std.testing.expectEqualSlices(u8, &expected, &kc);
}

test "keyCheck binds to file nonce" {
    const k: MasterKey = @splat(0xab);
    const a = keyCheck(&k, &@as(FileNonce, @splat(0)));
    const b = keyCheck(&k, &@as(FileNonce, @splat(1)));
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}

test "AEGIS round trip and tamper" {
    const key: CipherKey = @splat(9);
    const nonce: Nonce = @splat(3);
    const m = "the quick brown fox jumps over the lazy dog";
    const ad = "AD";
    var buf: [m.len]u8 = undefined;
    @memcpy(&buf, m);
    const tag = encryptChunkInPlace(&key, &nonce, &buf, ad);
    try std.testing.expect(!std.mem.eql(u8, &buf, m));
    try decryptChunkInPlace(&key, &nonce, &buf, &tag, ad);
    try std.testing.expectEqualSlices(u8, m, &buf);

    var bad_tag = tag;
    bad_tag[0] ^= 1;
    var buf2: [m.len]u8 = undefined;
    @memcpy(&buf2, m);
    _ = encryptChunkInPlace(&key, &nonce, &buf2, ad);
    try std.testing.expectError(error.AuthenticationFailed, decryptChunkInPlace(&key, &nonce, &buf2, &bad_tag, ad));
}
