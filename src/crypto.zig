const std = @import("std");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Aegis = std.crypto.aead.aegis.Aegis128X2_256;
const XWing = std.crypto.kem.hybrid.MlKem768X25519;

pub const CIPHER_KEY_LEN: usize = 16;
pub const TAG_LEN: usize = 32;
pub const NONCE_LEN: usize = 16;
pub const FILE_NONCE_LEN: usize = 16;

pub const EK_LEN: usize = 1216;
pub const DK_SEED_LEN: usize = 32;
pub const KEM_CT_LEN: usize = 1120;
pub const SHARED_SECRET_LEN: usize = 32;

pub const ENCRYPTED_SEED_LEN: usize = DK_SEED_LEN;
pub const SEED_TAG_LEN: usize = TAG_LEN;

pub const FILE_DERIVATION_LABEL = "asymcrypt file derivation v1";
pub const DK_WRAP_NONCE_LABEL = "asymcrypt dk wrap nonce v1";

pub const CipherKey = [CIPHER_KEY_LEN]u8;
pub const Nonce = [NONCE_LEN]u8;
pub const FileNonce = [FILE_NONCE_LEN]u8;
pub const Tag = [TAG_LEN]u8;
pub const SharedSecret = [SHARED_SECRET_LEN]u8;
pub const EncapsulationKey = [EK_LEN]u8;
pub const DecapsulationSeed = [DK_SEED_LEN]u8;
pub const KemCiphertext = [KEM_CT_LEN]u8;

fn hmacParts(key: []const u8, parts: []const []const u8) [HmacSha256.mac_length]u8 {
    var ctx = HmacSha256.init(key);
    for (parts) |p| ctx.update(p);
    var out: [HmacSha256.mac_length]u8 = undefined;
    ctx.final(&out);
    return out;
}

pub fn deriveFileSecrets(shared_secret: *const SharedSecret, file_nonce: *const FileNonce) struct { CipherKey, Nonce } {
    var full = hmacParts(shared_secret, &.{ FILE_DERIVATION_LABEL, file_nonce });
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

pub fn kemGenerate(io: std.Io) !struct { DecapsulationSeed, EncapsulationKey } {
    const kp = try XWing.KeyPair.generate(io);
    return .{ kp.secret_key.toBytes(), kp.public_key.toBytes() };
}

pub fn kemEncapsulate(ek_bytes: *const EncapsulationKey, io: std.Io) !struct { KemCiphertext, SharedSecret } {
    const pk = XWing.PublicKey.fromBytes(ek_bytes);
    const result = try pk.encaps(io);
    return .{ result.ciphertext, result.shared_secret };
}

pub fn kemDecapsulate(seed: *const DecapsulationSeed, ct: *const KemCiphertext) !SharedSecret {
    const sk = XWing.SecretKey.fromBytes(seed);
    return try sk.decaps(ct);
}

fn dkWrapParams(argon2_key: *const SharedSecret) struct { CipherKey, Nonce } {
    const wrap_key: CipherKey = argon2_key[0..CIPHER_KEY_LEN].*;
    var nonce_full = hmacParts(argon2_key, &.{DK_WRAP_NONCE_LABEL});
    defer std.crypto.secureZero(u8, &nonce_full);
    const wrap_nonce: Nonce = nonce_full[0..NONCE_LEN].*;
    return .{ wrap_key, wrap_nonce };
}

pub fn wrapDkSeed(
    argon2_key: *const SharedSecret,
    seed: *const DecapsulationSeed,
) struct { [ENCRYPTED_SEED_LEN]u8, [SEED_TAG_LEN]u8 } {
    var params = dkWrapParams(argon2_key);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&params));
    var ct: [ENCRYPTED_SEED_LEN]u8 = seed.*;
    var tag: Tag = undefined;
    Aegis.encrypt(&ct, &tag, &ct, "", params[1], params[0]);
    return .{ ct, tag };
}

pub fn unwrapDkSeed(
    argon2_key: *const SharedSecret,
    encrypted_seed: *const [ENCRYPTED_SEED_LEN]u8,
    seed_tag: *const [SEED_TAG_LEN]u8,
) error{AuthenticationFailed}!DecapsulationSeed {
    var params = dkWrapParams(argon2_key);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&params));
    var seed: DecapsulationSeed = encrypted_seed.*;
    try Aegis.decrypt(&seed, &seed, seed_tag.*, "", params[1], params[0]);
    return seed;
}

pub fn encryptChunkInPlace(key: *const CipherKey, nonce: *const Nonce, buf: []u8, ad: []const u8) Tag {
    var tag: Tag = undefined;
    Aegis.encrypt(buf, &tag, buf, ad, nonce.*, key.*);
    return tag;
}

pub fn decryptChunkInPlace(key: *const CipherKey, nonce: *const Nonce, buf: []u8, tag: *const Tag, ad: []const u8) error{AuthenticationFailed}!void {
    try Aegis.decrypt(buf, buf, tag.*, ad, nonce.*, key.*);
}

test "deriveFileSecrets is deterministic" {
    const k: SharedSecret = @splat(0x42);
    const fn_: FileNonce = @splat(0x9e);
    const a = deriveFileSecrets(&k, &fn_);
    const b = deriveFileSecrets(&k, &fn_);
    try std.testing.expectEqualSlices(u8, &a[0], &b[0]);
    try std.testing.expectEqualSlices(u8, &a[1], &b[1]);
}

test "deriveFileSecrets depends on each input" {
    const k1: SharedSecret = @splat(1);
    const k2: SharedSecret = @splat(2);
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

test "deriveFileSecrets halves differ" {
    const k: SharedSecret = @splat(0);
    const fn_: FileNonce = @splat(0);
    const got = deriveFileSecrets(&k, &fn_);
    try std.testing.expect(!std.mem.eql(u8, &got[0], &@as([NONCE_LEN]u8, got[1])));
}

test "deriveFileSecrets known vector" {
    const k: SharedSecret = @splat(0);
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

test "KEM round trip" {
    const kp = try XWing.KeyPair.generateDeterministic(@as([32]u8, @splat(0x42)));
    const result = try kp.public_key.encapsDeterministic(&@as([64]u8, @splat(0x99)));
    const ss_dec = try kp.secret_key.decaps(&result.ciphertext);
    try std.testing.expectEqualSlices(u8, &result.shared_secret, &ss_dec);
}

test "KEM wrong seed produces different shared secret" {
    const kp1 = try XWing.KeyPair.generateDeterministic(@as([32]u8, @splat(0x42)));
    const kp2 = try XWing.KeyPair.generateDeterministic(@as([32]u8, @splat(0x99)));
    const result = try kp1.public_key.encapsDeterministic(&@as([64]u8, @splat(0xaa)));
    const ss_wrong = try kp2.secret_key.decaps(&result.ciphertext);
    try std.testing.expect(!std.mem.eql(u8, &result.shared_secret, &ss_wrong));
}

test "wrap/unwrap DK seed round trip" {
    const key: SharedSecret = @splat(0xab);
    const seed: DecapsulationSeed = @splat(0x42);
    const wrapped = wrapDkSeed(&key, &seed);
    const recovered = try unwrapDkSeed(&key, &wrapped[0], &wrapped[1]);
    try std.testing.expectEqualSlices(u8, &seed, &recovered);
}

test "unwrap DK seed wrong key fails" {
    const key: SharedSecret = @splat(0xab);
    const seed: DecapsulationSeed = @splat(0x42);
    const wrapped = wrapDkSeed(&key, &seed);
    const wrong_key: SharedSecret = @splat(0xcd);
    try std.testing.expectError(error.AuthenticationFailed, unwrapDkSeed(&wrong_key, &wrapped[0], &wrapped[1]));
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
