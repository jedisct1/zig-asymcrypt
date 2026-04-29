const std = @import("std");
const crypto = @import("crypto.zig");
const format = @import("format.zig");

pub const KEY_TYPE_PLAIN_V1: u8 = 0x01;
pub const KEY_TYPE_COMPOSITE_V1: u8 = 0x02;
pub const KEY_TYPE_RECOVERY_V1: u8 = 0x03;

pub const KeyFileFormat = enum { raw, hex };
pub const KeyRole = enum { chain, recovery };

pub const KeyKind = union(enum) {
    plain_chain,
    composite_chain: format.Argon2Meta,
    plain_recovery,

    pub fn typeByte(self: KeyKind) u8 {
        return switch (self) {
            .plain_chain => KEY_TYPE_PLAIN_V1,
            .composite_chain => KEY_TYPE_COMPOSITE_V1,
            .plain_recovery => KEY_TYPE_RECOVERY_V1,
        };
    }

    pub fn kdfMeta(self: KeyKind) ?format.Argon2Meta {
        return switch (self) {
            .composite_chain => |m| m,
            else => null,
        };
    }

    pub fn chainFromKdf(kdf: ?format.Argon2Meta) KeyKind {
        if (kdf) |m| return .{ .composite_chain = m };
        return .plain_chain;
    }
};

pub const ParsedKeyFile = struct {
    key: crypto.MasterKey,
    kdf: ?format.Argon2Meta,
    file_format: KeyFileFormat,
    role: KeyRole,
};

pub const MAX_RAW_KEY_FILE_LEN = 1 + crypto.MASTER_KEY_LEN + format.ARGON2_METADATA_LEN;
pub const MAX_HEX_KEY_FILE_LEN = MAX_RAW_KEY_FILE_LEN * 2;

pub const ParseError = error{
    UnrecognisedKeyFile,
    InvalidHexKey,
    BodyLengthMismatch,
} || format.Argon2Meta.DecodeError;

pub fn parseKeyFile(bytes: []const u8) ParseError!ParsedKeyFile {
    if (try tryParseRaw(bytes, .raw)) |p| return p;

    var trimmed_buf: [MAX_HEX_KEY_FILE_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &trimmed_buf);
    var trimmed_len: usize = 0;
    for (bytes) |b| {
        if (std.ascii.isWhitespace(b)) continue;
        if (trimmed_len == trimmed_buf.len) return error.UnrecognisedKeyFile;
        trimmed_buf[trimmed_len] = b;
        trimmed_len += 1;
    }
    if (trimmed_len == 0) return error.UnrecognisedKeyFile;

    var decoded: [MAX_RAW_KEY_FILE_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &decoded);
    const slice = std.fmt.hexToBytes(&decoded, trimmed_buf[0..trimmed_len]) catch
        return error.UnrecognisedKeyFile;
    if (try tryParseRaw(slice, .hex)) |p| return p;
    return error.UnrecognisedKeyFile;
}

fn tryParseRaw(bytes: []const u8, file_format: KeyFileFormat) !?ParsedKeyFile {
    if (bytes.len == 0) return null;
    const TagInfo = struct { role: KeyRole, expected_extra: usize, has_kdf: bool };
    const info: TagInfo = switch (bytes[0]) {
        KEY_TYPE_PLAIN_V1 => .{ .role = .chain, .expected_extra = 0, .has_kdf = false },
        KEY_TYPE_COMPOSITE_V1 => .{ .role = .chain, .expected_extra = format.ARGON2_METADATA_LEN, .has_kdf = true },
        KEY_TYPE_RECOVERY_V1 => .{ .role = .recovery, .expected_extra = 0, .has_kdf = false },
        else => return null,
    };
    const body = bytes[1..];
    if (body.len != crypto.MASTER_KEY_LEN + info.expected_extra) return error.BodyLengthMismatch;

    var parsed: ParsedKeyFile = .{
        .key = body[0..crypto.MASTER_KEY_LEN].*,
        .kdf = null,
        .file_format = file_format,
        .role = info.role,
    };
    if (info.has_kdf) parsed.kdf = try format.Argon2Meta.decode(body[crypto.MASTER_KEY_LEN..]);
    return parsed;
}

pub const MAX_ENCODED_KEY_FILE_LEN = MAX_RAW_KEY_FILE_LEN * 2 + 1;

pub fn encodeKeyFile(
    buffer: *[MAX_ENCODED_KEY_FILE_LEN]u8,
    key: *const crypto.MasterKey,
    kind: KeyKind,
    file_format: KeyFileFormat,
) []u8 {
    var raw_buf: [MAX_RAW_KEY_FILE_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &raw_buf);

    var raw_len: usize = 1 + crypto.MASTER_KEY_LEN;
    raw_buf[0] = kind.typeByte();
    raw_buf[1..][0..crypto.MASTER_KEY_LEN].* = key.*;
    if (kind.kdfMeta()) |meta| {
        raw_buf[raw_len..][0..format.ARGON2_METADATA_LEN].* = meta.encode();
        raw_len += format.ARGON2_METADATA_LEN;
    }

    switch (file_format) {
        .raw => {
            @memcpy(buffer[0..raw_len], raw_buf[0..raw_len]);
            return buffer[0..raw_len];
        },
        .hex => {
            const total = raw_len * 2 + 1;
            const out = buffer[0..total];
            return std.fmt.bufPrint(out, "{x}\n", .{raw_buf[0..raw_len]}) catch unreachable;
        },
    }
}

pub fn parentOrCwd(path: []const u8) []const u8 {
    return std.fs.path.dirname(path) orelse ".";
}

pub const KeyLock = struct {
    file: std.Io.File,
    io: std.Io,

    pub fn acquire(io: std.Io, key_path: []const u8) !KeyLock {
        var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const lock_path = std.fmt.bufPrint(&path_buf, "{s}.lock", .{key_path}) catch
            return error.NameTooLong;
        const file = try std.Io.Dir.cwd().createFile(io, lock_path, .{
            .read = true,
            .truncate = false,
            .lock = .exclusive,
        });
        return .{ .file = file, .io = io };
    }

    pub fn release(self: *KeyLock) void {
        self.file.close(self.io);
        self.* = undefined;
    }
};

pub const PermsError = error{InsecureKeyFilePermissions};

/// Returns the file's permission bits (0..0o777) so callers can preserve the
/// mode across rotation. Errors with `InsecureKeyFilePermissions` if any
/// group/world bit is set and `allow_insecure` is false.
pub fn checkKeyPermissions(
    io: std.Io,
    path: []const u8,
    allow_insecure: bool,
) !u32 {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    const stat = try file.stat(io);
    const mode = fileMode(stat);
    if (!allow_insecure and (mode & 0o077) != 0) return error.InsecureKeyFilePermissions;
    return mode;
}

pub const ReadCheckedResult = struct { bytes: []u8, mode: u32 };

pub fn readKeyFileChecked(
    io: std.Io,
    gpa: std.mem.Allocator,
    path: []const u8,
    allow_insecure: bool,
) !ReadCheckedResult {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    const stat = try file.stat(io);
    const mode = fileMode(stat);
    if (!allow_insecure and (mode & 0o077) != 0) return error.InsecureKeyFilePermissions;
    const size: usize = @intCast(stat.size);
    const bytes = try gpa.alloc(u8, size);
    errdefer gpa.free(bytes);
    var read_buf: [4096]u8 = undefined;
    var fr = file.reader(io, &read_buf);
    try fr.interface.readSliceAll(bytes);
    return .{ .bytes = bytes, .mode = mode };
}

fn fileMode(stat: std.Io.File.Stat) u32 {
    if (comptime !@hasDecl(std.Io.File.Permissions, "toMode")) return 0;
    return @intCast(stat.permissions.toMode() & 0o777);
}

/// Atomically write `bytes` to `path`. With `replace = false` the operation
/// fails if `path` already exists.
pub fn writeKeyFileDurable(
    io: std.Io,
    path: []const u8,
    bytes: []const u8,
    mode: ?u32,
    replace: bool,
) !void {
    var dir = try std.Io.Dir.cwd().openDir(io, parentOrCwd(path), .{});
    defer dir.close(io);

    const perms: std.Io.File.Permissions = if (mode) |m|
        .fromMode(@intCast(m))
    else
        .default_file;

    var atomic = try dir.createFileAtomic(io, std.fs.path.basename(path), .{
        .permissions = perms,
        .replace = replace,
    });
    defer atomic.deinit(io);

    var buf: [8192]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    var w = atomic.file.writer(io, &buf);
    try w.interface.writeAll(bytes);
    try w.interface.flush();
    try atomic.file.sync(io);
    if (replace) try atomic.replace(io) else try atomic.link(io);
}

pub fn randomKey(io: std.Io) !crypto.MasterKey {
    var k: crypto.MasterKey = undefined;
    try io.randomSecure(&k);
    return k;
}

test "parse raw plain key" {
    const key: crypto.MasterKey = @splat(7);
    var bytes: [1 + crypto.MASTER_KEY_LEN]u8 = undefined;
    bytes[0] = KEY_TYPE_PLAIN_V1;
    bytes[1..].* = key;
    const parsed = try parseKeyFile(&bytes);
    try std.testing.expectEqualSlices(u8, &key, &parsed.key);
    try std.testing.expect(parsed.kdf == null);
    try std.testing.expectEqual(KeyFileFormat.raw, parsed.file_format);
    try std.testing.expectEqual(KeyRole.chain, parsed.role);
}

test "parse raw composite key" {
    const key: crypto.MasterKey = @splat(0xa5);
    const meta: format.Argon2Meta = .{
        .salt = @splat(0x33),
        .mem_kib = 65536,
        .iterations = 3,
        .parallelism = 4,
    };
    var enc_buf: [MAX_ENCODED_KEY_FILE_LEN]u8 = undefined;
    const enc = encodeKeyFile(&enc_buf, &key, .{ .composite_chain = meta }, .raw);
    const parsed = try parseKeyFile(enc);
    try std.testing.expectEqualSlices(u8, &key, &parsed.key);
    try std.testing.expect(parsed.kdf.?.eql(meta));
    try std.testing.expectEqual(KeyFileFormat.raw, parsed.file_format);
    try std.testing.expectEqual(KeyRole.chain, parsed.role);
}

test "parse raw recovery key" {
    const key: crypto.MasterKey = @splat(0x5a);
    var enc_buf: [MAX_ENCODED_KEY_FILE_LEN]u8 = undefined;
    const enc = encodeKeyFile(&enc_buf, &key, .plain_recovery, .raw);
    try std.testing.expectEqual(@as(u8, KEY_TYPE_RECOVERY_V1), enc[0]);
    try std.testing.expectEqual(@as(usize, 1 + crypto.MASTER_KEY_LEN), enc.len);
    const parsed = try parseKeyFile(enc);
    try std.testing.expectEqualSlices(u8, &key, &parsed.key);
    try std.testing.expect(parsed.kdf == null);
    try std.testing.expectEqual(KeyRole.recovery, parsed.role);
}

test "parse hex plain key" {
    const key: crypto.MasterKey = @splat(0x11);
    var enc_buf: [MAX_ENCODED_KEY_FILE_LEN]u8 = undefined;
    const enc = encodeKeyFile(&enc_buf, &key, .plain_chain, .hex);
    const parsed = try parseKeyFile(enc);
    try std.testing.expectEqualSlices(u8, &key, &parsed.key);
    try std.testing.expectEqual(KeyFileFormat.hex, parsed.file_format);
    try std.testing.expectEqual(KeyRole.chain, parsed.role);
}

test "parse hex recovery key" {
    const key: crypto.MasterKey = @splat(0x99);
    var enc_buf: [MAX_ENCODED_KEY_FILE_LEN]u8 = undefined;
    const enc = encodeKeyFile(&enc_buf, &key, .plain_recovery, .hex);
    for (enc) |b| try std.testing.expect(std.ascii.isHex(b) or b == '\n');
    const parsed = try parseKeyFile(enc);
    try std.testing.expectEqualSlices(u8, &key, &parsed.key);
    try std.testing.expectEqual(KeyRole.recovery, parsed.role);
    try std.testing.expectEqual(KeyFileFormat.hex, parsed.file_format);
}

test "parse hex composite key with surrounding whitespace" {
    const gpa = std.testing.allocator;
    const key: crypto.MasterKey = @splat(0x22);
    const meta: format.Argon2Meta = .{
        .salt = @splat(0x33),
        .mem_kib = 65536,
        .iterations = 3,
        .parallelism = 4,
    };
    var enc_buf: [MAX_ENCODED_KEY_FILE_LEN]u8 = undefined;
    const enc = encodeKeyFile(&enc_buf, &key, .{ .composite_chain = meta }, .hex);
    var padded: std.ArrayList(u8) = .empty;
    defer padded.deinit(gpa);
    try padded.appendSlice(gpa, "   ");
    try padded.appendSlice(gpa, enc);
    try padded.appendSlice(gpa, "\n  \n");
    const parsed = try parseKeyFile(padded.items);
    try std.testing.expectEqualSlices(u8, &key, &parsed.key);
    try std.testing.expect(parsed.kdf.?.eql(meta));
    try std.testing.expectEqual(KeyFileFormat.hex, parsed.file_format);
    try std.testing.expectEqual(KeyRole.chain, parsed.role);
}

test "rejects short input" {
    try std.testing.expectError(error.UnrecognisedKeyFile, parseKeyFile(&.{}));
    try std.testing.expectError(error.BodyLengthMismatch, parseKeyFile(&.{ KEY_TYPE_PLAIN_V1, 1, 2, 3 }));
}

test "rejects recovery body wrong length" {
    var bytes_short: [1 + crypto.MASTER_KEY_LEN - 1]u8 = .{KEY_TYPE_RECOVERY_V1} ++ @as([crypto.MASTER_KEY_LEN - 1]u8, @splat(0));
    try std.testing.expectError(error.BodyLengthMismatch, parseKeyFile(&bytes_short));
    var bytes_long: [1 + crypto.MASTER_KEY_LEN + 1]u8 = .{KEY_TYPE_RECOVERY_V1} ++ @as([crypto.MASTER_KEY_LEN + 1]u8, @splat(0));
    try std.testing.expectError(error.BodyLengthMismatch, parseKeyFile(&bytes_long));
}

test "rejects unknown type" {
    var bytes: [1 + crypto.MASTER_KEY_LEN]u8 = undefined;
    bytes[0] = 0xff;
    @memset(bytes[1..], 0);
    try std.testing.expectError(error.UnrecognisedKeyFile, parseKeyFile(&bytes));
}

test "rejects bad hex" {
    try std.testing.expectError(error.UnrecognisedKeyFile, parseKeyFile("zz112233445566778899aabbccddeeff"));
}

test "encode recovery first byte" {
    const key: crypto.MasterKey = @splat(0);
    var enc_buf: [MAX_ENCODED_KEY_FILE_LEN]u8 = undefined;
    const raw = encodeKeyFile(&enc_buf, &key, .plain_recovery, .raw);
    try std.testing.expectEqual(@as(u8, KEY_TYPE_RECOVERY_V1), raw[0]);
    try std.testing.expectEqual(@as(usize, 1 + crypto.MASTER_KEY_LEN), raw.len);
}
