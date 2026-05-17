const std = @import("std");
const crypto = @import("crypto.zig");
const format = @import("format.zig");

pub const KEY_TYPE_EK: u8 = 0x01;
pub const KEY_TYPE_COMPOSITE: u8 = 0x02;
pub const KEY_TYPE_DK_SEED: u8 = 0x03;

pub const EK_FILE_LEN: usize = 1 + crypto.EK_LEN;
pub const DK_SEED_FILE_LEN: usize = 1 + crypto.DK_SEED_LEN;
pub const COMPOSITE_FILE_LEN: usize = 1 + crypto.EK_LEN + format.PASSWORD_BLOB_LEN;

pub const KeyFileFormat = enum { raw, hex };

pub const ParsedKeyFile = union(enum) {
    encapsulation_key: struct {
        ek_bytes: crypto.EncapsulationKey,
        file_format: KeyFileFormat,
    },
    composite: struct {
        ek_bytes: crypto.EncapsulationKey,
        password_blob_bytes: [format.PASSWORD_BLOB_LEN]u8,
        file_format: KeyFileFormat,
    },
    decapsulation_seed: struct {
        seed: crypto.DecapsulationSeed,
        file_format: KeyFileFormat,
    },

    pub fn isPublic(self: ParsedKeyFile) bool {
        return self == .encapsulation_key;
    }
};

pub const MAX_RAW_KEY_FILE_LEN = COMPOSITE_FILE_LEN;
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
    const tag = bytes[0];
    const body = bytes[1..];
    switch (tag) {
        KEY_TYPE_EK => {
            if (body.len != crypto.EK_LEN) return error.BodyLengthMismatch;
            return .{ .encapsulation_key = .{
                .ek_bytes = body[0..crypto.EK_LEN].*,
                .file_format = file_format,
            } };
        },
        KEY_TYPE_COMPOSITE => {
            const expected = crypto.EK_LEN + format.PASSWORD_BLOB_LEN;
            if (body.len != expected) return error.BodyLengthMismatch;
            return .{ .composite = .{
                .ek_bytes = body[0..crypto.EK_LEN].*,
                .password_blob_bytes = body[crypto.EK_LEN..][0..format.PASSWORD_BLOB_LEN].*,
                .file_format = file_format,
            } };
        },
        KEY_TYPE_DK_SEED => {
            if (body.len != crypto.DK_SEED_LEN) return error.BodyLengthMismatch;
            return .{ .decapsulation_seed = .{
                .seed = body[0..crypto.DK_SEED_LEN].*,
                .file_format = file_format,
            } };
        },
        else => return null,
    }
}

pub const MAX_ENCODED_KEY_FILE_LEN = MAX_RAW_KEY_FILE_LEN * 2 + 1;

pub fn encodeEkFile(
    buffer: *[MAX_ENCODED_KEY_FILE_LEN]u8,
    ek_bytes: *const crypto.EncapsulationKey,
    file_format: KeyFileFormat,
) []u8 {
    var raw_buf: [EK_FILE_LEN]u8 = undefined;
    raw_buf[0] = KEY_TYPE_EK;
    raw_buf[1..][0..crypto.EK_LEN].* = ek_bytes.*;
    return formatOutput(buffer, &raw_buf, file_format);
}

pub fn encodeDkSeedFile(
    buffer: *[MAX_ENCODED_KEY_FILE_LEN]u8,
    seed: *const crypto.DecapsulationSeed,
    file_format: KeyFileFormat,
) []u8 {
    var raw_buf: [DK_SEED_FILE_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &raw_buf);
    raw_buf[0] = KEY_TYPE_DK_SEED;
    raw_buf[1..][0..crypto.DK_SEED_LEN].* = seed.*;
    return formatOutput(buffer, &raw_buf, file_format);
}

pub fn encodeCompositeFile(
    buffer: *[MAX_ENCODED_KEY_FILE_LEN]u8,
    ek_bytes: *const crypto.EncapsulationKey,
    password_blob: *const [format.PASSWORD_BLOB_LEN]u8,
    file_format: KeyFileFormat,
) []u8 {
    var raw_buf: [COMPOSITE_FILE_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &raw_buf);
    raw_buf[0] = KEY_TYPE_COMPOSITE;
    raw_buf[1..][0..crypto.EK_LEN].* = ek_bytes.*;
    raw_buf[1 + crypto.EK_LEN ..][0..format.PASSWORD_BLOB_LEN].* = password_blob.*;
    return formatOutput(buffer, &raw_buf, file_format);
}

fn formatOutput(
    buffer: *[MAX_ENCODED_KEY_FILE_LEN]u8,
    raw_buf: []const u8,
    file_format: KeyFileFormat,
) []u8 {
    switch (file_format) {
        .raw => {
            @memcpy(buffer[0..raw_buf.len], raw_buf);
            return buffer[0..raw_buf.len];
        },
        .hex => {
            const total = raw_buf.len * 2 + 1;
            const out = buffer[0..total];
            return std.fmt.bufPrint(out, "{x}\n", .{raw_buf}) catch unreachable;
        },
    }
}

pub fn parentOrCwd(path: []const u8) []const u8 {
    return std.fs.path.dirname(path) orelse ".";
}

pub const PermsError = error{InsecureKeyFilePermissions};

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

test "parse raw EK" {
    const ek: crypto.EncapsulationKey = @splat(7);
    var enc_buf: [MAX_ENCODED_KEY_FILE_LEN]u8 = undefined;
    const enc = encodeEkFile(&enc_buf, &ek, .raw);
    try std.testing.expectEqual(@as(usize, EK_FILE_LEN), enc.len);
    try std.testing.expectEqual(@as(u8, KEY_TYPE_EK), enc[0]);
    const parsed = try parseKeyFile(enc);
    try std.testing.expectEqualSlices(u8, &ek, &parsed.encapsulation_key.ek_bytes);
    try std.testing.expectEqual(KeyFileFormat.raw, parsed.encapsulation_key.file_format);
}

test "parse raw DK seed" {
    const seed: crypto.DecapsulationSeed = @splat(0x5a);
    var enc_buf: [MAX_ENCODED_KEY_FILE_LEN]u8 = undefined;
    const enc = encodeDkSeedFile(&enc_buf, &seed, .raw);
    try std.testing.expectEqual(@as(usize, DK_SEED_FILE_LEN), enc.len);
    try std.testing.expectEqual(@as(u8, KEY_TYPE_DK_SEED), enc[0]);
    const parsed = try parseKeyFile(enc);
    try std.testing.expectEqualSlices(u8, &seed, &parsed.decapsulation_seed.seed);
    try std.testing.expectEqual(KeyFileFormat.raw, parsed.decapsulation_seed.file_format);
}

test "parse raw composite" {
    const ek: crypto.EncapsulationKey = @splat(0xa5);
    const blob: [format.PASSWORD_BLOB_LEN]u8 = @splat(0x33);
    var enc_buf: [MAX_ENCODED_KEY_FILE_LEN]u8 = undefined;
    const enc = encodeCompositeFile(&enc_buf, &ek, &blob, .raw);
    try std.testing.expectEqual(@as(usize, COMPOSITE_FILE_LEN), enc.len);
    try std.testing.expectEqual(@as(u8, KEY_TYPE_COMPOSITE), enc[0]);
    const parsed = try parseKeyFile(enc);
    try std.testing.expectEqualSlices(u8, &ek, &parsed.composite.ek_bytes);
    try std.testing.expectEqualSlices(u8, &blob, &parsed.composite.password_blob_bytes);
    try std.testing.expectEqual(KeyFileFormat.raw, parsed.composite.file_format);
}

test "parse hex EK" {
    const ek: crypto.EncapsulationKey = @splat(0x11);
    var enc_buf: [MAX_ENCODED_KEY_FILE_LEN]u8 = undefined;
    const enc = encodeEkFile(&enc_buf, &ek, .hex);
    const parsed = try parseKeyFile(enc);
    try std.testing.expectEqualSlices(u8, &ek, &parsed.encapsulation_key.ek_bytes);
    try std.testing.expectEqual(KeyFileFormat.hex, parsed.encapsulation_key.file_format);
}

test "parse hex DK seed" {
    const seed: crypto.DecapsulationSeed = @splat(0x99);
    var enc_buf: [MAX_ENCODED_KEY_FILE_LEN]u8 = undefined;
    const enc = encodeDkSeedFile(&enc_buf, &seed, .hex);
    for (enc) |b| try std.testing.expect(std.ascii.isHex(b) or b == '\n');
    const parsed = try parseKeyFile(enc);
    try std.testing.expectEqualSlices(u8, &seed, &parsed.decapsulation_seed.seed);
    try std.testing.expectEqual(KeyFileFormat.hex, parsed.decapsulation_seed.file_format);
}

test "parse hex composite with surrounding whitespace" {
    const gpa = std.testing.allocator;
    const ek: crypto.EncapsulationKey = @splat(0x22);
    const blob: [format.PASSWORD_BLOB_LEN]u8 = @splat(0x44);
    var enc_buf: [MAX_ENCODED_KEY_FILE_LEN]u8 = undefined;
    const enc = encodeCompositeFile(&enc_buf, &ek, &blob, .hex);
    var padded: std.ArrayList(u8) = .empty;
    defer padded.deinit(gpa);
    try padded.appendSlice(gpa, "   ");
    try padded.appendSlice(gpa, enc);
    try padded.appendSlice(gpa, "\n  \n");
    const parsed = try parseKeyFile(padded.items);
    try std.testing.expectEqualSlices(u8, &ek, &parsed.composite.ek_bytes);
    try std.testing.expectEqualSlices(u8, &blob, &parsed.composite.password_blob_bytes);
    try std.testing.expectEqual(KeyFileFormat.hex, parsed.composite.file_format);
}

test "rejects short input" {
    try std.testing.expectError(error.UnrecognisedKeyFile, parseKeyFile(&.{}));
    try std.testing.expectError(error.BodyLengthMismatch, parseKeyFile(&.{ KEY_TYPE_DK_SEED, 1, 2, 3 }));
}

test "rejects DK seed wrong length" {
    var bytes_short: [1 + crypto.DK_SEED_LEN - 1]u8 = .{KEY_TYPE_DK_SEED} ++ @as([crypto.DK_SEED_LEN - 1]u8, @splat(0));
    try std.testing.expectError(error.BodyLengthMismatch, parseKeyFile(&bytes_short));
    var bytes_long: [1 + crypto.DK_SEED_LEN + 1]u8 = .{KEY_TYPE_DK_SEED} ++ @as([crypto.DK_SEED_LEN + 1]u8, @splat(0));
    try std.testing.expectError(error.BodyLengthMismatch, parseKeyFile(&bytes_long));
}

test "rejects unknown type" {
    var bytes: [1 + crypto.EK_LEN]u8 = undefined;
    bytes[0] = 0xff;
    @memset(bytes[1..], 0);
    try std.testing.expectError(error.UnrecognisedKeyFile, parseKeyFile(&bytes));
}

test "EK is public" {
    const ek: crypto.EncapsulationKey = @splat(0);
    var enc_buf: [MAX_ENCODED_KEY_FILE_LEN]u8 = undefined;
    const enc = encodeEkFile(&enc_buf, &ek, .raw);
    const parsed = try parseKeyFile(enc);
    try std.testing.expect(parsed.isPublic());
}

test "DK seed is not public" {
    const seed: crypto.DecapsulationSeed = @splat(0);
    var enc_buf: [MAX_ENCODED_KEY_FILE_LEN]u8 = undefined;
    const enc = encodeDkSeedFile(&enc_buf, &seed, .raw);
    const parsed = try parseKeyFile(enc);
    try std.testing.expect(!parsed.isPublic());
}

test "composite is not public" {
    const ek: crypto.EncapsulationKey = @splat(0);
    const blob: [format.PASSWORD_BLOB_LEN]u8 = @splat(0);
    var enc_buf: [MAX_ENCODED_KEY_FILE_LEN]u8 = undefined;
    const enc = encodeCompositeFile(&enc_buf, &ek, &blob, .raw);
    const parsed = try parseKeyFile(enc);
    try std.testing.expect(!parsed.isPublic());
}
