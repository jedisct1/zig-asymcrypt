const std = @import("std");
const crypto = @import("crypto.zig");
const format = @import("format.zig");

pub const DEFAULT_MEM_KIB: u32 = 256 * 1024;
pub const DEFAULT_ITERATIONS: u32 = 3;
pub const DEFAULT_PARALLELISM: u32 = 1;

pub const ResolveError = error{
    Argon2MemTooSmall,
    Argon2ItersTooSmall,
    Argon2LanesTooSmall,
};

pub fn resolveArgon2Params(
    mem_kib: ?u32,
    iterations: ?u32,
    parallelism: ?u32,
) ResolveError!struct { u32, u32, u32 } {
    const m = mem_kib orelse DEFAULT_MEM_KIB;
    const t = iterations orelse DEFAULT_ITERATIONS;
    const p = parallelism orelse DEFAULT_PARALLELISM;
    if (m == 0) return error.Argon2MemTooSmall;
    if (t == 0) return error.Argon2ItersTooSmall;
    if (p == 0) return error.Argon2LanesTooSmall;
    return .{ m, t, p };
}

pub fn deriveKeyFromPassword(
    gpa: std.mem.Allocator,
    io: std.Io,
    password: []const u8,
    meta: *const format.Argon2Meta,
) !crypto.MasterKey {
    var out: crypto.MasterKey = undefined;
    const params: std.crypto.pwhash.argon2.Params = .{
        .t = meta.iterations,
        .m = meta.mem_kib,
        .p = @intCast(meta.parallelism),
    };
    try std.crypto.pwhash.argon2.kdf(
        gpa,
        &out,
        password,
        &meta.salt,
        params,
        .argon2id,
        io,
    );
    return out;
}

pub fn randomSalt(io: std.Io) ![16]u8 {
    var s: [16]u8 = undefined;
    try io.randomSecure(&s);
    return s;
}

/// If `ASYMCRYPT_PASSWORD` is set, its value is returned without prompting.
/// Otherwise the prompt is written to stderr and a single line is read from
/// stdin; with `confirm`, the user types it twice and the two are compared.
///
/// The returned slice is owned by the caller and must be zeroed and freed.
pub fn readPassword(
    gpa: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    prompt: []const u8,
    confirm: bool,
) ![]u8 {
    if (environ.getPosix("ASYMCRYPT_PASSWORD")) |value| {
        if (value.len == 0) return error.EmptyPassword;
        return gpa.dupe(u8, value);
    }

    var stderr_buffer: [256]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writer(io, &stderr_buffer);
    try stderr_writer.interface.writeAll(prompt);
    try stderr_writer.interface.flush();

    var stdin_buffer: [4096]u8 = undefined;
    defer std.crypto.secureZero(u8, &stdin_buffer);
    var stdin_reader = std.Io.File.stdin().reader(io, &stdin_buffer);

    const first_line = readLine(&stdin_reader.interface) catch |err| switch (err) {
        error.StreamTooLong => return error.PasswordTooLong,
        else => |e| return e,
    };
    if (first_line.len == 0) return error.EmptyPassword;
    const first = try gpa.dupe(u8, first_line);
    errdefer {
        std.crypto.secureZero(u8, first);
        gpa.free(first);
    }

    if (confirm) {
        try stderr_writer.interface.writeAll("Confirm password: ");
        try stderr_writer.interface.flush();
        const second_line = readLine(&stdin_reader.interface) catch |err| switch (err) {
            error.StreamTooLong => return error.PasswordTooLong,
            else => |e| return e,
        };
        const matches = std.mem.eql(u8, first, second_line);
        if (!matches) return error.PasswordsDoNotMatch;
    }
    return first;
}

fn readLine(reader: *std.Io.Reader) ![]const u8 {
    const line = reader.takeDelimiterInclusive('\n') catch |err| switch (err) {
        error.EndOfStream => {
            const remaining = reader.buffered();
            reader.toss(remaining.len);
            return std.mem.trimEnd(u8, remaining, "\r");
        },
        else => |e| return e,
    };
    return std.mem.trimEnd(u8, line[0 .. line.len - 1], "\r");
}

test "resolveArgon2Params defaults" {
    const r = try resolveArgon2Params(null, null, null);
    try std.testing.expectEqual(DEFAULT_MEM_KIB, r[0]);
    try std.testing.expectEqual(DEFAULT_ITERATIONS, r[1]);
    try std.testing.expectEqual(DEFAULT_PARALLELISM, r[2]);
}

test "resolveArgon2Params rejects zero" {
    try std.testing.expectError(error.Argon2MemTooSmall, resolveArgon2Params(0, null, null));
    try std.testing.expectError(error.Argon2ItersTooSmall, resolveArgon2Params(null, 0, null));
    try std.testing.expectError(error.Argon2LanesTooSmall, resolveArgon2Params(null, null, 0));
}
