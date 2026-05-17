const std = @import("std");
const clap = @import("clap");
const format = @import("format.zig");

pub const InitArgs = struct {
    out: []const u8,
    recovery_out: ?[]const u8 = null,
    password: bool = false,
    hex: bool = false,
    argon2_mem: ?u32 = null,
    argon2_iters: ?u32 = null,
    argon2_lanes: ?u32 = null,
};

pub const EncryptArgs = struct {
    key_file: []const u8,
    input: ?[]const u8 = null,
    output: ?[]const u8 = null,
    chunk_size: u32 = format.DEFAULT_CHUNK_SIZE,
    force: bool = false,
    insecure_perms: bool = false,
};

pub const DecryptArgs = struct {
    key_file: ?[]const u8 = null,
    password: bool = false,
    input: ?[]const u8 = null,
    output: ?[]const u8 = null,
    force: bool = false,
    insecure_perms: bool = false,
};

pub const Command = union(enum) {
    init: InitArgs,
    encrypt: EncryptArgs,
    decrypt: DecryptArgs,
};

pub const ParseError = error{
    NoSubcommand,
    UnknownSubcommand,
    MissingRequiredArgument,
    KeyfilePasswordConflict,
    InvalidChunkSize,
    NameNotPartOfEnum,
} || clap.streaming.Error || std.mem.Allocator.Error || std.fmt.ParseIntError;

pub fn validateChunkSize(n: u32) !void {
    if (n == 0 or n > format.MAX_CHUNK_SIZE) return error.InvalidChunkSize;
}

const Subcommand = enum { init, encrypt, decrypt };

const main_params = clap.parseParamsComptime(
    \\<command>
    \\
);

const main_parsers = .{
    .command = clap.parsers.enumeration(Subcommand),
};

const init_params = clap.parseParamsComptime(
    \\-o, --out <PATH>           Path for the device key (encapsulation key or composite).
    \\-r, --recovery-out <PATH>  Path for the offline recovery key (decapsulation seed).
    \\    --password             Derive wrapping key from a password instead of writing a recovery file.
    \\    --hex                  Encode key files as hex.
    \\    --argon2-mem <U32>     Argon2 memory in KiB.
    \\    --argon2-iters <U32>   Argon2 iterations.
    \\    --argon2-lanes <U32>   Argon2 parallelism.
    \\
);

const encrypt_params = clap.parseParamsComptime(
    \\-k, --key-file <PATH>      Path to the device key file (required).
    \\-i, --input <PATH>         Plaintext input path (default: stdin).
    \\-o, --output <PATH>        Ciphertext output path (default: stdout).
    \\    --chunk-size <U32>     Chunk size in bytes.
    \\    --force                Overwrite existing output file.
    \\    --insecure-perms       Skip key file permission check.
    \\
);

const decrypt_params = clap.parseParamsComptime(
    \\-k, --key-file <PATH>      Path to the offline recovery key (decapsulation seed).
    \\    --password             Read a password from the prompt instead of using a key file.
    \\-i, --input <PATH>         Ciphertext input path (default: stdin).
    \\-o, --output <PATH>        Plaintext output path (default: stdout).
    \\    --force                Overwrite existing output file.
    \\    --insecure-perms       Skip key file permission check.
    \\
);

const value_parsers = .{
    .PATH = clap.parsers.string,
    .U32 = clap.parsers.int(u32, 10),
};

pub fn parseFromIterator(gpa: std.mem.Allocator, iter: anytype) ParseError!Command {
    var main_res = clap.parseEx(clap.Help, &main_params, main_parsers, iter, .{
        .allocator = gpa,
        .terminating_positional = 0,
    }) catch |err| switch (err) {
        error.InvalidArgument, error.NameNotPartOfEnum => return error.UnknownSubcommand,
        else => |e| return e,
    };
    defer main_res.deinit();

    const sub = main_res.positionals[0] orelse return error.NoSubcommand;
    return switch (sub) {
        .init => .{ .init = try parseInit(gpa, iter) },
        .encrypt => .{ .encrypt = try parseEncrypt(gpa, iter) },
        .decrypt => .{ .decrypt = try parseDecrypt(gpa, iter) },
    };
}

fn parseInit(gpa: std.mem.Allocator, iter: anytype) ParseError!InitArgs {
    var res = try clap.parseEx(clap.Help, &init_params, value_parsers, iter, .{ .allocator = gpa });
    defer res.deinit();
    const out = res.args.out orelse return error.MissingRequiredArgument;
    return .{
        .out = out,
        .recovery_out = res.args.@"recovery-out",
        .password = res.args.password != 0,
        .hex = res.args.hex != 0,
        .argon2_mem = res.args.@"argon2-mem",
        .argon2_iters = res.args.@"argon2-iters",
        .argon2_lanes = res.args.@"argon2-lanes",
    };
}

fn parseEncrypt(gpa: std.mem.Allocator, iter: anytype) ParseError!EncryptArgs {
    var res = try clap.parseEx(clap.Help, &encrypt_params, value_parsers, iter, .{ .allocator = gpa });
    defer res.deinit();
    const key_file = res.args.@"key-file" orelse return error.MissingRequiredArgument;
    return .{
        .key_file = key_file,
        .input = res.args.input,
        .output = res.args.output,
        .chunk_size = res.args.@"chunk-size" orelse format.DEFAULT_CHUNK_SIZE,
        .force = res.args.force != 0,
        .insecure_perms = res.args.@"insecure-perms" != 0,
    };
}

fn parseDecrypt(gpa: std.mem.Allocator, iter: anytype) ParseError!DecryptArgs {
    var res = try clap.parseEx(clap.Help, &decrypt_params, value_parsers, iter, .{ .allocator = gpa });
    defer res.deinit();
    const key_file = res.args.@"key-file";
    const password = res.args.password != 0;
    if (password and key_file != null) return error.KeyfilePasswordConflict;
    return .{
        .key_file = key_file,
        .password = password,
        .input = res.args.input,
        .output = res.args.output,
        .force = res.args.force != 0,
        .insecure_perms = res.args.@"insecure-perms" != 0,
    };
}

pub fn parseSlice(gpa: std.mem.Allocator, args: []const []const u8) ParseError!Command {
    if (args.len < 2) return error.NoSubcommand;
    var iter: clap.args.SliceIterator = .{ .args = args[1..] };
    return parseFromIterator(gpa, &iter);
}

const testing = std.testing;

fn parseTest(args: []const []const u8) ParseError!Command {
    return parseSlice(testing.allocator, args);
}

test "init parses with both paths" {
    const cmd = try parseTest(&.{ "asymcrypt", "init", "-o", "k", "-r", "r" });
    try testing.expect(cmd == .init);
    try testing.expectEqualStrings("k", cmd.init.out);
    try testing.expectEqualStrings("r", cmd.init.recovery_out.?);
    try testing.expect(!cmd.init.password);
    try testing.expect(!cmd.init.hex);
}

test "init parses without recovery_out at parse layer" {
    const cmd = try parseTest(&.{ "asymcrypt", "init", "-o", "k" });
    try testing.expect(cmd.init.recovery_out == null);
    try testing.expect(!cmd.init.password);
}

test "init password mode" {
    const cmd = try parseTest(&.{ "asymcrypt", "init", "--password", "-o", "k" });
    try testing.expect(cmd.init.password);
    try testing.expect(cmd.init.recovery_out == null);
}

test "init argon2-mem with password parses" {
    const cmd = try parseTest(&.{ "asymcrypt", "init", "--argon2-mem", "65536", "--password", "-o", "k" });
    try testing.expect(cmd.init.password);
    try testing.expectEqual(@as(?u32, 65536), cmd.init.argon2_mem);
}

test "init hex works in both modes" {
    {
        const cmd = try parseTest(&.{ "asymcrypt", "init", "--hex", "-o", "k", "-r", "r" });
        try testing.expect(cmd.init.hex);
    }
    {
        const cmd = try parseTest(&.{ "asymcrypt", "init", "--password", "--hex", "-o", "k" });
        try testing.expect(cmd.init.password);
        try testing.expect(cmd.init.hex);
    }
}

test "old key-file flag for init is rejected" {
    try testing.expectError(error.InvalidArgument, parseTest(&.{ "asymcrypt", "init", "--key-file", "k" }));
}

test "missing subcommand" {
    try testing.expectError(error.NoSubcommand, parseTest(&.{"asymcrypt"}));
}

test "init missing -o" {
    try testing.expectError(error.MissingRequiredArgument, parseTest(&.{ "asymcrypt", "init" }));
}

test "keygen subcommand is gone" {
    try testing.expectError(error.UnknownSubcommand, parseTest(&.{ "asymcrypt", "keygen", "--out", "k" }));
}

test "decrypt password and key-file conflict" {
    try testing.expectError(error.KeyfilePasswordConflict, parseTest(&.{ "asymcrypt", "decrypt", "--password", "-k", "r" }));
}
