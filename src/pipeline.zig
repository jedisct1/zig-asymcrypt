const std = @import("std");
const cli = @import("cli.zig");
const crypto = @import("crypto.zig");
const format = @import("format.zig");
const io_mod = @import("io.zig");
const key_mod = @import("key.zig");
const password_mod = @import("password.zig");

const InitArgs = cli.InitArgs;
const EncryptArgs = cli.EncryptArgs;
const DecryptArgs = cli.DecryptArgs;

pub fn runInit(
    gpa: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    args: InitArgs,
) !void {
    if (args.password and args.recovery_out != null) return error.RecoveryOutWithPassword;
    if (!args.password and args.recovery_out == null) return error.RecoveryOutRequired;
    if (!args.password and (args.argon2_mem != null or args.argon2_iters != null or args.argon2_lanes != null))
        return error.Argon2FlagsRequirePassword;

    const file_format: key_mod.KeyFileFormat = if (args.hex) .hex else .raw;

    try validateInitPath(io, args.out);
    if (args.recovery_out) |rp| {
        try validateInitPath(io, rp);
        if (try pathsEqual(args.out, rp)) return error.SamePathForCurrentAndRecovery;
    }

    var kdf: ?format.Argon2Meta = null;
    if (args.password) {
        const params = try password_mod.resolveArgon2Params(args.argon2_mem, args.argon2_iters, args.argon2_lanes);
        kdf = .{
            .salt = try password_mod.randomSalt(io),
            .mem_kib = params[0],
            .iterations = params[1],
            .parallelism = params[2],
        };
    }

    var k0: crypto.MasterKey = undefined;
    defer std.crypto.secureZero(u8, &k0);

    if (kdf) |meta| {
        const pw = try password_mod.readPassword(gpa, io, environ, "Password: ", true);
        defer {
            std.crypto.secureZero(u8, pw);
            gpa.free(pw);
        }
        k0 = try password_mod.deriveKeyFromPassword(gpa, io, pw, &meta);
    } else {
        k0 = try key_mod.randomKey(io);
    }

    var k1: crypto.MasterKey = k0;
    defer std.crypto.secureZero(u8, &k1);
    crypto.evolveKey(&k1);

    var current_buf: [key_mod.MAX_ENCODED_KEY_FILE_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &current_buf);
    const current_bytes = key_mod.encodeKeyFile(&current_buf, &k1, key_mod.KeyKind.chainFromKdf(kdf), file_format);

    var recovery_persisted: ?[]const u8 = null;
    if (args.recovery_out) |rp| {
        var recovery_buf: [key_mod.MAX_ENCODED_KEY_FILE_LEN]u8 = undefined;
        defer std.crypto.secureZero(u8, &recovery_buf);
        const recovery_bytes = key_mod.encodeKeyFile(&recovery_buf, &k0, .plain_recovery, file_format);
        try key_mod.writeKeyFileDurable(io, rp, recovery_bytes, 0o600, false);
        recovery_persisted = rp;
    }

    key_mod.writeKeyFileDurable(io, args.out, current_bytes, 0o600, false) catch |err| {
        if (recovery_persisted) |rp| {
            std.Io.Dir.cwd().deleteFile(io, rp) catch {};
        }
        return err;
    };
}

fn validateInitPath(io: std.Io, path: []const u8) !void {
    var dir = try std.Io.Dir.cwd().openDir(io, key_mod.parentOrCwd(path), .{});
    dir.close(io);
}

fn pathsEqual(a: []const u8, b: []const u8) !bool {
    var buf_a: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var buf_b: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var fba_a: std.heap.FixedBufferAllocator = .init(&buf_a);
    var fba_b: std.heap.FixedBufferAllocator = .init(&buf_b);
    const aa = try std.fs.path.resolve(fba_a.allocator(), &.{a});
    const bb = try std.fs.path.resolve(fba_b.allocator(), &.{b});
    return std.mem.eql(u8, aa, bb);
}

pub fn runEncrypt(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: EncryptArgs,
) !void {
    try cli.validateChunkSize(args.chunk_size);

    var lock = try key_mod.KeyLock.acquire(io, args.key_file);
    defer lock.release();

    const checked = try key_mod.readKeyFileChecked(io, gpa, args.key_file, args.insecure_perms);
    const mode = checked.mode;
    defer {
        std.crypto.secureZero(u8, checked.bytes);
        gpa.free(checked.bytes);
    }
    const parsed = try key_mod.parseKeyFile(checked.bytes);
    if (parsed.role == .recovery) return error.KeyfileIsRecovery;

    const key_format = parsed.file_format;
    const kdf = parsed.kdf;
    var stream_key: crypto.MasterKey = parsed.key;
    defer std.crypto.secureZero(u8, &stream_key);

    var input = try io_mod.Input.open(io, gpa, args.input);
    defer input.close(io);
    var output = try io_mod.Output.open(io, gpa, args.output, args.force);
    defer output.deinit(io);

    // Pre-rotation: commit K_{n+1} to the key file *before* writing any
    // ciphertext. After this, only this process holds K_n in memory; a
    // mid-stream crash leaves any partial output undecryptable from the
    // device's key file.
    {
        var next_key: crypto.MasterKey = stream_key;
        defer std.crypto.secureZero(u8, &next_key);
        crypto.evolveKey(&next_key);
        var next_buf: [key_mod.MAX_ENCODED_KEY_FILE_LEN]u8 = undefined;
        defer std.crypto.secureZero(u8, &next_buf);
        const next_bytes = key_mod.encodeKeyFile(&next_buf, &next_key, key_mod.KeyKind.chainFromKdf(kdf), key_format);
        try key_mod.writeKeyFileDurable(io, args.key_file, next_bytes, mode, true);
    }

    var file_nonce: crypto.FileNonce = undefined;
    try io.randomSecure(&file_nonce);

    const header: format.Header = .{
        .chunk_size = args.chunk_size,
        .file_nonce = file_nonce,
        .kdf = kdf,
    };

    var ad_buf: [format.MAX_CHUNK_AD_LEN]u8 = undefined;
    const header_bytes = header.encode(ad_buf[0..format.MAX_HEADER_LEN]);

    const kc = crypto.keyCheck(&stream_key, &file_nonce);
    var header_vec: [2][]const u8 = .{ header_bytes, &kc };
    try output.writer().writeVecAll(&header_vec);

    const file_secrets = crypto.deriveFileSecrets(&stream_key, &file_nonce);
    var file_key: crypto.CipherKey = file_secrets[0];
    defer std.crypto.secureZero(u8, &file_key);
    var base_nonce: crypto.Nonce = file_secrets[1];
    defer std.crypto.secureZero(u8, &base_nonce);

    const ctx: ChunkContext = .{
        .gpa = gpa,
        .file_key = &file_key,
        .base_nonce = &base_nonce,
        .ad_buf = &ad_buf,
        .header_len = header_bytes.len,
        .chunk_size = args.chunk_size,
    };
    try encryptChunks(ctx, &input, &output);

    try output.commit(io);
}

const ChunkContext = struct {
    gpa: std.mem.Allocator,
    file_key: *const crypto.CipherKey,
    base_nonce: *const crypto.Nonce,
    /// `ad_buf[0..header_len]` must already hold the encoded header; only
    /// the trailing `CHUNK_AD_TRAILER_LEN` bytes are rewritten per chunk.
    ad_buf: *[format.MAX_CHUNK_AD_LEN]u8,
    header_len: usize,
    chunk_size: usize,

    fn updateAd(self: ChunkContext, chunk_index: u64, plain_len: u32, flags: u8) []const u8 {
        const trailer = self.ad_buf[self.header_len..][0..format.CHUNK_AD_TRAILER_LEN];
        format.writeChunkAdTrailer(trailer, chunk_index, plain_len, flags);
        return self.ad_buf[0 .. self.header_len + format.CHUNK_AD_TRAILER_LEN];
    }
};

fn encryptChunks(ctx: ChunkContext, input: *io_mod.Input, output: *io_mod.Output) !void {
    const buf = try ctx.gpa.alloc(u8, ctx.chunk_size);
    defer ctx.gpa.free(buf);

    var chunk_index: u64 = 0;
    while (true) {
        const len = try input.reader().readSliceShort(buf);
        const partial = len < ctx.chunk_size;
        const is_final = partial or blk: {
            _ = input.reader().peekByte() catch |err| switch (err) {
                error.EndOfStream => break :blk true,
                else => |e| return e,
            };
            break :blk false;
        };
        try emitChunk(ctx, output, chunk_index, buf[0..len], is_final);
        if (is_final) return;
        chunk_index = std.math.add(u64, chunk_index, 1) catch return error.ChunkIndexOverflow;
    }
}

fn emitChunk(ctx: ChunkContext, output: *io_mod.Output, chunk_index: u64, buf: []u8, is_final: bool) !void {
    const flags: u8 = if (is_final) format.FINAL_CHUNK_FLAG else 0;
    const plain_len: u32 = std.math.cast(u32, buf.len) orelse return error.ChunkPlainLenTooLarge;
    const ad = ctx.updateAd(chunk_index, plain_len, flags);
    const nonce = crypto.deriveChunkNonce(ctx.base_nonce, chunk_index);
    const tag = crypto.encryptChunkInPlace(ctx.file_key, &nonce, buf, ad);
    const framing = format.encodeChunkFraming(plain_len, flags);
    var vec: [3][]const u8 = .{ &framing, buf, &tag };
    try output.writer().writeVecAll(&vec);
}

pub fn runDecrypt(
    gpa: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    args: DecryptArgs,
) !void {
    var prevalidated_key: ?crypto.MasterKey = null;
    defer if (prevalidated_key) |*k| std.crypto.secureZero(u8, k);

    if (args.password) {
        if (args.key_file != null) return error.NoKeyOrPassword;
    } else {
        const path = args.key_file orelse return error.NoKeyOrPassword;
        const checked = try key_mod.readKeyFileChecked(io, gpa, path, args.insecure_perms);
        defer {
            std.crypto.secureZero(u8, checked.bytes);
            gpa.free(checked.bytes);
        }
        const parsed = try key_mod.parseKeyFile(checked.bytes);
        if (parsed.role != .recovery) return error.KeyfileIsChain;
        prevalidated_key = parsed.key;
    }

    var input = try io_mod.Input.open(io, gpa, args.input);
    defer input.close(io);

    var ad_buf: [format.MAX_CHUNK_AD_LEN]u8 = undefined;
    const parsed_header = try format.Header.read(input.reader(), ad_buf[0..format.MAX_HEADER_LEN]);
    const header = parsed_header.header;
    const header_bytes = parsed_header.raw_bytes;

    var candidate_key: crypto.MasterKey = undefined;
    defer std.crypto.secureZero(u8, &candidate_key);
    if (prevalidated_key) |k| {
        candidate_key = k;
    } else {
        const kdf = header.kdf orelse return error.NoKeyOrPassword;
        const pw = try password_mod.readPassword(gpa, io, environ, "Password: ", false);
        defer {
            std.crypto.secureZero(u8, pw);
            gpa.free(pw);
        }
        candidate_key = try password_mod.deriveKeyFromPassword(gpa, io, pw, &kdf);
    }

    var stored_check: crypto.KeyCheck = undefined;
    try input.reader().readSliceAll(&stored_check);

    try findChainStep(io, &candidate_key, &header.file_nonce, &stored_check, args.max_key_steps);

    const file_secrets = crypto.deriveFileSecrets(&candidate_key, &header.file_nonce);
    var file_key: crypto.CipherKey = file_secrets[0];
    defer std.crypto.secureZero(u8, &file_key);
    var base_nonce: crypto.Nonce = file_secrets[1];
    defer std.crypto.secureZero(u8, &base_nonce);

    var output = try io_mod.Output.open(io, gpa, args.output, args.force);
    defer output.deinit(io);

    const ctx: ChunkContext = .{
        .gpa = gpa,
        .file_key = &file_key,
        .base_nonce = &base_nonce,
        .ad_buf = &ad_buf,
        .header_len = header_bytes.len,
        .chunk_size = header.chunk_size,
    };
    try decryptChunks(ctx, &input, &output);

    try output.commit(io);
}

fn findChainStep(
    io: std.Io,
    candidate_key: *crypto.MasterKey,
    file_nonce: *const crypto.FileNonce,
    stored_check: *const crypto.KeyCheck,
    max_steps: u64,
) !void {
    const stderr_is_tty = std.Io.File.stderr().isTty(io) catch false;
    var stderr_buf: [128]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writer(io, &stderr_buf);

    var steps: u64 = 0;
    while (true) {
        const got = crypto.keyCheck(candidate_key, file_nonce);
        if (std.crypto.timing_safe.eql([crypto.KEY_CHECK_LEN]u8, got, stored_check.*)) break;
        if (steps >= max_steps) return error.KeyChainExhausted;
        crypto.evolveKey(candidate_key);
        steps += 1;
        if (stderr_is_tty and steps % 1024 == 0) {
            stderr_writer.interface.print("\rsearching key chain: {d} steps", .{steps}) catch {};
            stderr_writer.interface.flush() catch {};
        }
    }
    if (stderr_is_tty and steps >= 1024) {
        stderr_writer.interface.print("\rkey chain matched at step {d}              \n", .{steps}) catch {};
        stderr_writer.interface.flush() catch {};
    } else if (steps > 0) {
        stderr_writer.interface.print("asymcrypt: matched chain step {d}\n", .{steps}) catch {};
        stderr_writer.interface.flush() catch {};
    }
}

fn decryptChunks(ctx: ChunkContext, input: *io_mod.Input, output: *io_mod.Output) !void {
    const buf = try ctx.gpa.alloc(u8, ctx.chunk_size);
    defer ctx.gpa.free(buf);

    var chunk_index: u64 = 0;
    while (true) {
        var framing: [format.CHUNK_FRAMING_LEN]u8 = undefined;
        try input.reader().readSliceAll(&framing);
        const plain_len_u32, const flags = format.decodeChunkFraming(&framing);
        const is_final = try format.validateChunkFlags(flags);
        const plain_len: usize = plain_len_u32;
        if (plain_len > ctx.chunk_size) return error.ChunkPlainLenExceedsChunkSize;
        if (!is_final and plain_len != ctx.chunk_size) return error.NonFinalChunkBadLength;
        try input.reader().readSliceAll(buf[0..plain_len]);
        var tag: crypto.Tag = undefined;
        try input.reader().readSliceAll(&tag);
        const nonce = crypto.deriveChunkNonce(ctx.base_nonce, chunk_index);
        const ad = ctx.updateAd(chunk_index, plain_len_u32, flags);
        crypto.decryptChunkInPlace(ctx.file_key, &nonce, buf[0..plain_len], &tag, ad) catch return error.AuthFailedForChunk;
        try output.writer().writeAll(buf[0..plain_len]);
        chunk_index = std.math.add(u64, chunk_index, 1) catch return error.ChunkIndexOverflow;
        if (is_final) {
            var probe: [1]u8 = undefined;
            const extra = try input.reader().readSliceShort(&probe);
            if (extra != 0) return error.TrailingBytesAfterFinal;
            return;
        }
    }
}
