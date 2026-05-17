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

    const kp = try crypto.kemGenerate(io);
    var seed: crypto.DecapsulationSeed = kp[0];
    defer std.crypto.secureZero(u8, &seed);
    const ek_bytes: crypto.EncapsulationKey = kp[1];

    if (args.password) {
        const params = try password_mod.resolveArgon2Params(args.argon2_mem, args.argon2_iters, args.argon2_lanes);
        const meta: format.Argon2Meta = .{
            .salt = try password_mod.randomSalt(io),
            .mem_kib = params[0],
            .iterations = params[1],
            .parallelism = params[2],
        };

        const pw = try password_mod.readPassword(gpa, io, environ, "Password: ", true);
        defer {
            std.crypto.secureZero(u8, pw);
            gpa.free(pw);
        }
        var argon2_key = try password_mod.deriveKeyFromPassword(gpa, io, pw, &meta);
        defer std.crypto.secureZero(u8, &argon2_key);

        const wrapped = crypto.wrapDkSeed(&argon2_key, &seed);
        std.crypto.secureZero(u8, &seed);

        const blob: format.PasswordBlob = .{
            .encrypted_seed = wrapped[0],
            .seed_tag = wrapped[1],
            .argon2 = meta,
        };
        const blob_bytes = blob.encode();

        var enc_buf: [key_mod.MAX_ENCODED_KEY_FILE_LEN]u8 = undefined;
        defer std.crypto.secureZero(u8, &enc_buf);
        const file_bytes = key_mod.encodeCompositeFile(&enc_buf, &ek_bytes, &blob_bytes, file_format);
        try key_mod.writeKeyFileDurable(io, args.out, file_bytes, 0o600, false);
    } else {
        var recovery_persisted: ?[]const u8 = null;
        if (args.recovery_out) |rp| {
            var enc_buf: [key_mod.MAX_ENCODED_KEY_FILE_LEN]u8 = undefined;
            defer std.crypto.secureZero(u8, &enc_buf);
            const recovery_bytes = key_mod.encodeDkSeedFile(&enc_buf, &seed, file_format);
            try key_mod.writeKeyFileDurable(io, rp, recovery_bytes, 0o600, false);
            recovery_persisted = rp;
        }

        var enc_buf: [key_mod.MAX_ENCODED_KEY_FILE_LEN]u8 = undefined;
        const ek_file_bytes = key_mod.encodeEkFile(&enc_buf, &ek_bytes, file_format);
        key_mod.writeKeyFileDurable(io, args.out, ek_file_bytes, 0o644, false) catch |err| {
            if (recovery_persisted) |rp| {
                std.Io.Dir.cwd().deleteFile(io, rp) catch {};
            }
            return err;
        };
    }
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

    const checked = try key_mod.readKeyFileChecked(io, gpa, args.key_file, true);
    defer {
        std.crypto.secureZero(u8, checked.bytes);
        gpa.free(checked.bytes);
    }
    const parsed = try key_mod.parseKeyFile(checked.bytes);

    const ek_bytes: crypto.EncapsulationKey, const password_blob: ?format.PasswordBlob = switch (parsed) {
        .encapsulation_key => |ek| .{ ek.ek_bytes, null },
        .composite => |c| blk: {
            _ = try key_mod.checkKeyPermissions(io, args.key_file, args.insecure_perms);
            break :blk .{ c.ek_bytes, try format.PasswordBlob.decode(&c.password_blob_bytes) };
        },
        .decapsulation_seed => return error.KeyfileIsDkSeed,
    };

    var input = try io_mod.Input.open(io, gpa, args.input);
    defer input.close(io);
    var output = try io_mod.Output.open(io, gpa, args.output, args.force);
    defer output.deinit(io);

    const encap = try crypto.kemEncapsulate(&ek_bytes, io);
    var shared_secret: crypto.SharedSecret = encap[1];
    defer std.crypto.secureZero(u8, &shared_secret);

    var file_nonce: crypto.FileNonce = undefined;
    try io.randomSecure(&file_nonce);

    const header: format.Header = .{
        .chunk_size = args.chunk_size,
        .file_nonce = file_nonce,
        .kem_ciphertext = encap[0],
        .password_blob = password_blob,
    };

    var ad_buf: [format.MAX_CHUNK_AD_LEN]u8 = undefined;
    const header_bytes = header.encode(ad_buf[0..format.MAX_HEADER_LEN]);
    try output.writer().writeAll(header_bytes);

    var file_secrets = crypto.deriveFileSecrets(&shared_secret, &file_nonce);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&file_secrets));
    const file_key: *crypto.CipherKey = &file_secrets[0];
    const base_nonce: *crypto.Nonce = &file_secrets[1];

    const ctx: ChunkContext = .{
        .gpa = gpa,
        .file_key = file_key,
        .base_nonce = base_nonce,
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
    var prevalidated_seed: ?crypto.DecapsulationSeed = null;
    defer if (prevalidated_seed) |*s| std.crypto.secureZero(u8, s);

    if (args.password) {
        if (args.key_file != null) return error.NoKeyOrPassword;
    } else {
        const path = args.key_file orelse return error.NoKeyOrPassword;
        const checked = try key_mod.readKeyFileChecked(io, gpa, path, true);
        defer {
            std.crypto.secureZero(u8, checked.bytes);
            gpa.free(checked.bytes);
        }
        const parsed = try key_mod.parseKeyFile(checked.bytes);
        switch (parsed) {
            .decapsulation_seed => |dk| {
                _ = try key_mod.checkKeyPermissions(io, path, args.insecure_perms);
                prevalidated_seed = dk.seed;
            },
            .encapsulation_key => return error.KeyfileIsEk,
            .composite => return error.KeyfileIsComposite,
        }
    }

    var input = try io_mod.Input.open(io, gpa, args.input);
    defer input.close(io);

    var ad_buf: [format.MAX_CHUNK_AD_LEN]u8 = undefined;
    const parsed_header = try format.Header.read(input.reader(), ad_buf[0..format.MAX_HEADER_LEN]);
    const header = parsed_header.header;
    const header_bytes = parsed_header.raw_bytes;

    var shared_secret: crypto.SharedSecret = undefined;
    defer std.crypto.secureZero(u8, &shared_secret);

    if (prevalidated_seed) |seed| {
        shared_secret = try crypto.kemDecapsulate(&seed, &header.kem_ciphertext);
    } else {
        const blob = header.password_blob orelse return error.NotPasswordMode;
        const pw = try password_mod.readPassword(gpa, io, environ, "Password: ", false);
        defer {
            std.crypto.secureZero(u8, pw);
            gpa.free(pw);
        }
        var argon2_key = try password_mod.deriveKeyFromPassword(gpa, io, pw, &blob.argon2);
        defer std.crypto.secureZero(u8, &argon2_key);

        var seed = crypto.unwrapDkSeed(&argon2_key, &blob.encrypted_seed, &blob.seed_tag) catch
            return error.WrongPassword;
        defer std.crypto.secureZero(u8, &seed);

        shared_secret = try crypto.kemDecapsulate(&seed, &header.kem_ciphertext);
    }

    var file_secrets = crypto.deriveFileSecrets(&shared_secret, &header.file_nonce);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&file_secrets));
    const file_key: *crypto.CipherKey = &file_secrets[0];
    const base_nonce: *crypto.Nonce = &file_secrets[1];

    var output = try io_mod.Output.open(io, gpa, args.output, args.force);
    defer output.deinit(io);

    const ctx: ChunkContext = .{
        .gpa = gpa,
        .file_key = file_key,
        .base_nonce = base_nonce,
        .ad_buf = &ad_buf,
        .header_len = header_bytes.len,
        .chunk_size = header.chunk_size,
    };
    try decryptChunks(ctx, &input, &output);

    try output.commit(io);
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
