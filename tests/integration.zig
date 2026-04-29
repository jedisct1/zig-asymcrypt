const std = @import("std");
const lib = @import("asymcrypt");
const cli = lib.cli;
const crypto = lib.crypto;
const format = lib.format;
const key_mod = lib.key;
const pipeline = lib.pipeline;

const testing = std.testing;
const Io = std.Io;

const TmpFixture = struct {
    tmp: testing.TmpDir,
    base: []u8, // owned

    pub fn init(gpa: std.mem.Allocator) !TmpFixture {
        var t = testing.tmpDir(.{});
        const base = try std.fs.path.join(gpa, &.{ ".zig-cache", "tmp", &t.sub_path });
        return .{ .tmp = t, .base = base };
    }

    pub fn deinit(self: *TmpFixture, gpa: std.mem.Allocator) void {
        gpa.free(self.base);
        self.tmp.cleanup();
    }

    pub fn path(self: *const TmpFixture, gpa: std.mem.Allocator, name: []const u8) ![]u8 {
        return std.fs.path.join(gpa, &.{ self.base, name });
    }

    pub fn writeFile(self: *const TmpFixture, name: []const u8, data: []const u8) !void {
        try self.tmp.dir.writeFile(testing.io, .{ .sub_path = name, .data = data, .flags = .{ .truncate = true } });
    }

    pub fn readFile(self: *const TmpFixture, gpa: std.mem.Allocator, name: []const u8) ![]u8 {
        var f = try self.tmp.dir.openFile(testing.io, name, .{ .mode = .read_only });
        defer f.close(testing.io);
        const sz = try f.length(testing.io);
        const buf = try gpa.alloc(u8, @intCast(sz));
        errdefer gpa.free(buf);
        var rbuf: [4096]u8 = undefined;
        var r = f.reader(testing.io, &rbuf);
        try r.interface.readSliceAll(buf);
        return buf;
    }

    pub fn exists(self: *const TmpFixture, name: []const u8) bool {
        var f = self.tmp.dir.openFile(testing.io, name, .{ .mode = .read_only, .path_only = true }) catch return false;
        f.close(testing.io);
        return true;
    }
};

fn passwordEnviron(comptime password: [:0]const u8) std.process.Environ {
    if (@import("builtin").os.tag == .windows or @import("builtin").os.tag == .wasi) {
        @compileError("password env override not implemented for this platform in tests");
    }
    const Static = struct {
        const entry: [:0]const u8 = "ASYMCRYPT_PASSWORD=" ++ password;
        var slice = [_:null]?[*:0]const u8{entry.ptr};
    };
    return .{ .block = .{ .slice = &Static.slice } };
}

fn randomInit(out: []const u8, recovery_out: []const u8) cli.InitArgs {
    return .{ .out = out, .recovery_out = recovery_out };
}

fn randomInitHex(out: []const u8, recovery_out: []const u8) cli.InitArgs {
    var a = randomInit(out, recovery_out);
    a.hex = true;
    return a;
}

fn passwordInit(out: []const u8) cli.InitArgs {
    return .{
        .out = out,
        .password = true,
        .argon2_mem = 8 * 1024,
        .argon2_iters = 1,
        .argon2_lanes = 1,
    };
}

fn passwordInitHex(out: []const u8) cli.InitArgs {
    var a = passwordInit(out);
    a.hex = true;
    return a;
}

fn encryptArgs(key_file: []const u8, input: []const u8, output: []const u8) cli.EncryptArgs {
    return .{
        .key_file = key_file,
        .input = input,
        .output = output,
        .chunk_size = 1024,
    };
}

fn decryptKeyfileArgs(
    key_file: []const u8,
    input: []const u8,
    output: []const u8,
    max_steps: u64,
) cli.DecryptArgs {
    return .{
        .key_file = key_file,
        .input = input,
        .output = output,
        .max_key_steps = max_steps,
        .force = true,
    };
}

fn decryptPasswordArgs(input: []const u8, output: []const u8, max_steps: u64) cli.DecryptArgs {
    return .{
        .password = true,
        .input = input,
        .output = output,
        .max_key_steps = max_steps,
        .force = true,
    };
}

const empty_env: std.process.Environ = .empty;

test "init random mode writes both files with chain invariant" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const cur = try fix.path(gpa, "current.key");
    defer gpa.free(cur);
    const rec = try fix.path(gpa, "recovery.key");
    defer gpa.free(rec);

    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(cur, rec));

    const cur_bytes = try fix.readFile(gpa, "current.key");
    defer gpa.free(cur_bytes);
    const rec_bytes = try fix.readFile(gpa, "recovery.key");
    defer gpa.free(rec_bytes);

    try testing.expectEqual(@as(usize, 1 + crypto.MASTER_KEY_LEN), cur_bytes.len);
    try testing.expectEqual(@as(usize, 1 + crypto.MASTER_KEY_LEN), rec_bytes.len);
    try testing.expectEqual(@as(u8, key_mod.KEY_TYPE_PLAIN_V1), cur_bytes[0]);
    try testing.expectEqual(@as(u8, key_mod.KEY_TYPE_RECOVERY_V1), rec_bytes[0]);

    const cur_p = try key_mod.parseKeyFile(cur_bytes);
    const rec_p = try key_mod.parseKeyFile(rec_bytes);
    try testing.expectEqual(key_mod.KeyRole.chain, cur_p.role);
    try testing.expectEqual(key_mod.KeyRole.recovery, rec_p.role);

    var evolved = rec_p.key;
    crypto.evolveKey(&evolved);
    try testing.expectEqualSlices(u8, &cur_p.key, &evolved);
}

test "init random mode hex chain invariant" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const cur = try fix.path(gpa, "current.key");
    defer gpa.free(cur);
    const rec = try fix.path(gpa, "recovery.key");
    defer gpa.free(rec);

    try pipeline.runInit(gpa, testing.io, empty_env, randomInitHex(cur, rec));

    inline for (.{ "current.key", "recovery.key" }) |name| {
        const bytes = try fix.readFile(gpa, name);
        defer gpa.free(bytes);
        for (bytes) |b| try testing.expect(std.ascii.isHex(b) or std.ascii.isWhitespace(b));
    }

    const cur_bytes = try fix.readFile(gpa, "current.key");
    defer gpa.free(cur_bytes);
    const rec_bytes = try fix.readFile(gpa, "recovery.key");
    defer gpa.free(rec_bytes);
    const cur_p = try key_mod.parseKeyFile(cur_bytes);
    const rec_p = try key_mod.parseKeyFile(rec_bytes);
    var evolved = rec_p.key;
    crypto.evolveKey(&evolved);
    try testing.expectEqualSlices(u8, &cur_p.key, &evolved);
}

test "init random mode files are mode 0600" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const cur = try fix.path(gpa, "current.key");
    defer gpa.free(cur);
    const rec = try fix.path(gpa, "recovery.key");
    defer gpa.free(rec);
    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(cur, rec));

    inline for (.{ "current.key", "recovery.key" }) |name| {
        var f = try fix.tmp.dir.openFile(testing.io, name, .{ .mode = .read_only });
        defer f.close(testing.io);
        const stat = try f.stat(testing.io);
        if (@hasDecl(Io.File.Permissions, "toMode")) {
            const mode: u32 = @intCast(stat.permissions.toMode() & 0o777);
            try testing.expectEqual(@as(u32, 0o600), mode);
        }
    }
}

test "password mode writes only current key" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const cur = try fix.path(gpa, "current.key");
    defer gpa.free(cur);

    try pipeline.runInit(gpa, testing.io, passwordEnviron("hunter2"), passwordInit(cur));
    const bytes = try fix.readFile(gpa, "current.key");
    defer gpa.free(bytes);
    try testing.expectEqual(@as(usize, 1 + crypto.MASTER_KEY_LEN + format.ARGON2_METADATA_LEN), bytes.len);
    try testing.expectEqual(@as(u8, key_mod.KEY_TYPE_COMPOSITE_V1), bytes[0]);
    const parsed = try key_mod.parseKeyFile(bytes);
    try testing.expectEqual(key_mod.KeyRole.chain, parsed.role);
    try testing.expect(parsed.kdf != null);
}

test "init paths must differ" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const same = try fix.path(gpa, "k.key");
    defer gpa.free(same);
    try testing.expectError(error.SamePathForCurrentAndRecovery, pipeline.runInit(gpa, testing.io, empty_env, randomInit(same, same)));
    try testing.expect(!fix.exists("k.key"));
}

test "random mode requires recovery_out" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const cur = try fix.path(gpa, "current.key");
    defer gpa.free(cur);
    const args: cli.InitArgs = .{ .out = cur };
    try testing.expectError(error.RecoveryOutRequired, pipeline.runInit(gpa, testing.io, empty_env, args));
    try testing.expect(!fix.exists("current.key"));
}

test "password mode rejects recovery_out" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const cur = try fix.path(gpa, "current.key");
    defer gpa.free(cur);
    const rec = try fix.path(gpa, "recovery.key");
    defer gpa.free(rec);

    const args: cli.InitArgs = .{ .out = cur, .recovery_out = rec, .password = true, .argon2_mem = 8 * 1024, .argon2_iters = 1, .argon2_lanes = 1 };
    try testing.expectError(error.RecoveryOutWithPassword, pipeline.runInit(gpa, testing.io, passwordEnviron("hunter2"), args));
    try testing.expect(!fix.exists("current.key"));
    try testing.expect(!fix.exists("recovery.key"));
}

test "argon2 zero iters rejected" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);
    const k = try fix.path(gpa, "k.key");
    defer gpa.free(k);
    var a = passwordInit(k);
    a.argon2_iters = 0;
    try testing.expectError(error.Argon2ItersTooSmall, pipeline.runInit(gpa, testing.io, passwordEnviron("hunter2"), a));
    try testing.expect(!fix.exists("k.key"));
}

test "argon2 flag without password rejected" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);
    const cur = try fix.path(gpa, "k.key");
    defer gpa.free(cur);
    const rec = try fix.path(gpa, "r.key");
    defer gpa.free(rec);
    var a = randomInit(cur, rec);
    a.argon2_mem = 65536;
    try testing.expectError(error.Argon2FlagsRequirePassword, pipeline.runInit(gpa, testing.io, empty_env, a));
    try testing.expect(!fix.exists("k.key"));
    try testing.expect(!fix.exists("r.key"));
}

test "round trip recovers with offline key" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const cur = try fix.path(gpa, "current.key");
    defer gpa.free(cur);
    const rec = try fix.path(gpa, "recovery.key");
    defer gpa.free(rec);
    const plain = try fix.path(gpa, "plain.txt");
    defer gpa.free(plain);
    const cipher = try fix.path(gpa, "plain.asym");
    defer gpa.free(cipher);
    const out = try fix.path(gpa, "plain.out");
    defer gpa.free(out);

    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(cur, rec));
    try fix.writeFile("plain.txt", "hello two-file init");
    try pipeline.runEncrypt(gpa, testing.io, encryptArgs(cur, plain, cipher));
    try pipeline.runDecrypt(gpa, testing.io, empty_env, decryptKeyfileArgs(rec, cipher, out, 1000));

    const got = try fix.readFile(gpa, "plain.out");
    defer gpa.free(got);
    try testing.expectEqualStrings("hello two-file init", got);
}

test "empty round trip" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const cur = try fix.path(gpa, "cur.key");
    defer gpa.free(cur);
    const rec = try fix.path(gpa, "rec.key");
    defer gpa.free(rec);
    const plain = try fix.path(gpa, "p");
    defer gpa.free(plain);
    const cipher = try fix.path(gpa, "p.enc");
    defer gpa.free(cipher);
    const out = try fix.path(gpa, "p.out");
    defer gpa.free(out);

    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(cur, rec));
    try fix.writeFile("p", "");
    try pipeline.runEncrypt(gpa, testing.io, encryptArgs(cur, plain, cipher));
    try pipeline.runDecrypt(gpa, testing.io, empty_env, decryptKeyfileArgs(rec, cipher, out, 5));
    const got = try fix.readFile(gpa, "p.out");
    defer gpa.free(got);
    try testing.expectEqual(@as(usize, 0), got.len);
}

test "multi-chunk round trip" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const cur = try fix.path(gpa, "cur.key");
    defer gpa.free(cur);
    const rec = try fix.path(gpa, "rec.key");
    defer gpa.free(rec);
    const plain = try fix.path(gpa, "big.plain");
    defer gpa.free(plain);
    const cipher = try fix.path(gpa, "big.enc");
    defer gpa.free(cipher);
    const out = try fix.path(gpa, "big.out");
    defer gpa.free(out);

    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(cur, rec));

    const data = try gpa.alloc(u8, 250_000);
    defer gpa.free(data);
    for (data, 0..) |*b, i| b.* = @intCast(i % 251);
    try fix.writeFile("big.plain", data);

    var args = encryptArgs(cur, plain, cipher);
    args.chunk_size = 32 * 1024;
    try pipeline.runEncrypt(gpa, testing.io, args);
    try pipeline.runDecrypt(gpa, testing.io, empty_env, decryptKeyfileArgs(rec, cipher, out, 5));

    const got = try fix.readFile(gpa, "big.out");
    defer gpa.free(got);
    try testing.expectEqualSlices(u8, data, got);
}

test "exact chunk boundary" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const cur = try fix.path(gpa, "cur.key");
    defer gpa.free(cur);
    const rec = try fix.path(gpa, "rec.key");
    defer gpa.free(rec);
    const plain = try fix.path(gpa, "b.plain");
    defer gpa.free(plain);
    const cipher = try fix.path(gpa, "b.enc");
    defer gpa.free(cipher);
    const out = try fix.path(gpa, "b.out");
    defer gpa.free(out);

    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(cur, rec));
    const chunk: u32 = 4096;
    const data = try gpa.alloc(u8, chunk * 3);
    defer gpa.free(data);
    @memset(data, 0xa5);
    try fix.writeFile("b.plain", data);

    var args = encryptArgs(cur, plain, cipher);
    args.chunk_size = chunk;
    try pipeline.runEncrypt(gpa, testing.io, args);
    try pipeline.runDecrypt(gpa, testing.io, empty_env, decryptKeyfileArgs(rec, cipher, out, 5));

    const got = try fix.readFile(gpa, "b.out");
    defer gpa.free(got);
    try testing.expectEqualSlices(u8, data, got);
}

test "key evolution chain decrypts every backup" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const cur = try fix.path(gpa, "cur.key");
    defer gpa.free(cur);
    const rec = try fix.path(gpa, "rec.key");
    defer gpa.free(rec);

    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(cur, rec));

    var i: u32 = 0;
    while (i < 6) : (i += 1) {
        const plain_name = try std.fmt.allocPrint(gpa, "p{d}.txt", .{i});
        defer gpa.free(plain_name);
        const ct_name = try std.fmt.allocPrint(gpa, "ct{d}.bin", .{i});
        defer gpa.free(ct_name);
        const out_name = try std.fmt.allocPrint(gpa, "out{d}.bin", .{i});
        defer gpa.free(out_name);

        const plain_path = try fix.path(gpa, plain_name);
        defer gpa.free(plain_path);
        const ct_path = try fix.path(gpa, ct_name);
        defer gpa.free(ct_path);
        const out_path = try fix.path(gpa, out_name);
        defer gpa.free(out_path);

        const payload = try std.fmt.allocPrint(gpa, "payload {d}", .{i});
        defer gpa.free(payload);
        try fix.writeFile(plain_name, payload);
        try pipeline.runEncrypt(gpa, testing.io, encryptArgs(cur, plain_path, ct_path));
        try pipeline.runDecrypt(gpa, testing.io, empty_env, decryptKeyfileArgs(rec, ct_path, out_path, 50));
        const got = try fix.readFile(gpa, out_name);
        defer gpa.free(got);
        try testing.expectEqualStrings(payload, got);
    }
}

test "encrypt rejects recovery key" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const cur = try fix.path(gpa, "cur.key");
    defer gpa.free(cur);
    const rec = try fix.path(gpa, "rec.key");
    defer gpa.free(rec);
    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(cur, rec));

    const cur_before = try fix.readFile(gpa, "cur.key");
    defer gpa.free(cur_before);
    const rec_before = try fix.readFile(gpa, "rec.key");
    defer gpa.free(rec_before);

    const plain = try fix.path(gpa, "p.txt");
    defer gpa.free(plain);
    const ct = try fix.path(gpa, "p.enc");
    defer gpa.free(ct);
    try fix.writeFile("p.txt", "should not encrypt");

    try testing.expectError(error.KeyfileIsRecovery, pipeline.runEncrypt(gpa, testing.io, encryptArgs(rec, plain, ct)));

    const cur_after = try fix.readFile(gpa, "cur.key");
    defer gpa.free(cur_after);
    const rec_after = try fix.readFile(gpa, "rec.key");
    defer gpa.free(rec_after);
    try testing.expectEqualSlices(u8, cur_before, cur_after);
    try testing.expectEqualSlices(u8, rec_before, rec_after);
    try testing.expect(!fix.exists("p.enc"));
}

test "decrypt rejects chain key" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const cur = try fix.path(gpa, "cur.key");
    defer gpa.free(cur);
    const rec = try fix.path(gpa, "rec.key");
    defer gpa.free(rec);
    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(cur, rec));

    const plain = try fix.path(gpa, "p.txt");
    defer gpa.free(plain);
    const ct = try fix.path(gpa, "p.enc");
    defer gpa.free(ct);
    const out = try fix.path(gpa, "out.bin");
    defer gpa.free(out);

    try fix.writeFile("p.txt", "hi");
    try pipeline.runEncrypt(gpa, testing.io, encryptArgs(cur, plain, ct));

    try testing.expectError(error.KeyfileIsChain, pipeline.runDecrypt(gpa, testing.io, empty_env, decryptKeyfileArgs(cur, ct, out, 1000)));
    try testing.expect(!fix.exists("out.bin"));
}

test "wrong recovery key fails within max_steps" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const cur = try fix.path(gpa, "cur.key");
    defer gpa.free(cur);
    const rec = try fix.path(gpa, "rec.key");
    defer gpa.free(rec);
    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(cur, rec));

    const plain = try fix.path(gpa, "p.txt");
    defer gpa.free(plain);
    const ct = try fix.path(gpa, "p.enc");
    defer gpa.free(ct);
    try fix.writeFile("p.txt", "hello");
    try pipeline.runEncrypt(gpa, testing.io, encryptArgs(cur, plain, ct));

    const other_cur = try fix.path(gpa, "other.cur");
    defer gpa.free(other_cur);
    const other_rec = try fix.path(gpa, "other.rec");
    defer gpa.free(other_rec);
    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(other_cur, other_rec));

    const out = try fix.path(gpa, "oops.out");
    defer gpa.free(out);
    try testing.expectError(error.KeyChainExhausted, pipeline.runDecrypt(gpa, testing.io, empty_env, decryptKeyfileArgs(other_rec, ct, out, 16)));
}

test "tampered chunk fails authentication" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const cur = try fix.path(gpa, "cur.key");
    defer gpa.free(cur);
    const rec = try fix.path(gpa, "rec.key");
    defer gpa.free(rec);
    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(cur, rec));

    const data = try gpa.alloc(u8, 300_000);
    defer gpa.free(data);
    @memset(data, 0x42);
    try fix.writeFile("t.plain", data);

    const plain = try fix.path(gpa, "t.plain");
    defer gpa.free(plain);
    const ct = try fix.path(gpa, "t.enc");
    defer gpa.free(ct);
    var args = encryptArgs(cur, plain, ct);
    args.chunk_size = 64 * 1024;
    try pipeline.runEncrypt(gpa, testing.io, args);

    var ct_bytes = try fix.readFile(gpa, "t.enc");
    defer gpa.free(ct_bytes);
    ct_bytes[ct_bytes.len - 30] ^= 0xff;
    try fix.writeFile("t.enc", ct_bytes);

    const out = try fix.path(gpa, "out.bin");
    defer gpa.free(out);
    try testing.expectError(error.AuthFailedForChunk, pipeline.runDecrypt(gpa, testing.io, empty_env, decryptKeyfileArgs(rec, ct, out, 1)));
    try testing.expect(!fix.exists("out.bin"));
}

test "refuse overwrite without force" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const cur = try fix.path(gpa, "cur.key");
    defer gpa.free(cur);
    const rec = try fix.path(gpa, "rec.key");
    defer gpa.free(rec);
    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(cur, rec));

    try fix.writeFile("o.plain", "x");
    try fix.writeFile("o.enc", "existing");
    const plain = try fix.path(gpa, "o.plain");
    defer gpa.free(plain);
    const ct = try fix.path(gpa, "o.enc");
    defer gpa.free(ct);
    try testing.expectError(error.OutputExists, pipeline.runEncrypt(gpa, testing.io, encryptArgs(cur, plain, ct)));

    const after = try fix.readFile(gpa, "o.enc");
    defer gpa.free(after);
    try testing.expectEqualStrings("existing", after);
}

test "pre-rotation advances disk key" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const cur = try fix.path(gpa, "cur.key");
    defer gpa.free(cur);
    const rec = try fix.path(gpa, "rec.key");
    defer gpa.free(rec);
    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(cur, rec));

    const k0_bytes = try fix.readFile(gpa, "cur.key");
    defer gpa.free(k0_bytes);
    const k0 = try key_mod.parseKeyFile(k0_bytes);
    var expected = k0.key;
    crypto.evolveKey(&expected);

    try fix.writeFile("p.txt", "some plaintext");
    const plain = try fix.path(gpa, "p.txt");
    defer gpa.free(plain);
    const ctp = try fix.path(gpa, "p.enc");
    defer gpa.free(ctp);
    try pipeline.runEncrypt(gpa, testing.io, encryptArgs(cur, plain, ctp));

    const after_bytes = try fix.readFile(gpa, "cur.key");
    defer gpa.free(after_bytes);
    const after = try key_mod.parseKeyFile(after_bytes);
    try testing.expectEqualSlices(u8, &expected, &after.key);
}

test "password round trip" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const cur = try fix.path(gpa, "k.key");
    defer gpa.free(cur);
    const env = passwordEnviron("correct horse battery staple");
    try pipeline.runInit(gpa, testing.io, env, passwordInit(cur));

    try fix.writeFile("p", "top secret backup");
    const plain = try fix.path(gpa, "p");
    defer gpa.free(plain);
    const ct = try fix.path(gpa, "p.enc");
    defer gpa.free(ct);
    try pipeline.runEncrypt(gpa, testing.io, encryptArgs(cur, plain, ct));

    const out = try fix.path(gpa, "p.dec");
    defer gpa.free(out);
    try pipeline.runDecrypt(gpa, testing.io, env, decryptPasswordArgs(ct, out, 8));

    const got = try fix.readFile(gpa, "p.dec");
    defer gpa.free(got);
    try testing.expectEqualStrings("top secret backup", got);
}

test "wrong password fails" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const cur = try fix.path(gpa, "k.key");
    defer gpa.free(cur);
    try pipeline.runInit(gpa, testing.io, passwordEnviron("right one"), passwordInit(cur));

    try fix.writeFile("p", "x");
    const plain = try fix.path(gpa, "p");
    defer gpa.free(plain);
    const ct = try fix.path(gpa, "p.enc");
    defer gpa.free(ct);
    try pipeline.runEncrypt(gpa, testing.io, encryptArgs(cur, plain, ct));

    const out = try fix.path(gpa, "oops.out");
    defer gpa.free(out);
    try testing.expectError(error.KeyChainExhausted, pipeline.runDecrypt(gpa, testing.io, passwordEnviron("wrong one"), decryptPasswordArgs(ct, out, 4)));
}

test "current cannot decrypt past backup" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const cur = try fix.path(gpa, "cur.key");
    defer gpa.free(cur);
    const rec = try fix.path(gpa, "rec.key");
    defer gpa.free(rec);
    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(cur, rec));

    try fix.writeFile("p1", "first");
    const p1 = try fix.path(gpa, "p1");
    defer gpa.free(p1);
    const c1 = try fix.path(gpa, "c1");
    defer gpa.free(c1);
    try pipeline.runEncrypt(gpa, testing.io, encryptArgs(cur, p1, c1));

    try fix.writeFile("p2", "second");
    const p2 = try fix.path(gpa, "p2");
    defer gpa.free(p2);
    const c2 = try fix.path(gpa, "c2");
    defer gpa.free(c2);
    try pipeline.runEncrypt(gpa, testing.io, encryptArgs(cur, p2, c2));

    // The current chain key cannot decrypt c1 because forward chain walking
    // never goes backward. We use a chain key, so the role check trips first.
    const out = try fix.path(gpa, "oops.out");
    defer gpa.free(out);
    try testing.expectError(error.KeyfileIsChain, pipeline.runDecrypt(gpa, testing.io, empty_env, decryptKeyfileArgs(cur, c1, out, 1000)));
}
