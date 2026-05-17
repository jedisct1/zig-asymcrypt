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
    base: []u8,

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
) cli.DecryptArgs {
    return .{
        .key_file = key_file,
        .input = input,
        .output = output,
        .force = true,
    };
}

fn decryptPasswordArgs(input: []const u8, output: []const u8) cli.DecryptArgs {
    return .{
        .password = true,
        .input = input,
        .output = output,
        .force = true,
    };
}

const empty_env: std.process.Environ = .empty;

test "init random mode writes EK and DK seed files" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const dev = try fix.path(gpa, "device.key");
    defer gpa.free(dev);
    const rec = try fix.path(gpa, "recovery.key");
    defer gpa.free(rec);

    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(dev, rec));

    const dev_bytes = try fix.readFile(gpa, "device.key");
    defer gpa.free(dev_bytes);
    const rec_bytes = try fix.readFile(gpa, "recovery.key");
    defer gpa.free(rec_bytes);

    try testing.expectEqual(@as(usize, key_mod.EK_FILE_LEN), dev_bytes.len);
    try testing.expectEqual(@as(usize, key_mod.DK_SEED_FILE_LEN), rec_bytes.len);
    try testing.expectEqual(@as(u8, key_mod.KEY_TYPE_EK), dev_bytes[0]);
    try testing.expectEqual(@as(u8, key_mod.KEY_TYPE_DK_SEED), rec_bytes[0]);

    const dev_p = try key_mod.parseKeyFile(dev_bytes);
    const rec_p = try key_mod.parseKeyFile(rec_bytes);
    try testing.expect(dev_p.isPublic());
    try testing.expect(!rec_p.isPublic());
}

test "init random mode hex" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const dev = try fix.path(gpa, "device.key");
    defer gpa.free(dev);
    const rec = try fix.path(gpa, "recovery.key");
    defer gpa.free(rec);

    try pipeline.runInit(gpa, testing.io, empty_env, randomInitHex(dev, rec));

    inline for (.{ "device.key", "recovery.key" }) |name| {
        const bytes = try fix.readFile(gpa, name);
        defer gpa.free(bytes);
        for (bytes) |b| try testing.expect(std.ascii.isHex(b) or std.ascii.isWhitespace(b));
    }
}

test "init random mode files are mode 0600/0644" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const dev = try fix.path(gpa, "device.key");
    defer gpa.free(dev);
    const rec = try fix.path(gpa, "recovery.key");
    defer gpa.free(rec);
    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(dev, rec));

    if (@hasDecl(Io.File.Permissions, "toMode")) {
        var rf = try fix.tmp.dir.openFile(testing.io, "recovery.key", .{ .mode = .read_only });
        defer rf.close(testing.io);
        const rstat = try rf.stat(testing.io);
        const rmode: u32 = @intCast(rstat.permissions.toMode() & 0o777);
        try testing.expectEqual(@as(u32, 0o600), rmode);

        var df = try fix.tmp.dir.openFile(testing.io, "device.key", .{ .mode = .read_only });
        defer df.close(testing.io);
        const dstat = try df.stat(testing.io);
        const dmode: u32 = @intCast(dstat.permissions.toMode() & 0o777);
        try testing.expectEqual(@as(u32, 0o644), dmode);
    }
}

test "password mode writes composite key" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const dev = try fix.path(gpa, "device.key");
    defer gpa.free(dev);

    try pipeline.runInit(gpa, testing.io, passwordEnviron("hunter2"), passwordInit(dev));
    const bytes = try fix.readFile(gpa, "device.key");
    defer gpa.free(bytes);
    try testing.expectEqual(@as(usize, key_mod.COMPOSITE_FILE_LEN), bytes.len);
    try testing.expectEqual(@as(u8, key_mod.KEY_TYPE_COMPOSITE), bytes[0]);
    const parsed = try key_mod.parseKeyFile(bytes);
    try testing.expect(!parsed.isPublic());
    try testing.expect(parsed == .composite);
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

    const dev = try fix.path(gpa, "device.key");
    defer gpa.free(dev);
    const args: cli.InitArgs = .{ .out = dev };
    try testing.expectError(error.RecoveryOutRequired, pipeline.runInit(gpa, testing.io, empty_env, args));
    try testing.expect(!fix.exists("device.key"));
}

test "password mode rejects recovery_out" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const dev = try fix.path(gpa, "device.key");
    defer gpa.free(dev);
    const rec = try fix.path(gpa, "recovery.key");
    defer gpa.free(rec);

    const args: cli.InitArgs = .{ .out = dev, .recovery_out = rec, .password = true, .argon2_mem = 8 * 1024, .argon2_iters = 1, .argon2_lanes = 1 };
    try testing.expectError(error.RecoveryOutWithPassword, pipeline.runInit(gpa, testing.io, passwordEnviron("hunter2"), args));
    try testing.expect(!fix.exists("device.key"));
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
    const dev = try fix.path(gpa, "k.key");
    defer gpa.free(dev);
    const rec = try fix.path(gpa, "r.key");
    defer gpa.free(rec);
    var a = randomInit(dev, rec);
    a.argon2_mem = 65536;
    try testing.expectError(error.Argon2FlagsRequirePassword, pipeline.runInit(gpa, testing.io, empty_env, a));
    try testing.expect(!fix.exists("k.key"));
    try testing.expect(!fix.exists("r.key"));
}

test "round trip recovers with offline key" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const dev = try fix.path(gpa, "device.key");
    defer gpa.free(dev);
    const rec = try fix.path(gpa, "recovery.key");
    defer gpa.free(rec);
    const plain = try fix.path(gpa, "plain.txt");
    defer gpa.free(plain);
    const cipher = try fix.path(gpa, "plain.asym");
    defer gpa.free(cipher);
    const out = try fix.path(gpa, "plain.out");
    defer gpa.free(out);

    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(dev, rec));
    try fix.writeFile("plain.txt", "hello two-file init");
    try pipeline.runEncrypt(gpa, testing.io, encryptArgs(dev, plain, cipher));
    try pipeline.runDecrypt(gpa, testing.io, empty_env, decryptKeyfileArgs(rec, cipher, out));

    const got = try fix.readFile(gpa, "plain.out");
    defer gpa.free(got);
    try testing.expectEqualStrings("hello two-file init", got);
}

test "empty round trip" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const dev = try fix.path(gpa, "dev.key");
    defer gpa.free(dev);
    const rec = try fix.path(gpa, "rec.key");
    defer gpa.free(rec);
    const plain = try fix.path(gpa, "p");
    defer gpa.free(plain);
    const cipher = try fix.path(gpa, "p.enc");
    defer gpa.free(cipher);
    const out = try fix.path(gpa, "p.out");
    defer gpa.free(out);

    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(dev, rec));
    try fix.writeFile("p", "");
    try pipeline.runEncrypt(gpa, testing.io, encryptArgs(dev, plain, cipher));
    try pipeline.runDecrypt(gpa, testing.io, empty_env, decryptKeyfileArgs(rec, cipher, out));
    const got = try fix.readFile(gpa, "p.out");
    defer gpa.free(got);
    try testing.expectEqual(@as(usize, 0), got.len);
}

test "multi-chunk round trip" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const dev = try fix.path(gpa, "dev.key");
    defer gpa.free(dev);
    const rec = try fix.path(gpa, "rec.key");
    defer gpa.free(rec);
    const plain = try fix.path(gpa, "big.plain");
    defer gpa.free(plain);
    const cipher = try fix.path(gpa, "big.enc");
    defer gpa.free(cipher);
    const out = try fix.path(gpa, "big.out");
    defer gpa.free(out);

    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(dev, rec));

    const data = try gpa.alloc(u8, 250_000);
    defer gpa.free(data);
    for (data, 0..) |*b, i| b.* = @intCast(i % 251);
    try fix.writeFile("big.plain", data);

    var args = encryptArgs(dev, plain, cipher);
    args.chunk_size = 32 * 1024;
    try pipeline.runEncrypt(gpa, testing.io, args);
    try pipeline.runDecrypt(gpa, testing.io, empty_env, decryptKeyfileArgs(rec, cipher, out));

    const got = try fix.readFile(gpa, "big.out");
    defer gpa.free(got);
    try testing.expectEqualSlices(u8, data, got);
}

test "exact chunk boundary" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const dev = try fix.path(gpa, "dev.key");
    defer gpa.free(dev);
    const rec = try fix.path(gpa, "rec.key");
    defer gpa.free(rec);
    const plain = try fix.path(gpa, "b.plain");
    defer gpa.free(plain);
    const cipher = try fix.path(gpa, "b.enc");
    defer gpa.free(cipher);
    const out = try fix.path(gpa, "b.out");
    defer gpa.free(out);

    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(dev, rec));
    const chunk: u32 = 4096;
    const data = try gpa.alloc(u8, chunk * 3);
    defer gpa.free(data);
    @memset(data, 0xa5);
    try fix.writeFile("b.plain", data);

    var args = encryptArgs(dev, plain, cipher);
    args.chunk_size = chunk;
    try pipeline.runEncrypt(gpa, testing.io, args);
    try pipeline.runDecrypt(gpa, testing.io, empty_env, decryptKeyfileArgs(rec, cipher, out));

    const got = try fix.readFile(gpa, "b.out");
    defer gpa.free(got);
    try testing.expectEqualSlices(u8, data, got);
}

test "multiple independent encryptions" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const dev = try fix.path(gpa, "dev.key");
    defer gpa.free(dev);
    const rec = try fix.path(gpa, "rec.key");
    defer gpa.free(rec);

    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(dev, rec));

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
        try pipeline.runEncrypt(gpa, testing.io, encryptArgs(dev, plain_path, ct_path));
        try pipeline.runDecrypt(gpa, testing.io, empty_env, decryptKeyfileArgs(rec, ct_path, out_path));
        const got = try fix.readFile(gpa, out_name);
        defer gpa.free(got);
        try testing.expectEqualStrings(payload, got);
    }
}

test "encrypt rejects DK seed key" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const dev = try fix.path(gpa, "dev.key");
    defer gpa.free(dev);
    const rec = try fix.path(gpa, "rec.key");
    defer gpa.free(rec);
    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(dev, rec));

    const plain = try fix.path(gpa, "p.txt");
    defer gpa.free(plain);
    const ct = try fix.path(gpa, "p.enc");
    defer gpa.free(ct);
    try fix.writeFile("p.txt", "should not encrypt");

    try testing.expectError(error.KeyfileIsDkSeed, pipeline.runEncrypt(gpa, testing.io, encryptArgs(rec, plain, ct)));
    try testing.expect(!fix.exists("p.enc"));
}

test "decrypt rejects EK key" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const dev = try fix.path(gpa, "dev.key");
    defer gpa.free(dev);
    const rec = try fix.path(gpa, "rec.key");
    defer gpa.free(rec);
    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(dev, rec));

    const plain = try fix.path(gpa, "p.txt");
    defer gpa.free(plain);
    const ct = try fix.path(gpa, "p.enc");
    defer gpa.free(ct);
    const out = try fix.path(gpa, "out.bin");
    defer gpa.free(out);

    try fix.writeFile("p.txt", "hi");
    try pipeline.runEncrypt(gpa, testing.io, encryptArgs(dev, plain, ct));

    try testing.expectError(error.KeyfileIsEk, pipeline.runDecrypt(gpa, testing.io, empty_env, decryptKeyfileArgs(dev, ct, out)));
    try testing.expect(!fix.exists("out.bin"));
}

test "wrong recovery key fails" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const dev = try fix.path(gpa, "dev.key");
    defer gpa.free(dev);
    const rec = try fix.path(gpa, "rec.key");
    defer gpa.free(rec);
    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(dev, rec));

    const plain = try fix.path(gpa, "p.txt");
    defer gpa.free(plain);
    const ct = try fix.path(gpa, "p.enc");
    defer gpa.free(ct);
    try fix.writeFile("p.txt", "hello");
    try pipeline.runEncrypt(gpa, testing.io, encryptArgs(dev, plain, ct));

    const other_dev = try fix.path(gpa, "other.dev");
    defer gpa.free(other_dev);
    const other_rec = try fix.path(gpa, "other.rec");
    defer gpa.free(other_rec);
    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(other_dev, other_rec));

    const out = try fix.path(gpa, "oops.out");
    defer gpa.free(out);
    try testing.expectError(error.AuthFailedForChunk, pipeline.runDecrypt(gpa, testing.io, empty_env, decryptKeyfileArgs(other_rec, ct, out)));
}

test "tampered chunk fails authentication" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const dev = try fix.path(gpa, "dev.key");
    defer gpa.free(dev);
    const rec = try fix.path(gpa, "rec.key");
    defer gpa.free(rec);
    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(dev, rec));

    const data = try gpa.alloc(u8, 300_000);
    defer gpa.free(data);
    @memset(data, 0x42);
    try fix.writeFile("t.plain", data);

    const plain = try fix.path(gpa, "t.plain");
    defer gpa.free(plain);
    const ct = try fix.path(gpa, "t.enc");
    defer gpa.free(ct);
    var args = encryptArgs(dev, plain, ct);
    args.chunk_size = 64 * 1024;
    try pipeline.runEncrypt(gpa, testing.io, args);

    var ct_bytes = try fix.readFile(gpa, "t.enc");
    defer gpa.free(ct_bytes);
    ct_bytes[ct_bytes.len - 30] ^= 0xff;
    try fix.writeFile("t.enc", ct_bytes);

    const out = try fix.path(gpa, "out.bin");
    defer gpa.free(out);
    try testing.expectError(error.AuthFailedForChunk, pipeline.runDecrypt(gpa, testing.io, empty_env, decryptKeyfileArgs(rec, ct, out)));
    try testing.expect(!fix.exists("out.bin"));
}

test "refuse overwrite without force" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const dev = try fix.path(gpa, "dev.key");
    defer gpa.free(dev);
    const rec = try fix.path(gpa, "rec.key");
    defer gpa.free(rec);
    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(dev, rec));

    try fix.writeFile("o.plain", "x");
    try fix.writeFile("o.enc", "existing");
    const plain = try fix.path(gpa, "o.plain");
    defer gpa.free(plain);
    const ct = try fix.path(gpa, "o.enc");
    defer gpa.free(ct);
    try testing.expectError(error.OutputExists, pipeline.runEncrypt(gpa, testing.io, encryptArgs(dev, plain, ct)));

    const after = try fix.readFile(gpa, "o.enc");
    defer gpa.free(after);
    try testing.expectEqualStrings("existing", after);
}

test "device key unchanged after encryption" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const dev = try fix.path(gpa, "dev.key");
    defer gpa.free(dev);
    const rec = try fix.path(gpa, "rec.key");
    defer gpa.free(rec);
    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(dev, rec));

    const before = try fix.readFile(gpa, "dev.key");
    defer gpa.free(before);

    try fix.writeFile("p.txt", "some plaintext");
    const plain = try fix.path(gpa, "p.txt");
    defer gpa.free(plain);
    const ctp = try fix.path(gpa, "p.enc");
    defer gpa.free(ctp);
    try pipeline.runEncrypt(gpa, testing.io, encryptArgs(dev, plain, ctp));

    const after = try fix.readFile(gpa, "dev.key");
    defer gpa.free(after);
    try testing.expectEqualSlices(u8, before, after);
}

test "password round trip" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const dev = try fix.path(gpa, "k.key");
    defer gpa.free(dev);
    const env = passwordEnviron("correct horse battery staple");
    try pipeline.runInit(gpa, testing.io, env, passwordInit(dev));

    try fix.writeFile("p", "top secret backup");
    const plain = try fix.path(gpa, "p");
    defer gpa.free(plain);
    const ct = try fix.path(gpa, "p.enc");
    defer gpa.free(ct);
    try pipeline.runEncrypt(gpa, testing.io, encryptArgs(dev, plain, ct));

    const out = try fix.path(gpa, "p.dec");
    defer gpa.free(out);
    try pipeline.runDecrypt(gpa, testing.io, env, decryptPasswordArgs(ct, out));

    const got = try fix.readFile(gpa, "p.dec");
    defer gpa.free(got);
    try testing.expectEqualStrings("top secret backup", got);
}

test "wrong password fails" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const dev = try fix.path(gpa, "k.key");
    defer gpa.free(dev);
    try pipeline.runInit(gpa, testing.io, passwordEnviron("right one"), passwordInit(dev));

    try fix.writeFile("p", "x");
    const plain = try fix.path(gpa, "p");
    defer gpa.free(plain);
    const ct = try fix.path(gpa, "p.enc");
    defer gpa.free(ct);
    try pipeline.runEncrypt(gpa, testing.io, encryptArgs(dev, plain, ct));

    const out = try fix.path(gpa, "oops.out");
    defer gpa.free(out);
    try testing.expectError(error.WrongPassword, pipeline.runDecrypt(gpa, testing.io, passwordEnviron("wrong one"), decryptPasswordArgs(ct, out)));
}

test "password hex round trip" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const dev = try fix.path(gpa, "k.key");
    defer gpa.free(dev);
    const env = passwordEnviron("hex test pw");
    try pipeline.runInit(gpa, testing.io, env, passwordInitHex(dev));

    const dev_bytes = try fix.readFile(gpa, "k.key");
    defer gpa.free(dev_bytes);
    for (dev_bytes) |b| try testing.expect(std.ascii.isHex(b) or std.ascii.isWhitespace(b));

    try fix.writeFile("p", "hex mode data");
    const plain = try fix.path(gpa, "p");
    defer gpa.free(plain);
    const ct = try fix.path(gpa, "p.enc");
    defer gpa.free(ct);
    try pipeline.runEncrypt(gpa, testing.io, encryptArgs(dev, plain, ct));

    const out = try fix.path(gpa, "p.dec");
    defer gpa.free(out);
    try pipeline.runDecrypt(gpa, testing.io, env, decryptPasswordArgs(ct, out));

    const got = try fix.readFile(gpa, "p.dec");
    defer gpa.free(got);
    try testing.expectEqualStrings("hex mode data", got);
}

test "device key cannot decrypt" {
    const gpa = testing.allocator;
    var fix = try TmpFixture.init(gpa);
    defer fix.deinit(gpa);

    const dev = try fix.path(gpa, "dev.key");
    defer gpa.free(dev);
    const rec = try fix.path(gpa, "rec.key");
    defer gpa.free(rec);
    try pipeline.runInit(gpa, testing.io, empty_env, randomInit(dev, rec));

    try fix.writeFile("p", "secret");
    const plain = try fix.path(gpa, "p");
    defer gpa.free(plain);
    const ct = try fix.path(gpa, "p.enc");
    defer gpa.free(ct);
    try pipeline.runEncrypt(gpa, testing.io, encryptArgs(dev, plain, ct));

    const out = try fix.path(gpa, "oops.out");
    defer gpa.free(out);
    try testing.expectError(error.KeyfileIsEk, pipeline.runDecrypt(gpa, testing.io, empty_env, decryptKeyfileArgs(dev, ct, out)));
}
