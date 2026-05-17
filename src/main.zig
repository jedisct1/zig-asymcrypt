const std = @import("std");
const Io = std.Io;

const lib = @import("asymcrypt");

pub fn main(init: std.process.Init) u8 {
    return realMain(init) catch |err| {
        var buf: [256]u8 = undefined;
        var w = Io.File.stderr().writer(init.io, &buf);
        w.interface.print("asymcrypt: {s}\n", .{@errorName(err)}) catch {};
        w.interface.flush() catch {};
        return 1;
    };
}

fn realMain(init: std.process.Init) !u8 {
    var iter = try init.minimal.args.iterateAllocator(init.gpa);
    defer iter.deinit();
    _ = iter.next();

    const cmd = lib.cli.parseFromIterator(init.gpa, &iter) catch |err| {
        var buf: [256]u8 = undefined;
        var w = Io.File.stderr().writer(init.io, &buf);
        w.interface.print("asymcrypt: {s}\n", .{@errorName(err)}) catch {};
        w.interface.print(
            \\
            \\Usage:
            \\  asymcrypt init -o DEVICE [-r RECOVERY] [--password] [--hex] [--argon2-mem N] [--argon2-iters N] [--argon2-lanes N]
            \\  asymcrypt encrypt -k KEY [-i IN] [-o OUT] [--chunk-size N] [--force] [--insecure-perms]
            \\  asymcrypt decrypt (-k RECOVERY | --password) [-i IN] [-o OUT] [--force] [--insecure-perms]
            \\
        , .{}) catch {};
        w.interface.flush() catch {};
        return 1;
    };

    switch (cmd) {
        .init => |a| try lib.pipeline.runInit(init.gpa, init.io, init.minimal.environ, a),
        .encrypt => |a| try lib.pipeline.runEncrypt(init.gpa, init.io, a),
        .decrypt => |a| try lib.pipeline.runDecrypt(init.gpa, init.io, init.minimal.environ, a),
    }
    return 0;
}
