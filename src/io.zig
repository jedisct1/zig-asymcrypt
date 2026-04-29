const std = @import("std");

pub const stdio_path = "-";

const buffer_size: usize = 64 * 1024;

fn isStdio(path: ?[]const u8) bool {
    return path == null or std.mem.eql(u8, path.?, stdio_path);
}

pub const Input = struct {
    is_stdin: bool,
    file: std.Io.File,
    file_reader: std.Io.File.Reader,
    buffer: []u8,
    allocator: std.mem.Allocator,

    pub fn open(io: std.Io, allocator: std.mem.Allocator, path: ?[]const u8) !Input {
        const buf = try allocator.alloc(u8, buffer_size);
        errdefer allocator.free(buf);

        if (isStdio(path)) {
            const f = std.Io.File.stdin();
            return .{
                .is_stdin = true,
                .file = f,
                .file_reader = f.readerStreaming(io, buf),
                .buffer = buf,
                .allocator = allocator,
            };
        }
        const f = try std.Io.Dir.cwd().openFile(io, path.?, .{ .mode = .read_only });
        return .{
            .is_stdin = false,
            .file = f,
            .file_reader = f.reader(io, buf),
            .buffer = buf,
            .allocator = allocator,
        };
    }

    pub fn reader(self: *Input) *std.Io.Reader {
        return &self.file_reader.interface;
    }

    pub fn close(self: *Input, io: std.Io) void {
        if (!self.is_stdin) self.file.close(io);
        self.allocator.free(self.buffer);
        self.* = undefined;
    }
};

pub const Output = struct {
    state: union(enum) {
        stdout: void,
        staged: Staged,
    },
    file_writer: std.Io.File.Writer,
    buffer: []u8,
    allocator: std.mem.Allocator,

    pub const Staged = struct {
        atomic: std.Io.File.Atomic,
        dir: std.Io.Dir,
        force: bool,
    };

    pub fn open(
        io: std.Io,
        allocator: std.mem.Allocator,
        path: ?[]const u8,
        force: bool,
    ) !Output {
        const buf = try allocator.alloc(u8, buffer_size);
        errdefer allocator.free(buf);

        if (isStdio(path)) {
            const f = std.Io.File.stdout();
            return .{
                .state = .stdout,
                .file_writer = f.writerStreaming(io, buf),
                .buffer = buf,
                .allocator = allocator,
            };
        }

        const dest = path.?;
        const dir_path = std.fs.path.dirname(dest) orelse ".";
        const base = std.fs.path.basename(dest);
        var dir = try std.Io.Dir.cwd().openDir(io, dir_path, .{});
        errdefer dir.close(io);

        var atomic = try dir.createFileAtomic(io, base, .{ .replace = force });
        errdefer atomic.deinit(io);

        const fw = atomic.file.writer(io, buf);
        return .{
            .state = .{ .staged = .{ .atomic = atomic, .dir = dir, .force = force } },
            .file_writer = fw,
            .buffer = buf,
            .allocator = allocator,
        };
    }

    pub fn writer(self: *Output) *std.Io.Writer {
        return &self.file_writer.interface;
    }

    pub fn commit(self: *Output, io: std.Io) !void {
        try self.file_writer.interface.flush();
        switch (self.state) {
            .stdout => {},
            .staged => |*s| {
                try self.file_writer.file.sync(io);
                if (s.force) {
                    try s.atomic.replace(io);
                } else {
                    s.atomic.link(io) catch |err| switch (err) {
                        error.PathAlreadyExists => return error.OutputExists,
                        else => |e| return e,
                    };
                }
            },
        }
    }

    pub fn deinit(self: *Output, io: std.Io) void {
        switch (self.state) {
            .stdout => {},
            .staged => |*s| {
                s.atomic.deinit(io);
                s.dir.close(io);
            },
        }
        self.allocator.free(self.buffer);
        self.* = undefined;
    }
};
