const std = @import("std");
const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

const Header = extern struct {
    iter_count: u32,
    salt: [12]u8,
    nonce: [12]u8,
};

fn usage() void {}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    const args = try std.process.argsAlloc(arena_allocator);
    if (args.len != 3) {
        std.debug.print("zig_andotp_decrypt ECRYPTED_FILE PASSWORD\n", .{});
        std.os.exit(1);
    }
    const plaintext = decode(arena_allocator, args[1], args[2]) catch |err| {
        std.debug.print("Failed to decode '{s}': {any}\n", .{ args[1], err });
        std.os.exit(1);
    };
    try stdout.writeAll(plaintext);
}

pub fn decode(allocator: std.mem.Allocator, filename: []const u8, password: []const u8) ![]u8 {
    var file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();
    var buf_reader = std.io.bufferedReader(file.reader());
    var in_stream = buf_reader.reader();

    var header = try in_stream.readStruct(Header);
    if (native_endian == .Little)
        header.iter_count = @byteSwap(header.iter_count);

    var dk: [32]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(&dk, password, &header.salt, header.iter_count, std.crypto.auth.hmac.HmacSha1);

    const ciphertext = try in_stream.readAllAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(ciphertext);
    var tag: [std.crypto.aead.aes_gcm.Aes256Gcm.tag_length]u8 = undefined;
    std.mem.copy(u8, &tag, ciphertext[ciphertext.len - std.crypto.aead.aes_gcm.Aes256Gcm.tag_length ..]);
    const plaintext = try allocator.alloc(u8, ciphertext.len - std.crypto.aead.aes_gcm.Aes256Gcm.tag_length);
    try std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(plaintext, ciphertext[0 .. ciphertext.len - std.crypto.aead.aes_gcm.Aes256Gcm.tag_length], tag, "", header.nonce, dk);
    return plaintext;
}

test "test new format decryption" {
    const crypt_filename = "src/testdata/accounts_new_123456.json.aes";
    const plain_filename = "testdata/accounts_new_123456.json";
    const plaintext = try decode(std.testing.allocator, crypt_filename, "123456");
    const expected_plaintext = @embedFile(plain_filename).*;
    defer std.testing.allocator.free(plaintext);
    try std.testing.expectEqualStrings(plaintext, &expected_plaintext);
}
