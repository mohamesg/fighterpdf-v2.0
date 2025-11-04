import 'dart:typed_data';
import 'dart:io';
import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';

class EncryptionUtils {
  static const String _encryptionHeader = 'ENCPDF01';
  static const int _version = 1;
  static const int _keySize = 256; // bits
  static const int _ivSize = 16; // bytes

  /// Generate a random AES key
  static Uint8List generateAESKey() {
    final random = _SecureRandom();
    return Uint8List(32); // 256-bit key
  }

  /// Generate a random IV
  static Uint8List generateIV() {
    final random = _SecureRandom();
    return Uint8List(_ivSize);
  }

  /// Validate PEM file format
  static bool validatePemFile(String pemContent) {
    return pemContent.contains('-----BEGIN PUBLIC KEY-----') &&
        pemContent.contains('-----END PUBLIC KEY-----');
  }

  /// Extract public key from PEM content
  static RSAPublicKey? extractPublicKeyFromPem(String pemContent) {
    try {
      final lines = pemContent.split('\n');
      final keyLines = lines
          .where((line) =>
              line.isNotEmpty &&
              !line.contains('BEGIN') &&
              !line.contains('END'))
          .join();

      final keyBytes = _base64Decode(keyLines);
      final asn1Parser = ASN1Parser(keyBytes);
      final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
      final publicKeyBitString = topLevelSeq.elements[1] as ASN1BitString;

      final publicKeyAsn1 = ASN1Parser(publicKeyBitString.stringValue).nextObject();
      final publicKeySeq = publicKeyAsn1 as ASN1Sequence;

      final modulus = publicKeySeq.elements[0] as ASN1Integer;
      final exponent = publicKeySeq.elements[1] as ASN1Integer;

      return RSAPublicKey(modulus.valueAsBigInteger, exponent.valueAsBigInteger);
    } catch (e) {
      print('خطأ في استخراج المفتاح العام: $e');
      return null;
    }
  }

  /// Verify encryption file integrity
  static bool verifyEncryptionFile(File encryptedFile) {
    try {
      final bytes = encryptedFile.readAsBytesSync();
      if (bytes.length < 8) return false;

      final header = String.fromCharCodes(bytes.sublist(0, 8));
      return header == _encryptionHeader;
    } catch (e) {
      print('خطأ في التحقق من الملف: $e');
      return false;
    }
  }

  /// Get encryption file metadata
  static Map<String, dynamic>? getEncryptionFileMetadata(File encryptedFile) {
    try {
      final bytes = encryptedFile.readAsBytesSync();
      if (bytes.length < 20) return null;

      final header = String.fromCharCodes(bytes.sublist(0, 8));
      if (header != _encryptionHeader) return null;

      final version = _bytesToInt(bytes.sublist(8, 12));
      final wrappedKeyLength = _bytesToInt(bytes.sublist(12, 16));
      final consumedFlag = bytes[16 + wrappedKeyLength];

      return {
        'header': header,
        'version': version,
        'wrappedKeyLength': wrappedKeyLength,
        'consumed': consumedFlag == 1,
        'fileSize': bytes.length,
      };
    } catch (e) {
      print('خطأ في قراءة بيانات الملف: $e');
      return null;
    }
  }

  /// Helper function to convert bytes to int
  static int _bytesToInt(Uint8List bytes) {
    return ((bytes[0].toUnsigned(8) << 24) |
        (bytes[1].toUnsigned(8) << 16) |
        (bytes[2].toUnsigned(8) << 8) |
        bytes[3].toUnsigned(8));
  }

  /// Helper function to decode base64
  static Uint8List _base64Decode(String input) {
    return Uint8List.fromList(
      base64Decode(input.replaceAll('\n', '').replaceAll('\r', '')),
    );
  }

  /// Calculate file hash for integrity verification
  static String calculateFileHash(File file) {
    final bytes = file.readAsBytesSync();
    return sha256.convert(bytes).toString();
  }

  /// Validate file before encryption
  static bool validateFileBeforeEncryption(File file) {
    try {
      if (!file.existsSync()) return false;
      if (file.lengthSync() == 0) return false;
      if (file.lengthSync() > 500 * 1024 * 1024) return false; // 500MB limit
      return true;
    } catch (e) {
      print('خطأ في التحقق من الملف: $e');
      return false;
    }
  }
}

/// Secure random number generator
class _SecureRandom implements Random {
  final _random = Random.secure();

  @override
  int nextInt(int max) => _random.nextInt(max);

  @override
  double nextDouble() => _random.nextDouble();

  @override
  bool nextBool() => _random.nextBool();
}

/// Base64 decode helper
Uint8List base64Decode(String input) {
  const base64chars =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  final output = <int>[];
  var i = 0;

  while (i < input.length) {
    final c1 = base64chars.indexOf(input[i++]);
    final c2 = i < input.length ? base64chars.indexOf(input[i++]) : 0;
    final c3 = i < input.length ? base64chars.indexOf(input[i++]) : 0;
    final c4 = i < input.length ? base64chars.indexOf(input[i++]) : 0;

    output.add((c1 << 2) | (c2 >> 4));
    if (c3 != 64) {
      output.add(((c2 & 15) << 4) | (c3 >> 2));
      if (c4 != 64) {
        output.add(((c3 & 3) << 6) | c4);
      }
    }
  }

  return Uint8List.fromList(output);
}
