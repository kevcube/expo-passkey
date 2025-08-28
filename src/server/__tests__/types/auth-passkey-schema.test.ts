/**
 * @file Tests for the passkey schema
 * @description Tests specifically for the Passkey DB model
 */

import { passkeySchema } from "../../../types";

describe("Passkey Schema Tests", () => {
  describe("passkeySchema validation", () => {
    // Test a valid passkey object
    it("should validate a complete passkey object", () => {
      const passkey = {
        id: "passkey-123",
        name: "iPhone 14",
        publicKey: "public-key-data",
        userId: "user-123",
        credentialID: "credential-123",
        counter: 5,
        deviceType: "ios",
        backedUp: true,
        transports: "hybrid,internal",
        createdAt: new Date(),
        aaguid: "sample-aaguid",
      };

      const result = passkeySchema.safeParse(passkey);
      expect(result.success).toBe(true);

      if (result.success) {
        expect(result.data.credentialID).toBe("credential-123");
        expect(result.data.deviceType).toBe("ios");
        expect(result.data.backedUp).toBe(true);
      }
    });

    // Test with optional fields missing
    it("should validate passkey with optional fields missing", () => {
      const passkey = {
        id: "passkey-123",
        // name is optional
        publicKey: "public-key-data",
        userId: "user-123",
        credentialID: "credential-123",
        counter: 0,
        deviceType: "android",
        backedUp: false,
        // transports is optional
        createdAt: new Date(),
        // aaguid is optional
      };

      const result = passkeySchema.safeParse(passkey);
      expect(result.success).toBe(true);
    });

    // Verify required fields
    it("should reject when required fields are missing", () => {
      // Missing userId
      const missingUserId = {
        id: "passkey-123",
        // No userId
        credentialID: "credential-123",
        publicKey: "public-key-data",
        counter: 0,
        deviceType: "ios",
        backedUp: true,
        createdAt: new Date(),
      };

      const result1 = passkeySchema.safeParse(missingUserId);
      expect(result1.success).toBe(false);

      // Missing credentialID
      const missingCredentialID = {
        id: "passkey-123",
        userId: "user-123",
        // No credentialID
        publicKey: "public-key-data",
        counter: 0,
        deviceType: "ios",
        backedUp: true,
        createdAt: new Date(),
      };

      const result2 = passkeySchema.safeParse(missingCredentialID);
      expect(result2.success).toBe(false);

      // Missing publicKey
      const missingPublicKey = {
        id: "passkey-123",
        userId: "user-123",
        credentialID: "credential-123",
        // No publicKey
        counter: 0,
        deviceType: "ios",
        backedUp: true,
        createdAt: new Date(),
      };

      const result3 = passkeySchema.safeParse(missingPublicKey);
      expect(result3.success).toBe(false);
    });
  });
});
