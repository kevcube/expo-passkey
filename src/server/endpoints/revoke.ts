/**
 * @file Revoke passkey endpoint
 * @description Implementation of the endpoint to revoke a WebAuthn passkey
 */

import { createAuthEndpoint } from "better-auth/api";
import { APIError } from "better-call";

import { ERROR_CODES, ERROR_MESSAGES } from "../../types/errors";
import type { Logger } from "../utils/logger";
import { revokePasskeySchema } from "../utils/schema";

import type { Passkey, ResolvedSchemaConfig } from "../../types";

/**
 * Create endpoint to revoke a passkey
 */
export const createRevokeEndpoint = (options: {
  logger: Logger;
  schemaConfig: ResolvedSchemaConfig;
}) => {
  const { logger, schemaConfig } = options;

  return createAuthEndpoint(
    "/expo-passkey/revoke",
    {
      method: "POST",
      body: revokePasskeySchema,
      metadata: {
        openapi: {
          description: "Revoke a registered WebAuthn passkey",
          tags: ["Authentication"],
          responses: {
            200: {
              description: "Passkey successfully revoked",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      success: { type: "boolean" },
                    },
                  },
                },
              },
            },
            404: {
              description: "Passkey not found",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      error: {
                        type: "object",
                        properties: {
                          code: { type: "string" },
                          message: { type: "string" },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
    },
    async (ctx) => {
      const { userId, credentialID, reason } = ctx.body;

      try {
        logger.debug("Deleting passkey", { userId, credentialID });

        // Find the credential for the provided credential ID and user ID
        const credential = await ctx.context.adapter.findOne<Passkey>({
          model: schemaConfig.passkeyModel,
          where: [
            { field: "credentialID", operator: "eq", value: credentialID },
            { field: "userId", operator: "eq", value: userId },
          ],
        });

        if (!credential) {
          logger.warn("Delete failed: Passkey not found", { credentialID });
          throw new APIError("NOT_FOUND", {
            code: ERROR_CODES.SERVER.CREDENTIAL_NOT_FOUND,
            message: ERROR_MESSAGES[ERROR_CODES.SERVER.CREDENTIAL_NOT_FOUND],
          });
        }

        // Delete the credential
        await ctx.context.adapter.delete({
          model: schemaConfig.passkeyModel,
          where: [{ field: "id", operator: "eq", value: credential.id }],
        });

        logger.info("Passkey deleted successfully", {
          userId,
          credentialID,
        });

        return ctx.json({ success: true });
      } catch (error) {
        logger.error("Failed to revoke passkey", error);
        if (error instanceof APIError) throw error;
        throw new APIError("BAD_REQUEST", {
          code: ERROR_CODES.SERVER.REVOCATION_FAILED,
          message: ERROR_MESSAGES[ERROR_CODES.SERVER.REVOCATION_FAILED],
        });
      }
    },
  );
};
