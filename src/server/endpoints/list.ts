/**
 * @file List passkeys endpoint
 * @description Implementation of the endpoint to list user passkeys with WebAuthn info
 */

import { createAuthEndpoint, sessionMiddleware } from "better-auth/api";
import { APIError } from "better-call";

import { ERROR_CODES, ERROR_MESSAGES } from "../../types/errors";
import type { Logger } from "../utils/logger";
import {
  listPasskeysParamsSchema,
  listPasskeysQuerySchema,
} from "../utils/schema";

import type { Passkey, ResolvedSchemaConfig } from "../../types";

/**
 * Create endpoint to list user passkeys
 */
export const createListEndpoint = (options: {
  logger: Logger;
  schemaConfig: ResolvedSchemaConfig;
}) => {
  const { logger, schemaConfig } = options;

  return createAuthEndpoint(
    "/expo-passkey/list/:userId",
    {
      method: "GET",
      params: listPasskeysParamsSchema,
      query: listPasskeysQuerySchema,
      use: [sessionMiddleware],
      metadata: {
        openapi: {
          description: "Retrieve a list of registered passkeys for the user",
          tags: ["Authentication"],
          responses: {
            200: {
              description: "List of passkeys",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      passkeys: {
                        type: "array",
                        items: {
                          type: "object",
                          properties: {
                            id: { type: "string" },
                            name: { type: "string", nullable: true },
                            publicKey: { type: "string" },
                            userId: { type: "string" },
                            credentialID: { type: "string" },
                            counter: { type: "number" },
                            deviceType: { type: "string" },
                            backedUp: { type: "boolean" },
                            transports: { type: "string", nullable: true },
                            createdAt: {
                              type: "string",
                              format: "date-time",
                            },
                            aaguid: {
                              type: "string",
                              nullable: true,
                            },
                          },
                        },
                      },
                      nextOffset: { type: "number", nullable: true },
                    },
                  },
                },
              },
            },
            401: {
              description: "Unauthorized",
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
      try {
        const userId = ctx.params.userId;
        const limit = parseInt(ctx.query.limit || "10", 10);
        const offset = ctx.query.offset ? parseInt(ctx.query.offset, 10) : 0;

        logger.debug("Passkey list request received:", {
          userId,
          limit,
          offset,
        });

        // Verify session matches userId for security
        if (ctx.context.session?.user?.id !== userId) {
          logger.warn("Unauthorized attempt to list passkeys", {
            requestedUserId: userId,
            sessionUserId: ctx.context.session?.user?.id,
          });
          throw new APIError("UNAUTHORIZED", {
            code: "UNAUTHORIZED_ACCESS",
            message: "You can only view your own passkeys",
          });
        }

        // Fetch passkeys with pagination
        const passkeys = await ctx.context.adapter.findMany<Passkey>({
          model: schemaConfig.passkeyModel,
          where: [
            { field: "userId", operator: "eq", value: userId },
          ],
          sortBy: { field: "createdAt", direction: "desc" },
          limit: limit + 1,
          offset,
        });

        // Check if there are more results
        const hasMore = passkeys.length > limit;
        const results = hasMore ? passkeys.slice(0, limit) : passkeys;

        // Format passkeys for response
        const formattedPasskeys = results.map((passkey) => ({
          id: passkey.id,
          name: passkey.name || null,
          publicKey: passkey.publicKey,
          userId: passkey.userId,
          credentialID: passkey.credentialID,
          counter: passkey.counter,
          deviceType: passkey.deviceType,
          backedUp: passkey.backedUp,
          transports: passkey.transports || null,
          createdAt: passkey.createdAt,
          aaguid: passkey.aaguid || null,
        }));

        logger.debug("Returning passkeys:", {
          count: formattedPasskeys.length,
          hasMore,
          nextOffset: hasMore ? offset + limit : undefined,
        });

        return ctx.json({
          passkeys: formattedPasskeys,
          nextOffset: hasMore ? offset + limit : undefined,
        });
      } catch (error) {
        logger.error("Error listing passkeys:", error);

        if (error instanceof APIError) {
          throw error;
        }

        throw new APIError("INTERNAL_SERVER_ERROR", {
          code: ERROR_CODES.SERVER.PASSKEYS_RETRIEVAL_FAILED,
          message: ERROR_MESSAGES[ERROR_CODES.SERVER.PASSKEYS_RETRIEVAL_FAILED],
        });
      }
    },
  );
};
