/**
 * Module dependencies.
 */
import mongoose from "mongoose";

var Schema = mongoose.Schema;

/**
 * Schema definitions.
 */

mongoose.model(
  "OAuthTokens",
  new Schema({
    accessToken: { type: String },
    accessTokenExpiresOn: { type: Date },
    client: { type: Object }, // `client` and `user` are required in multiple places, for example `getAccessToken()`
    clientId: { type: String },
    refreshToken: { type: String },
    refreshTokenExpiresOn: { type: Date },
    user: { type: Object },
    userId: { type: String },
  })
);

mongoose.model(
  "OAuthClients",
  new Schema({
    clientId: { type: String },
    clientSecret: { type: String },
    redirectUris: { type: Array },
  })
);

mongoose.model(
  "OAuthUsers",
  new Schema({
    email: { type: String, default: "" },
    firstname: { type: String },
    lastname: { type: String },
    password: { type: String },
    username: { type: String },
  })
);

var OAuthTokensModel = mongoose.model("OAuthTokens");
var OAuthClientsModel = mongoose.model("OAuthClients");
var OAuthUsersModel = mongoose.model("OAuthUsers");

/**
 * Get access token.
 */

export const getAccessToken = function (bearerToken) {
  // Adding `.lean()`, as we get a mongoose wrapper object back from `findOne(...)`, and oauth2-server complains.
  return OAuthTokensModel.findOne({ accessToken: bearerToken }).lean();
};

/**
 * Get client.
 */

export const getClient = function (clientId, clientSecret) {
  return OAuthClientsModel.findOne({
    clientId: clientId,
    clientSecret: clientSecret,
  }).lean();
};

/**
 * Get refresh token.
 */

export const getRefreshToken = function (refreshToken) {
  return OAuthTokensModel.findOne({ refreshToken: refreshToken }).lean();
};

/**
 * Get user.
 */

export const getUser = function (username, password) {
  return OAuthUsersModel.findOne({
    username: username,
    password: password,
  }).lean();
};

/**
 * Save token.
 */

export const saveToken = function (token, client, user) {
  var accessToken = new OAuthTokensModel({
    accessToken: token.accessToken,
    accessTokenExpiresOn: token.accessTokenExpiresOn,
    client: client,
    clientId: client.clientId,
    refreshToken: token.refreshToken,
    refreshTokenExpiresOn: token.refreshTokenExpiresOn,
    user: user,
    userId: user._id,
  });
  // Can't just chain `lean()` to `save()` as we did with `findOne()` elsewhere. Instead we use `Promise` to resolve the data.
  return new Promise(function (resolve, reject) {
    accessToken.save(function (err, data) {
      if (err) reject(err);
      else resolve(data);
    });
  }).then(function (saveResult) {
    // `saveResult` is mongoose wrapper object, not doc itself. Calling `toJSON()` returns the doc.
    saveResult =
      saveResult && typeof saveResult == "object"
        ? (saveResult as any).toJSON()
        : saveResult;

    // Unsure what else points to `saveResult` in oauth2-server, making copy to be safe
    var data: any = new Object();
    for (var prop in saveResult as any) data[prop] = saveResult[prop];

    // /oauth-server/lib/models/token-model.js complains if missing `client` and `user`. Creating missing properties.
    data.client = data.clientId;
    data.user = data.userId;

    return data;
  });
};

export default {
  getAccessToken,
  getClient,
  getRefreshToken,
  getUser,
  saveToken,
  verifyScope: (token: any, scope: string | string[]) =>
    new Promise<boolean>(() => true),
};
