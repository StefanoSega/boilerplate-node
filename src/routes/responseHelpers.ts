export enum ResponseType {
  Success,
  BadRequest,
  Unauthorized,
  Conflict,
  InternalServerError,
}

const responseTypeStatusCodeMap: Record<ResponseType, number> = {
  [ResponseType.Success]: 200,
  [ResponseType.BadRequest]: 400,
  [ResponseType.Unauthorized]: 401,
  [ResponseType.Conflict]: 409,
  [ResponseType.InternalServerError]: 500,
};

export const getJsonResponse = (
  res: any,
  type: ResponseType,
  payload: Record<string, any>
) => {
  const statusCode = responseTypeStatusCodeMap[type];
  const isError = statusCode >= 400;

  if (isError) {
    return res.status(statusCode).json({
      code: statusCode,
      errors: payload,
    });
  }

  return res.status(statusCode).json(payload);
};
