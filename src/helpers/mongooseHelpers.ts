import mongoose from "mongoose";

export const queryToJson = <ResultType, DocType, THelpers, RawDocType>(
  query: mongoose.Query<ResultType, DocType, THelpers, RawDocType>
) => {
  return query.lean().exec();
};
