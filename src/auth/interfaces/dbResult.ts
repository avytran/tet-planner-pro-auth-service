export type DbResult<T> =
  | { status: "success"; data: T }
  | { status: "error"; message: string };
