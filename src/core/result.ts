export type ServiceError<Code extends string = string> = {
  code: Code;
  message: string;
};

export type Result<T, Code extends string = string> =
  { ok: true; value: T } | { ok: false; error: ServiceError<Code> };

export function ok<T>(value: T): Result<T, never> {
  return { ok: true, value };
}

export function err<Code extends string>(
  code: Code,
  message: string,
): Result<never, Code> {
  return { ok: false, error: { code, message } };
}
