export const GENERIC_FAILURE = "unable to sanitize outbound context";

export class AdapterError extends Error {
  constructor() {
    super(GENERIC_FAILURE);
    this.name = "AdapterError";
  }
}

export function failClosed(): never {
  throw new AdapterError();
}
