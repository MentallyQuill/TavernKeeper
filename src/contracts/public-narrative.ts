const UnsafePublicNarrative = [
  /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069<>]/u,
  /\b(?:https?|ftp):\/\/|\bwww\./iu,
  /(?:\b[A-Za-z]:[\\/]|(?:^|[\s"'(])\/(?:Users|home|tmp|var\/tmp|private\/tmp)\/)/u,
  /```|\b(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=|\b(?:async\s+)?function\s+[A-Za-z_$][\w$]*\s*\(|\bclass\s+[A-Za-z_$][\w$]*\s*(?:extends\s+[A-Za-z_$][\w$]*\s*)?\{|\b(?:import|export)\s+(?:\{|\*|default\b|[A-Za-z_$])|=>/u,
  /\b(?:repository|project|code|package|extension|plugin)\b.{0,48}\b(?:safe|trusted|certified|verified)\b/iu,
  /\b(?:safe|trusted|certified|verified)\b.{0,48}\b(?:repository|project|code|package|extension|plugin)\b/iu,
  /\bon[a-z][a-z0-9_-]*\s*=/iu,
] as const;

export function publicNarrativeIsSafe(value: string) {
  return !UnsafePublicNarrative.some((pattern) => pattern.test(value));
}
