import {poseidon2, poseidon4} from 'poseidon-lite';

export function poseidonHash(args: bigint[]): bigint {
  if (args.length === 2) return poseidon2(args);
  if (args.length === 4) return poseidon4(args);
  throw new Error('invalid_args');
}

export function expandArray(arr: string[], len: number, fill: string): string[] {
  return [...arr, ...Array(len - arr.length).fill(fill)];
}

export function membersToStrings(obj: Record<string, any>, maxDepth: number): Record<string, string> {
  const out = {};
  for(let key of Object.keys(obj)) {
    if(obj[key] instanceof Array) {
      out[key] = expandArray(obj[key].map(x => x.toString(10)), maxDepth, '0');
    } else {
      out[key] = obj[key].toString(10);
    }
  }
  return out;
}
