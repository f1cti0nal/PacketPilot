import { clsx, type ClassValue } from "clsx";

/** Thin wrapper around clsx for conditional className composition. */
export function cn(...inputs: ClassValue[]): string {
  return clsx(inputs);
}
